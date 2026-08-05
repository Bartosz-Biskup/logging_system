from datetime import datetime
from http.client import TOO_EARLY
from typing import Annotated
from redis import Redis
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import create_engine
from os import getenv
from dotenv import load_dotenv
from pydantic import BaseModel, EmailStr, Field
from repos.user_repository import User, AccountState, UserRepository
from repos.refresh_token_repository import RefreshTokenRepository
from repos.ban_repository import BanRepository
from repos.password_reset_repo import PasswordResetRequestRepository
from repos.mfa_setup import MfaSetupRepository
from repos.mfa_login_request import MfaLoginRequestRepository
from services.auth_service import UserAuthService, LoginResponse, LoginStatus
from services.exceptions import InvalidPasswordException, MFAException, NotAuthenticatedException, UserAlreadyRegisteredException, UserNotFoundException
from services.user_service import UserService
from services.config import (MIN_PASSWORD_LENGTH, 
                             MAX_PASSWORD_LENGTH,
                             ACCESS_TOKEN_EXP_TIME_MINUTES)
from services.token_service import TokenPair, TokenService, AccessTokenBlacklist
from services.ban_service import BanService
from services.user_capability_checker_service import UserCapabilityCheckerService
from services.mail_sender_service import MailSender
from services.password_reset_service import PasswordResetService
from services.mfa_service import MFAService, MfaLoginCode
from services.message_sender import MessageSender


app = FastAPI()
http_bearer = HTTPBearer()


load_dotenv()


DATABASE_URL = f"mysql+mysqlconnector://root:{getenv("DB_PASSWORD")}@localhost:3306/logging_system"
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine, autocommit=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except:
        db.rollback()
        raise
    finally:
        db.close()


def get_user_repo(db: Session = Depends(get_db)):
    return UserRepository(db)


def get_ban_repo(db: Session = Depends(get_db)):
    return BanRepository(db)


def get_token_repo(db: Session = Depends(get_db)):
    return RefreshTokenRepository(db)


def get_user_service(user_repo = Depends(get_user_repo)):
    return UserService(user_repo)


def get_redis():
    return Redis(host='localhost',
                 port=6379,
                 db=0)


def get_access_token_blacklist(redis: Redis = Depends(get_redis)):
    access_token_ttl_seconds = ACCESS_TOKEN_EXP_TIME_MINUTES * 60
    return AccessTokenBlacklist(redis,
                                access_token_ttl_seconds)


def get_token_service(token_repo: RefreshTokenRepository = Depends(get_token_repo),
                      access_token_blacklist: AccessTokenBlacklist = Depends(get_access_token_blacklist)):
    return TokenService(token_repo,
                        access_token_blacklist)


def get_ban_service(ban_repo: BanRepository = Depends(get_ban_repo),
                    user_repo: UserRepository = Depends(get_user_repo)):
    return BanService(ban_repo, user_repo)


def get_user_capability_checker_service(user_repo: UserRepository = Depends(get_user_repo),
                                        ban_service: BanService = Depends(get_ban_service)):
    return UserCapabilityCheckerService(user_repo, ban_service)


def get_password_reset_repo(db: Session = Depends(get_db)):
    return PasswordResetRequestRepository(db)


def get_password_reset_service(password_reset_repo: PasswordResetRequestRepository = Depends(get_password_reset_repo),
                               user_repo: UserRepository = Depends(get_user_repo),
                               capability_checker: UserCapabilityCheckerService = Depends(get_user_capability_checker_service)):
    return PasswordResetService(password_reset_repo,
                                user_repo,
                                MailSender(),
                                capability_checker)


def get_mfa_setup_repo(db: Session = Depends(get_db)):
    return MfaSetupRepository(db)


def get_mfa_login_request_repo(db: Session = Depends(get_db)):
    return MfaLoginRequestRepository(db)


def get_message_sender():
    return MessageSender()


def get_mfa_service(
    mfa_setup_repo: MfaSetupRepository = Depends(get_mfa_setup_repo),
    mfa_login_request_repo: MfaLoginRequestRepository = Depends(get_mfa_login_request_repo),
    user_capability_checker: UserCapabilityCheckerService = Depends(get_user_capability_checker_service),
    message_sender: MessageSender = Depends(get_message_sender),
):
    return MFAService(
        mfa_setup_repo,
        mfa_login_request_repo,
        user_capability_checker,
        message_sender,
    )


def get_user_auth_service(user_repo: UserRepository = Depends(get_user_repo),
                          token_service: TokenService = Depends(get_token_service),
                          user_capability_checker: UserCapabilityCheckerService = Depends(get_user_capability_checker_service),
                          mfa_service: MFAService = Depends(get_mfa_service)):
    return UserAuthService(user_repo,
                           token_service,
                           user_capability_checker,
                           mfa_service)


def get_user_from_refresh_token(credentials: Annotated[HTTPAuthorizationCredentials, Depends(http_bearer)],
                                user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]):
    try:
        return user_auth_service.get_active_user_from_refresh_token_or_raise(credentials.credentials)
    except NotAuthenticatedException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


def get_user_from_access_token(credentials: Annotated[HTTPAuthorizationCredentials, Depends(http_bearer)],
                                user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]):
    try:
        return user_auth_service.get_active_user_from_access_token_or_raise(credentials.credentials)
    except NotAuthenticatedException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


class UserRegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr = Field(max_length=120)
    password: str = Field(min_length=8, max_length=256)


class UserResponseModel(BaseModel):
    id: str = Field(min_length=36, max_length=36)
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr = Field(max_length=120)
    account_state: AccountState
    role: str = Field(max_length=20)
    created_at: datetime


@app.post("/users/register", response_model=UserResponseModel)
def register(body: UserRegisterRequest,
             user_service: Annotated[UserService, Depends(get_user_service)]):
    try:
        new_user: User = user_service.register_user(username=body.username,
                                                    email=body.email,
                                                    password=body.password)
    except UserAlreadyRegisteredException:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="User with this username or email is already registered")
    except InvalidPasswordException:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                            detail="Invalid Password, make sure password contains"
                            "at least one uppercase letter, one lowercase letter, "
                            "one digit and one special character and"
                            "its length is between 8 and 255")

    return UserResponseModel.model_validate(new_user,
                                            from_attributes=True)


class UserLoginRequest(BaseModel):
    email: EmailStr = Field(max_length=120)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH,
                          max_length=MAX_PASSWORD_LENGTH)


@app.post("/users/login", response_model=LoginResponse)
def login(body: UserLoginRequest,
          user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]):
    try:
        return user_auth_service.login(body.email, body.password)
    except NotAuthenticatedException:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid email or password")


@app.post("/users/logout")
def logout(credentials: Annotated[HTTPAuthorizationCredentials, Depends(http_bearer)],
           user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]):
    try:
        user_auth_service.logout(credentials.credentials)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="User not authorized")

    return {
        "message": "success"
    }


@app.post("/users/logout-all")
def logout_all(credentials: Annotated[HTTPAuthorizationCredentials, Depends(http_bearer)],
               user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]):
    try:
        user_auth_service.logout_all(credentials.credentials)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="User not authorized")

    return {
        "message": "success"
    }


@app.post("/users/rotate_tokens")
def rotate_tokens(credentials: Annotated[HTTPAuthorizationCredentials, Depends(http_bearer)],
                  user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]):
    try:
        user_auth_service.refresh_token_pair(credentials.credentials)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                    detail="User not authorized")

    return {
        "message": "success"
    }


@app.get("/users/get/{username}", response_model=UserResponseModel)
def get_user(username: str,
             user_repo: Annotated[UserRepository, Depends(get_user_repo)]):
    user: User | None = user_repo.get_user_by_username(username)

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="User not found")

    return UserResponseModel.model_validate(user, from_attributes=True)


class UpdateEmailRequest(BaseModel):
    new_email: EmailStr = Field(max_length=120)


class UpdateUsernameRequest(BaseModel):
    new_username: str = Field(min_length=3, max_length=50)


class UpdatePasswordRequest(BaseModel):
    current_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


@app.patch("/users/email", response_model=UserResponseModel)
def update_email(
    body: UpdateEmailRequest,
    user: Annotated[User, Depends(get_user_from_access_token)],
    user_service: Annotated[UserService, Depends(get_user_service)],
):
    try:
        updated_user = user_service.update_email(user.id, body.new_email)
    except UserNotFoundException:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    except UserAlreadyRegisteredException:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already taken")
    return updated_user


@app.patch("/users/username", response_model=UserResponseModel)
def update_username(
    body: UpdateUsernameRequest,
    user: Annotated[User, Depends(get_user_from_access_token)],
    user_service: Annotated[UserService, Depends(get_user_service)],
):
    try:
        updated_user = user_service.update_username(user.id, body.new_username)
    except UserNotFoundException:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    except UserAlreadyRegisteredException:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username is already taken")
    return updated_user

@app.patch("/users/password", response_model=UserResponseModel)
def update_password(
    body: UpdatePasswordRequest,
    user: Annotated[User, Depends(get_user_from_access_token)],
    user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]
):
    try:
        updated_user: User = user_auth_service.change_password(user, 
                                                               body.current_password, 
                                                               body.new_password)
    except NotAuthenticatedException:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="User unauthorized")
    except InvalidPasswordException:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                            detail="Invalid new password. Check our password guidelines.")

    return updated_user


class RequestPasswordResetBody(BaseModel):
    email: EmailStr = Field(max_length=120)


class ResetPasswordBody(BaseModel):
    reset_request_id: str = Field(min_length=36, max_length=36)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


@app.post("/users/password-reset/request", status_code=status.HTTP_200_OK)
def request_password_reset(body: RequestPasswordResetBody,
                           password_reset_service: Annotated[PasswordResetService, Depends(get_password_reset_service)]):
    try:
        password_reset_service.generate_and_send_password_reset_link(body.email)
    except ValueError:
        # Swallow on purpose so we always return the same generic message
        # (prevents email enumeration)
        pass

    return {
        "message": "If the account exists, a password reset link has been sent"
    }


@app.post("/users/password-reset/reset", status_code=status.HTTP_200_OK)
def reset_password(body: ResetPasswordBody,
                   password_reset_service: Annotated[PasswordResetService, Depends(get_password_reset_service)]):
    try:
        password_reset_service.reset_password_with_reset_request(body.reset_request_id,
                                                                 body.new_password)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid or expired reset request")
    except InvalidPasswordException:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                            detail="Invalid new password. Check our password guidelines.")

    return {
        "message": "Password has been reset successfully"
    }

@app.post("/users/login/mfa", response_model=TokenPair)
def confirm_mfa_login(body: MfaLoginCode,
                      user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]):
    try:
        return user_auth_service.confirm_mfa(body)
    except MFAException:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid or expired MFA code",
        )
    except UserNotFoundException:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )


class MfaSetupRequst(BaseModel):
    phone_number: str


@app.post("/mfa/setup", status_code=status.HTTP_201_CREATED)
def setup_mfa(body: MfaSetupRequst,
              user: Annotated[User, Depends(get_user_from_access_token)],
              mfa_service: Annotated[MFAService, Depends(get_mfa_service)]):
    try:
        mfa_service.setup_mfa(user.id, body.phone_number)
    except MFAException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=str(e))

    return {
        "message": "MFA set up successfully"
    }
