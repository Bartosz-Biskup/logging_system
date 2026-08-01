from datetime import datetime
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
from services.auth_service import UserAuthService
from services.exceptions import InvalidPasswordException, NotAuthenticatedException, UserAlreadyRegisteredException
from services.user_service import UserService
from services.config import (MIN_PASSWORD_LENGTH, 
                             MAX_PASSWORD_LENGTH,
                             ACCESS_TOKEN_EXP_TIME_MINUTES)
from services.token_service import TokenPair, TokenService, AccessTokenBlacklist
from services.ban_service import BanService
from services.user_capability_checker_service import UserCapabilityCheckerService


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


def get_user_auth_service(user_repo: UserRepository = Depends(get_user_repo),
                          token_service: TokenService = Depends(get_token_service),
                          user_capability_checker: UserCapabilityCheckerService = Depends(get_user_capability_checker_service)):
    return UserAuthService(user_repo,
                           token_service,
                           user_capability_checker)


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


@app.post("/users/login", response_model=TokenPair)
def login(body: UserLoginRequest,
          user_auth_service: Annotated[UserAuthService, Depends(get_user_auth_service)]):
    try:
        tokens: TokenPair = user_auth_service.login(body.email, body.password)
    except NotAuthenticatedException:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid email or password")

    return tokens


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


# TODO: login, 
# logout, 
# logout-all, 
# rotate_tokens, 
# get_user, 
# update email and username, 
# set new password,
# reset password (generate link and reset )