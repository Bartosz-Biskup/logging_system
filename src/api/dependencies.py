from typing import Annotated
from redis import Redis
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import create_engine
from os import getenv
from dotenv import load_dotenv
from repos.user_repository import UserRepository
from repos.refresh_token_repository import RefreshTokenRepository
from repos.ban_repository import BanRepository
from repos.password_reset_repo import PasswordResetRequestRepository
from repos.mfa_setup import MfaSetupRepository
from repos.mfa_login_request import MfaLoginRequestRepository
from services.auth_service import UserAuthService
from services.hashing_utils import HashingService
from services.user_service import UserService
from services.config import ACCESS_TOKEN_EXP_TIME_MINUTES
from services.token_service import TokenService, AccessTokenBlacklist
from services.JWT_utils import JWTTokenIssuer
from services.ban_service import BanService
from services.exceptions import NotAuthenticatedException
from services.user_capability_checker_service import UserCapabilityCheckerService
from services.mail_sender_service import MailSender
from services.password_reset_service import PasswordResetService
from services.mfa_service import MFAService
from services.message_sender import MessageSender


load_dotenv()
http_bearer = HTTPBearer()


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


def get_hashing_service():
    return HashingService()


def get_user_service(user_repo = Depends(get_user_repo),
                     hashing_service = Depends(get_hashing_service)):
    return UserService(user_repo, hashing_service)


def get_redis():
    return Redis(host='localhost',
                 port=6379,
                 db=0)


def get_access_token_blacklist(redis: Redis = Depends(get_redis)):
    access_token_ttl_seconds = ACCESS_TOKEN_EXP_TIME_MINUTES * 60
    return AccessTokenBlacklist(redis,
                                access_token_ttl_seconds)


def get_jwt_issuer() -> JWTTokenIssuer:
    access_secret = getenv("ACCESS_TOKEN_SECRET")
    refresh_secret = getenv("REFRESH_TOKEN_SECRET")
    if not access_secret or not refresh_secret:
        raise ValueError("ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET must be set")
    return JWTTokenIssuer(
        access_token_secret=access_secret,
        refresh_token_secret=refresh_secret,
    )


def get_token_service(
    token_repo: RefreshTokenRepository = Depends(get_token_repo),
    access_token_blacklist: AccessTokenBlacklist = Depends(get_access_token_blacklist),
    jwt_issuer: JWTTokenIssuer = Depends(get_jwt_issuer),
):
    return TokenService(token_repo, access_token_blacklist, jwt_issuer)


def get_ban_service(ban_repo: BanRepository = Depends(get_ban_repo),
                    user_repo: UserRepository = Depends(get_user_repo)):
    return BanService(ban_repo, user_repo)


def get_user_capability_checker_service(user_repo: UserRepository = Depends(get_user_repo),
                                        ban_service: BanService = Depends(get_ban_service)):
    return UserCapabilityCheckerService(user_repo, ban_service)


def get_password_reset_repo(db: Session = Depends(get_db)):
    return PasswordResetRequestRepository(db)


def get_mail_sender():
    return MailSender()


def get_password_reset_service(password_reset_repo: PasswordResetRequestRepository = Depends(get_password_reset_repo),
                               user_repo: UserRepository = Depends(get_user_repo),
                               capability_checker: UserCapabilityCheckerService = Depends(get_user_capability_checker_service),
                               hashing_service = Depends(get_hashing_service),
                               mail_sender = Depends(get_mail_sender)):
    return PasswordResetService(password_reset_repo,
                                user_repo,
                                mail_sender,
                                capability_checker,
                                hashing_service)


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
    hashing_service = Depends(get_hashing_service)
):
    return MFAService(
        mfa_setup_repo,
        mfa_login_request_repo,
        user_capability_checker,
        message_sender,
        hashing_service
    )


def get_user_auth_service(user_repo: UserRepository = Depends(get_user_repo),
                          token_service: TokenService = Depends(get_token_service),
                          user_capability_checker: UserCapabilityCheckerService = Depends(get_user_capability_checker_service),
                          mfa_service: MFAService = Depends(get_mfa_service),
                          hashing_service = Depends(get_hashing_service)):
    return UserAuthService(user_repo,
                           token_service,
                           user_capability_checker,
                           mfa_service,
                           hashing_service)


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
