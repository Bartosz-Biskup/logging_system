from jose import jwt, JWTError
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from os import environ
from uuid import uuid4
from services.config import (JWT_TOKEN_ISSUER,
                    ACCESS_TOKEN_EXP_TIME_MINUTES,
                    REFRESH_TOKEN_EXP_TIME_DAYS,
                    TOKEN_AUD)


class AccessTokenPayload(BaseModel):
    sub: str = Field(min_length=36, max_length=36)
    jti: str = Field(min_length=36, max_length=36)
    iss: str = Field(min_length=1, max_length=200)
    typ: str = "access"
    username: str = Field(min_length=1, max_length=200)
    iat: datetime
    exp: datetime
    aud: str = Field(min_length=1, max_length=200)
    role: str


class RefreshTokenPayload(BaseModel):
    sub: str = Field(min_length=36, max_length=36)
    jti: str = Field(min_length=36, max_length=36)
    iss: str = Field(min_length=1, max_length=200)
    typ: str = "refresh"
    iat: datetime
    exp: datetime
    aud: str = Field(min_length=1, max_length=200)


load_dotenv()


class JWTTokenIssuer:
    ISSUER = JWT_TOKEN_ISSUER
    ACCESS_EXP_TIME = ACCESS_TOKEN_EXP_TIME_MINUTES
    REFRESH_EXP_TIME = REFRESH_TOKEN_EXP_TIME_DAYS
    ACCESS_TOKEN_SECRET = environ.get('ACCESS_TOKEN_SECRET')
    REFRESH_TOKEN_SECRET = environ.get('REFRESH_TOKEN_SECRET')
    TOKEN_AUD = TOKEN_AUD

    @classmethod
    def create_access_token(cls, user_id: str,
                            username: str,
                            role: str,
                            jti: str | None = None) -> str:
        jti = str(uuid4()) if jti is None else jti
        now = datetime.now(timezone.utc)
        payload: AccessTokenPayload = AccessTokenPayload(sub=user_id,
                                                         jti=jti,
                                                         iss=cls.ISSUER,
                                                         username=username,
                                                         iat=now,
                                                         exp=now+timedelta(minutes=cls.ACCESS_EXP_TIME),
                                                         aud=cls.TOKEN_AUD,
                                                         role=role)

        token = jwt.encode(payload.model_dump(),
                           cls.ACCESS_TOKEN_SECRET,
                           "HS256")

        return token

    @classmethod
    def create_refresh_token(cls, user_id: str, jti: str | None = None) -> tuple[str, str, str, datetime]:
        jti = str(uuid4()) if jti is None else jti
        now = datetime.now(timezone.utc)

        payload: RefreshTokenPayload = RefreshTokenPayload(
            sub=user_id,
            jti=jti,
            iss=cls.ISSUER,
            iat=now,
            exp=now+timedelta(days=cls.REFRESH_EXP_TIME),
            aud=cls.TOKEN_AUD
        )

        token = jwt.encode(payload.model_dump(),
                           cls.REFRESH_TOKEN_SECRET,
                           "HS256")

        return token, payload.jti, payload.sub, payload.exp

    @classmethod
    def decode_access_token(cls, token: str) -> AccessTokenPayload:
        try:
            payload = jwt.decode(token=token,
                                 key=cls.ACCESS_TOKEN_SECRET,
                                 algorithms="HS256",
                                 audience=cls.TOKEN_AUD,
                                 issuer=cls.ISSUER)
        except JWTError:
            raise ValueError('Invalid token.')

        return AccessTokenPayload.model_validate(payload)

    @classmethod
    def decode_refresh_token(cls, token: str) -> RefreshTokenPayload:
        try:
            payload = jwt.decode(token=token,
                                 key=cls.REFRESH_TOKEN_SECRET,
                                 algorithms="HS256",
                                 audience=cls.TOKEN_AUD,
                                 issuer=cls.ISSUER)
        except JWTError:
            raise ValueError('Invalid token.')

        return RefreshTokenPayload.model_validate(payload)

    @classmethod
    def verify_access_token(cls, token: str) -> bool:
        try:
            cls.decode_access_token(token)
        except ValueError:
            return False

        return True

    @classmethod
    def verify_refresh_token(cls, token: str) -> bool:
        try:
            cls.decode_refresh_token(token)
        except ValueError:
            return False

        return True
