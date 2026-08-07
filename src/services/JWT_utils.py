from jose import jwt, JWTError
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field
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


class JWTTokenIssuer:
    """Encodes, decodes, and verifies JWT access & refresh tokens.

    Secrets are injected via __init__ — no module-level side effects,
    fully testable without monkeypatching.
    """

    def __init__(
        self,
        access_token_secret: str,
        refresh_token_secret: str,
    ) -> None:
        self._access_secret = access_token_secret
        self._refresh_secret = refresh_token_secret

    # -- config (overrideable via __init__ if needed) --
    issuer: str = JWT_TOKEN_ISSUER
    access_exp_minutes: int = ACCESS_TOKEN_EXP_TIME_MINUTES
    refresh_exp_days: int = REFRESH_TOKEN_EXP_TIME_DAYS
    token_aud: str = TOKEN_AUD

    # ------------------------------------------------------------
    #  Public API
    # ------------------------------------------------------------

    def create_access_token(
        self, user_id: str, username: str, role: str, jti: str | None = None,
    ) -> str:
        jti = jti or str(uuid4())
        now = datetime.now(timezone.utc)
        payload = AccessTokenPayload(
            sub=user_id,
            jti=jti,
            iss=self.issuer,
            username=username,
            iat=now,
            exp=now + timedelta(minutes=self.access_exp_minutes),
            aud=self.token_aud,
            role=role,
        )
        return jwt.encode(payload.model_dump(), self._access_secret, "HS256")

    def create_refresh_token(
        self, user_id: str, jti: str | None = None,
    ) -> tuple[str, str, str, datetime]:
        jti = jti or str(uuid4())
        now = datetime.now(timezone.utc)
        payload = RefreshTokenPayload(
            sub=user_id,
            jti=jti,
            iss=self.issuer,
            iat=now,
            exp=now + timedelta(days=self.refresh_exp_days),
            aud=self.token_aud,
        )
        token = jwt.encode(payload.model_dump(), self._refresh_secret, "HS256")
        return token, payload.jti, payload.sub, payload.exp

    def decode_access_token(self, token: str) -> AccessTokenPayload:
        try:
            payload = jwt.decode(
                token,
                key=self._access_secret,
                algorithms="HS256",
                audience=self.token_aud,
                issuer=self.issuer,
            )
        except JWTError:
            raise ValueError("Invalid token.")
        return AccessTokenPayload.model_validate(payload)

    def decode_refresh_token(self, token: str) -> RefreshTokenPayload:
        try:
            payload = jwt.decode(
                token,
                key=self._refresh_secret,
                algorithms="HS256",
                audience=self.token_aud,
                issuer=self.issuer,
            )
        except JWTError:
            raise ValueError("Invalid token.")
        return RefreshTokenPayload.model_validate(payload)

    def verify_access_token(self, token: str) -> bool:
        try:
            self.decode_access_token(token)
        except ValueError:
            return False
        return True

    def verify_refresh_token(self, token: str) -> bool:
        try:
            self.decode_refresh_token(token)
        except ValueError:
            return False
        return True
