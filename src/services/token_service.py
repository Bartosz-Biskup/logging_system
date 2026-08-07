from typing import Protocol
from pydantic import BaseModel
from uuid import uuid4
from datetime import datetime, timezone
from redis import Redis
from repos.refresh_token_repository import (RefreshToken,
                                            RefreshTokenRepositoryProtocol)
from services.JWT_utils import AccessTokenPayload, JWTTokenIssuer, RefreshTokenPayload
from services.exceptions import NotAuthenticatedException


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str


class TokenServiceProtocol(Protocol):
    def generate_token_pair_for_user(self, user_id: str, username: str, role: str) -> TokenPair:
        ...

    def rotate_token_pair(self, refresh_token: str, user_id: str, username: str, role: str) -> TokenPair:
        ...

    def revoke_token_pair(self, refresh_token: str) -> None:
        ...

    def revoke_all_user_refresh_tokens(self, user_id: str) -> None:
        ...

    def get_valid_refresh_token_or_raise(self, refresh_token: str) -> RefreshToken:
        ...

    def get_user_id_from_access_token_or_raise(self, access_token: str) -> str:
        ...


class AccessTokenBlacklistProtocol(Protocol):
    def blacklist_access_token(self, jti: str) -> None:
        ...

    def is_access_token_blacklisted(self, jti: str) -> bool:
        ...


class AccessTokenBlacklist:
    def __init__(self, redis: Redis, ttl_seconds: int) -> None:
        self._redis = redis
        self._ttl_seconds = ttl_seconds

    def blacklist_access_token(self, jti: str) -> None:
        self._redis.setex(f"blacklist:access:{jti}", self._ttl_seconds, "1")

    def is_access_token_blacklisted(self, jti: str) -> bool:
        return self._redis.exists(f"blacklist:access:{jti}") == 1


class TokenService:
    def __init__(self,
                 token_repo: RefreshTokenRepositoryProtocol,
                 access_token_blacklist: AccessTokenBlacklistProtocol,
                 jwt_issuer: JWTTokenIssuer) -> None:
        self._token_repo = token_repo
        self._access_token_blacklist = access_token_blacklist
        self._jwt_issuer = jwt_issuer

    def get_valid_refresh_token_or_raise(self, refresh_token: str) -> RefreshToken:
        try:
            token_: RefreshTokenPayload = self._jwt_issuer.decode_refresh_token(refresh_token)
        except ValueError:
            raise NotAuthenticatedException("Invalid refresh token.")

        token: RefreshToken | None = self._token_repo.get_refresh_token_by_id(token_.jti)

        if token is None:
            raise NotAuthenticatedException("Invalid or revoked refresh token.")
        if token.revoked_at is not None:
            raise NotAuthenticatedException("Invalid or revoked refresh token.")

        return token

    def get_user_id_from_access_token_or_raise(self, access_token: str) -> str:
        try:
            token: AccessTokenPayload = self._jwt_issuer.decode_access_token(access_token)
        except ValueError:
            raise NotAuthenticatedException("Invalid access token.")

        if self._access_token_blacklist.is_access_token_blacklisted(token.jti):
            raise NotAuthenticatedException()

        return token.sub

    def generate_token_pair_for_user(self, user_id: str, username: str, role: str) -> TokenPair:
        jti: str = str(uuid4())
        access_token = self._jwt_issuer.create_access_token(
            user_id=user_id,
            username=username,
            role=role,
            jti=jti,
        )
        refresh_token, jti, sub, exp = self._jwt_issuer.create_refresh_token(
            user_id=user_id, jti=jti,
        )

        self._token_repo.create_refresh_token(RefreshToken(
            id=jti,
            user_id=user_id,
            expires_at=exp,
            revoked_at=None,
            created_at=datetime.now(timezone.utc)
        ))

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token
        )

    def rotate_token_pair(self, refresh_token: str, user_id: str, username: str, role: str) -> TokenPair:
        token = self.get_valid_refresh_token_or_raise(refresh_token)
        if token.user_id != user_id:
            raise NotAuthenticatedException("Token.user_id and user_id are different.")

        token.revoked_at = datetime.now(timezone.utc)
        self._access_token_blacklist.blacklist_access_token(token.id)
        self._token_repo.update_refresh_token(token)
        return self.generate_token_pair_for_user(token.user_id, username, role)

    def revoke_token_pair(self, refresh_token: str) -> None:
        token: RefreshToken = self.get_valid_refresh_token_or_raise(refresh_token)
        token.revoked_at = datetime.now(timezone.utc)
        self._access_token_blacklist.blacklist_access_token(token.id)
        self._token_repo.update_refresh_token(token)

    def revoke_all_user_refresh_tokens(self, user_id: str) -> None:
        tokens: list[RefreshToken] = self._token_repo.get_active_by_user(user_id)
        for token in tokens:
            if token.revoked_at is not None:
                continue # one day we may switch from suing get_active_by_user to smth like get_all_users_token
            token.revoked_at = datetime.now(timezone.utc)
            self._access_token_blacklist.blacklist_access_token(token.id)
            self._token_repo.update_refresh_token(token)
