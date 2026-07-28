from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
from typing import Protocol
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from repos.exceptions import ObjectNotFoundException, ObjectAlreadyExists
from db_and_models.refresh_token import RefreshToken as RefreshTokenModel


class RefreshToken(BaseModel):
    id: str = Field(min_length=36, max_length=36)
    user_id: str = Field(min_length=36, max_length=36)
    expires_at: datetime
    revoked_at: datetime | None = None
    created_at: datetime

    @field_validator("expires_at", "revoked_at", "created_at", mode="before")
    @classmethod
    def validate_datetime(
        cls,
        value: datetime | None
    ) -> datetime | None:
        if value is None:
            return None

        return value.replace(tzinfo=timezone.utc)

    model_config = {
        "from_attributes": True
    }


class RefreshTokenRepositoryProtocol(Protocol):
    def create_refresh_token(self, token: RefreshToken) -> None:
        ...

    def update_refresh_token(self, token: RefreshToken) -> None:
        ...

    def get_refresh_token_by_id(self, rt_id: str) -> RefreshToken | None:
        ...

    def get_refresh_token_by_user(
        self,
        user_id: str
    ) -> list[RefreshToken]:
        ...

    def get_active_by_user(
        self,
        user_id: str
    ) -> list[RefreshToken]:
        ...

    def delete_token(self, token_id: str) -> None:
        ...


class RefreshTokenRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create_refresh_token(self, token: RefreshToken) -> None:
        orm_token = RefreshTokenModel(
            id=token.id,
            user_id=token.user_id,
            expires_at=token.expires_at,
            revoked_at=token.revoked_at,
            created_at=token.created_at
        )

        self._session.add(orm_token)

        try:
            self._session.flush()
        except IntegrityError as e:
            raise ObjectAlreadyExists() from e

    def update_refresh_token(self, token: RefreshToken) -> None:
        orm_token: RefreshTokenModel | None = self._session.get(
            RefreshTokenModel,
            token.id
        )

        if orm_token is None:
            raise ObjectNotFoundException()

        orm_token.expires_at = token.expires_at
        orm_token.revoked_at = token.revoked_at

        try:
            self._session.flush()
        except IntegrityError as e:
            raise ObjectAlreadyExists() from e

    def get_refresh_token_by_id(
        self,
        rt_id: str
    ) -> RefreshToken | None:
        token: RefreshTokenModel | None = self._session.get(
            RefreshTokenModel,
            rt_id
        )

        if token is None:
            return None

        return RefreshToken.model_validate(token)

    def get_refresh_token_by_user(
        self,
        user_id: str
    ) -> list[RefreshToken]:
        stmt = select(RefreshTokenModel).where(
            RefreshTokenModel.user_id == user_id
        )

        tokens = self._session.scalars(stmt).all()

        return [
            RefreshToken.model_validate(token)
            for token in tokens
        ]

    def get_active_by_user(
        self,
        user_id: str
    ) -> list[RefreshToken]:
        stmt = (
            select(RefreshTokenModel)
            .where(
                RefreshTokenModel.user_id == user_id,
                RefreshTokenModel.revoked_at.is_(None),
                RefreshTokenModel.expires_at > datetime.now(timezone.utc)
            )
        )

        tokens = self._session.scalars(stmt).all()

        return [
            RefreshToken.model_validate(token)
            for token in tokens
        ]

    def delete_token(self, token_id: str) -> None:
        orm_token: RefreshTokenModel | None = self._session.get(
            RefreshTokenModel,
            token_id
        )

        if orm_token is None:
            raise ObjectNotFoundException()

        self._session.delete(orm_token)
        self._session.flush()