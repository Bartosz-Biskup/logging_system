from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone
from typing import Protocol
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from repos.exceptions import ObjectNotFoundException, ObjectAlreadyExists
from db_and_models.ban import Ban as BanModel


class Ban(BaseModel):
    id: str = Field(min_length=36, max_length=36)
    user_id: str = Field(min_length=36, max_length=36)
    banned_at: datetime
    banned_until: datetime
    reason: str | None = Field(max_length=255)
    banned_by: str | None = Field(min_length=36, max_length=36)
    revoked_at: datetime | None = None

    @field_validator("banned_at", "banned_until", "revoked_at", mode="before")
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


class BanRepositoryProtocol(Protocol):
    def create_ban(self, ban: Ban) -> None:
        ...

    def update_ban(self, ban: Ban) -> None:
        ...

    def get_ban_by_id(self, ban_id: str) -> Ban | None:
        ...

    def get_ban_by_user(self, user_id: str) -> list[Ban]:
        ...


class BanRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create_ban(self, ban: Ban) -> None:
        orm_ban = BanModel(
            id=ban.id,
            user_id=ban.user_id,
            banned_at=ban.banned_at,
            banned_until=ban.banned_until,
            reason=ban.reason,
            banned_by=ban.banned_by,
            revoked_at=ban.revoked_at
        )

        self._session.add(orm_ban)
        try:
            self._session.flush()
        except IntegrityError as e:
            raise ObjectAlreadyExists() from e

    def update_ban(self, ban: Ban) -> None:
        orm_ban: BanModel | None = self._session.get(BanModel, ban.id)
        if orm_ban is None:
            raise ObjectNotFoundException()

        orm_ban.user_id = ban.user_id
        orm_ban.banned_at = ban.banned_at
        orm_ban.banned_until = ban.banned_until
        orm_ban.reason = ban.reason
        orm_ban.banned_by = ban.banned_by
        orm_ban.revoked_at = ban.revoked_at

        try:
            self._session.flush()
        except IntegrityError as e:
            raise ObjectAlreadyExists() from e

    def get_ban_by_id(self, ban_id: str) -> Ban | None:
        stmt = select(BanModel).where(BanModel.id == ban_id)
        ban: BanModel | None = self._session.scalar(stmt)

        if ban is None:
            return None

        return Ban.model_validate(ban)

    def get_ban_by_user(self, user_id: str) -> list[Ban]:
        stmt = select(BanModel).where(BanModel.user_id == user_id)
        bans: list[BanModel] = list(self._session.scalars(stmt).all())
        return [Ban.model_validate(b) for b in bans]

        return [Ban.model_validate(ban) for ban in bans]
