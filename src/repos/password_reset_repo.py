from pydantic import BaseModel, field_validator, Field
from typing import Protocol, Self
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select
from db_and_models.password_reset_request import PasswordResetRequest as PasswordResetRequestModel


class PasswordResetRequest(BaseModel):
    id: str = Field(min_length=36, max_length=36)
    user_id: str = Field(min_length=36, max_length=36)
    expires_at: datetime
    used_at: datetime | None
    created_at: datetime

    @field_validator('expires_at', 'used_at', 'created_at', mode='before')
    @classmethod
    def validate(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None

        return value.replace(tzinfo=timezone.utc)


class PasswordResetRequestRepositoryProtocol(Protocol):
    def get_reset_request_by_id(self, id: str) -> PasswordResetRequest | None:
        ...

    def update_reset_request(self, request: PasswordResetRequest) -> None:
        ...

    def create_reset_request(self, request: PasswordResetRequest) -> None:
        ...

    def get_last_user_reset_request(self, user_id: str) -> PasswordResetRequest | None:
        ...


class PasswordResetRequestRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    @staticmethod
    def _to_domain(r: PasswordResetRequestModel) -> PasswordResetRequest:
        return PasswordResetRequest(
            id=r.id,
            user_id=r.user_id,
            expires_at=r.expires_at,
            used_at=r.used_at,
            created_at=r.created_at
        )

    def get_reset_request_by_id(self, id: str) -> PasswordResetRequest | None:
        stmt = select(PasswordResetRequestModel).where(PasswordResetRequestModel.id == id)
        password_r = self._session.scalar(stmt)

        if password_r is None:
            return None

        return self._to_domain(password_r)

    def create_reset_request(self, request: PasswordResetRequest) -> None:
        model = PasswordResetRequestModel(
            id=request.id,
            user_id=request.user_id,
            expires_at=request.expires_at,
            used_at=request.used_at,
            created_at=request.created_at
        )
        self._session.add(model)

    def update_reset_request(self, request: PasswordResetRequest) -> None:
        stmt = select(PasswordResetRequestModel).where(PasswordResetRequestModel.id == request.id)
        model = self._session.scalar(stmt)

        if model is None:
            raise ValueError(f"Reset request {request.id} not found")

        model.used_at = request.used_at
        model.expires_at = request.expires_at

    def get_last_user_reset_request(self, user_id: str) -> PasswordResetRequest | None:
        stmt = (
            select(PasswordResetRequestModel)
            .where(PasswordResetRequestModel.user_id == user_id)
            .order_by(PasswordResetRequestModel.created_at.desc())
            .limit(1)
        )
        password_r = self._session.scalar(stmt)

        if password_r is None:
            return None

        return self._to_domain(password_r)