from pydantic import BaseModel, Field
from datetime import datetime, timezone
from typing import Protocol
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from repos.exceptions import ObjectAlreadyExists, ObjectNotFoundException
from repos._types import UTCDateTime, UTCDateTimeOrNone
from db_and_models.mfa_login_request import (
    MfaLoginRequest as MfaLoginRequestModel
)


class MfaLoginRequest(BaseModel):
    id: str = Field(min_length=36, max_length=36)
    user_id: str = Field(min_length=36, max_length=36)
    code_hash: str = Field(max_length=256)
    expires_at: UTCDateTime
    confirmed_at: UTCDateTimeOrNone = None
    created_at: UTCDateTime

    model_config = {
        "from_attributes": True
    }


class MfaLoginRequestRepositoryProtocol(Protocol):
    def create_request(self, request: MfaLoginRequest) -> None:
        ...

    def confirm_request(
        self,
        request_id: str,
        confirmed_at: datetime
    ) -> None:
        ...

    def get_request_by_id(
        self,
        request_id: str
    ) -> MfaLoginRequest | None:
        ...

    def get_active_request_by_user(
        self,
        user_id: str
    ) -> MfaLoginRequest | None:
        ...

    def update_request(
        self,
        request: MfaLoginRequest
    ) -> None:
        ...


class MfaLoginRequestRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create_request(
        self,
        request: MfaLoginRequest
    ) -> None:
        orm_request = MfaLoginRequestModel(
            id=request.id,
            user_id=request.user_id,
            code_hash=request.code_hash,
            expires_at=request.expires_at,
            confirmed_at=request.confirmed_at,
            created_at=request.created_at
        )

        self._session.add(orm_request)

        try:
            self._session.flush()
        except IntegrityError as e:
            raise ObjectAlreadyExists() from e

    def confirm_request(
        self,
        request_id: str,
        confirmed_at: datetime
    ) -> None:
        orm_request: MfaLoginRequestModel | None = self._session.get(
            MfaLoginRequestModel,
            request_id
        )

        if orm_request is None:
            raise ObjectNotFoundException()

        orm_request.confirmed_at = confirmed_at

        self._session.flush()

    def get_request_by_id(
        self,
        request_id: str
    ) -> MfaLoginRequest | None:
        request: MfaLoginRequestModel | None = self._session.get(
            MfaLoginRequestModel,
            request_id
        )

        if request is None:
            return None

        return MfaLoginRequest.model_validate(request)

    def get_active_request_by_user(
        self,
        user_id: str
    ) -> MfaLoginRequest | None:
        stmt = (
            select(MfaLoginRequestModel)
            .where(
                MfaLoginRequestModel.user_id == user_id,
                MfaLoginRequestModel.confirmed_at.is_(None),
                MfaLoginRequestModel.expires_at > datetime.now(timezone.utc)
            )
        )

        request: MfaLoginRequestModel | None = self._session.scalar(stmt)

        if request is None:
            return None

        return MfaLoginRequest.model_validate(request)

    def update_request(
        self,
        request: MfaLoginRequest
    ) -> None:
        orm_request: MfaLoginRequestModel | None = self._session.get(
            MfaLoginRequestModel,
            request.id
        )

        if orm_request is None:
            raise ObjectNotFoundException()

        orm_request.user_id = request.user_id
        orm_request.code_hash = request.code_hash
        orm_request.expires_at = request.expires_at
        orm_request.confirmed_at = request.confirmed_at
        orm_request.created_at = request.created_at

        try:
            self._session.flush()
        except IntegrityError as e:
            raise ObjectAlreadyExists() from e