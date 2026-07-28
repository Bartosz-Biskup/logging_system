from pydantic import BaseModel, Field
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from repos.exceptions import ObjectAlreadyExists, ObjectNotFoundException
from db_and_models.mfa_setup import MfaSetup as MfaSetupModel


class MfaSetup(BaseModel):
    user_id: str = Field(min_length=36, max_length=36)
    user_phone_number: str = Field(max_length=32)

    model_config = {
        "from_attributes": True
    }


class MfaSetupRepositoryProtocol(Protocol):
    def create_mfa_setup(self, setup: MfaSetup) -> None:
        ...

    def update_mfa_setup(self, setup: MfaSetup) -> None:
        ...

    def get_mfa_setup_by_user(self, user_id: str) -> MfaSetup | None:
        ...

    def delete_mfa_setup(self, user_id: str) -> None:
        ...


class MfaSetupRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create_mfa_setup(self, setup: MfaSetup) -> None:
        orm_setup = MfaSetupModel(
            user_id=setup.user_id,
            user_phone_number=setup.user_phone_number
        )

        self._session.add(orm_setup)

        try:
            self._session.flush()
        except IntegrityError as e:
            raise ObjectAlreadyExists() from e

    def update_mfa_setup(self, setup: MfaSetup) -> None:
        orm_setup: MfaSetupModel | None = self._session.get(
            MfaSetupModel,
            setup.user_id
        )

        if orm_setup is None:
            raise ObjectNotFoundException()

        orm_setup.user_phone_number = setup.user_phone_number

        try:
            self._session.flush()
        except IntegrityError as e:
            raise ObjectAlreadyExists() from e

    def get_mfa_setup_by_user(
        self,
        user_id: str
    ) -> MfaSetup | None:
        stmt = select(MfaSetupModel).where(
            MfaSetupModel.user_id == user_id
        )

        setup: MfaSetupModel | None = self._session.scalar(stmt)

        if setup is None:
            return None

        return MfaSetup.model_validate(setup)

    def delete_mfa_setup(self, user_id: str) -> None:
        orm_setup: MfaSetupModel | None = self._session.get(
            MfaSetupModel,
            user_id
        )

        if orm_setup is None:
            raise ObjectNotFoundException()

        self._session.delete(orm_setup)
        self._session.flush()