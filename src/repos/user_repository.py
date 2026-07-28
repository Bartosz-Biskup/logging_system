from pydantic import BaseModel, Field, EmailStr, field_validator
from sqlalchemy import select
from datetime import datetime, timezone
from typing import Protocol
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload
from db_and_models.user import User as UserModel
from db_and_models.user import AccountState
from db_and_models.user_role import UserRole
from repos.exceptions import ObjectNotFoundException, ObjectAlreadyExists


class User(BaseModel):
    id: str = Field(min_length=36, max_length=36)
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr = Field(max_length=120)
    password_hash: str = Field(max_length=256)
    account_state: AccountState
    role: str = Field(max_length=20)
    created_at: datetime

    @field_validator('created_at', mode='before')
    @classmethod
    def validate_datetime(cls, value: datetime) -> datetime:
        return value.replace(tzinfo=timezone.utc)

    @field_validator('email', mode='before')
    @classmethod
    def validate_email(cls, value: str) -> str:
        return value.lower()

    model_config = {
        "from_attributes": True
    }


class UserRepositoryProtocol(Protocol):
    def create_user(self, user: User) -> None:
        ...

    def update_user(self, user: User) -> None:
        ...

    def get_user_by_id(self, u_id: str) -> User | None:
        ...

    def get_user_by_username(self, username: str) -> User | None:
        ...

    def get_user_by_email(self, email: str) -> User | None:
        ...


class UserRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    @staticmethod
    def _to_domain(user: UserModel) -> User:
        return User(
            id=user.id,
            username=user.username,
            email=user.email,
            password_hash=user.password_hash,
            account_state=user.account_state,
            role=user.role.role,
            created_at=user.created_at,
        )

    def create_user(self, user: User) -> None:
        orm_user = UserModel(
            id=user.id,
            username=user.username,
            email=user.email,
            password_hash=user.password_hash,
            account_state=user.account_state,
            role=UserRole(role=user.role),
            created_at=datetime.now(timezone.utc)
        )

        self._session.add(orm_user)
        try:
            self._session.flush()
        except IntegrityError as e:
            raise ObjectAlreadyExists() from e

    def update_user(self, user: User) -> None:
        orm_user: UserModel | None = self._session.get(UserModel, user.id)
        if orm_user is None:
            raise ObjectNotFoundException()

        orm_user.username = user.username
        orm_user.email = user.email
        orm_user.password_hash = user.password_hash
        orm_user.account_state = user.account_state
        orm_user.role.role = user.role
        orm_user.created_at = user.created_at

        try:
            self._session.flush()
        except IntegrityError as e:
            raise ObjectAlreadyExists() from e

    def get_user_by_id(self, u_id: str) -> User | None:
        stmt = (select(UserModel)
                .options(joinedload(UserModel.role))
                .where(UserModel.id == u_id))
        user = self._session.scalar(stmt)

        if user is None:
            return None

        return self._to_domain(user)

    def get_user_by_username(self, username: str) -> User | None:
        stmt = (select(UserModel)
                .options(joinedload(UserModel.role))
                .where(UserModel.username == username))
        user = self._session.scalar(stmt)

        if user is None:
            return None

        return self._to_domain(user)

    def get_user_by_email(self, email: str) -> User | None:
        stmt = (select(UserModel)
                .options(joinedload(UserModel.role))
                .where(UserModel.email == email))
        user = self._session.scalar(stmt)

        if user is None:
            return None

        return self._to_domain(user)
