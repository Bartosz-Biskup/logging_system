from typing import TYPE_CHECKING
from enum import Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String
from datetime import datetime
from db_and_models.base import Base


if TYPE_CHECKING:
    from user_role import UserRole


class AccountState(str, Enum):
    active = "active"
    pending_removal = "pending_removal"
    removed = "removed"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    email: Mapped[str] = mapped_column(String(120), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    account_state: Mapped[AccountState] = mapped_column(default=AccountState.active)
    role: Mapped["UserRole"] = relationship(
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
    created_at: Mapped[datetime]



