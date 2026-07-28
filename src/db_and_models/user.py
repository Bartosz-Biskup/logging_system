from enum import Enum
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String
from datetime import datetime
from db_and_models.base import Base


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
    role: Mapped[str] = mapped_column(String(20), default="user")
    created_at: Mapped[datetime]



