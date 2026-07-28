from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, ForeignKey
from db_and_models.base import Base


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(20))