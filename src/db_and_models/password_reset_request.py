from sqlalchemy.orm import mapped_column, Mapped
from sqlalchemy import String, ForeignKey
from datetime import datetime
from db_and_models.base import Base


class PasswordResetRequest(Base):
    __tablename__ = "password_reset_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id",
                                                                ondelete="CASCADE"))
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
    created_at: Mapped[datetime]