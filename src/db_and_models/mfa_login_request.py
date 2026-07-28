from sqlalchemy.orm import mapped_column, Mapped
from sqlalchemy import String, ForeignKey
from datetime import datetime
from db_and_models.base import Base


class MfaLoginRequest(Base):
    __tablename__ = "MFA_login_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id",
                                                                ondelete="CASCADE"))
    code_hash: Mapped[str] = mapped_column(String(256))
    expires_at: Mapped[datetime]
    confirmed_at: Mapped[datetime | None]
    created_at: Mapped[datetime]
