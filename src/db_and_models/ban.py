from sqlalchemy.orm import mapped_column, Mapped
from sqlalchemy import String, ForeignKey
from datetime import datetime
from db_and_models.base import Base


class Ban(Base):
    __tablename__ = "bans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id",
                                                                ondelete="CASCADE"))
    banned_at: Mapped[datetime]
    banned_until: Mapped[datetime]
    reason: Mapped[str | None] = mapped_column(String(255))
    banned_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id",
                                                                  ondelete="SET NULL"))
    revoked_at: Mapped[datetime | None]
