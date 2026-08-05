from sqlalchemy.orm import mapped_column, Mapped
from sqlalchemy import String, ForeignKey
from db_and_models.base import Base


class MfaSetup(Base):
    __tablename__ = "MFA_setups"
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id",
                                                                ondelete="CASCADE"),
                                         primary_key=True)
    user_phone_number: Mapped[str] = mapped_column(String(16), unique=True)