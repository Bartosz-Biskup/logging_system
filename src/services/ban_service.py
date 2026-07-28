from datetime import datetime, timezone, timedelta
from uuid import uuid4
from typing import Protocol

from repos.ban_repository import BanRepositoryProtocol, Ban
from repos.user_repository import UserRepositoryProtocol


class BanServiceProtocol(Protocol):
    def is_user_banned(self, user_id: str) -> bool:
        ...

    def ban_user(self, user_id: str,
                 banned_for_days: int,
                 reason: str,
                 banned_by: str | None = None) -> None:
        ...

    def unban_user(self, user_id: str) -> None:
        ...


class BanService:
    def __init__(self,
                 ban_repo: BanRepositoryProtocol,
                 user_repo: UserRepositoryProtocol) -> None:
        self._ban_repo = ban_repo
        self._user_repo = user_repo

    @staticmethod
    def _is_ban_active(ban: Ban) -> bool:
        now = datetime.now(timezone.utc)
        return ban.revoked_at is None and ban.banned_until > now

    def _get_active_ban(self, user_id: str) -> Ban | None:
        bans = self._ban_repo.get_ban_by_user(user_id)
        for ban in bans:
            if self._is_ban_active(ban):
                return ban
        return None

    def _revoke_ban(self, ban: Ban) -> None:
        ban.revoked_at = datetime.now(timezone.utc)
        self._ban_repo.update_ban(ban)

    def is_user_banned(self, user_id: str) -> bool:
        return self._get_active_ban(user_id) is not None

    def ban_user(self, user_id: str,
                 banned_for_days: int,
                 reason: str,
                 banned_by: str | None = None) -> None:
        if banned_for_days <= 0:
            raise ValueError("banned_for_days must be positive")

        user = self._user_repo.get_user_by_id(user_id)
        if user is None:
            raise ValueError(f"User {user_id} not found")

        active_ban = self._get_active_ban(user_id)
        if active_ban is not None:
            self._revoke_ban(active_ban)

        now = datetime.now(timezone.utc)
        new_ban = Ban(
            id=str(uuid4()),
            user_id=user_id,
            banned_at=now,
            banned_until=now + timedelta(days=banned_for_days),
            reason=reason,
            banned_by=banned_by,
            revoked_at=None
        )
        self._ban_repo.create_ban(new_ban)

    def unban_user(self, user_id: str) -> None:
        active_ban = self._get_active_ban(user_id)
        if active_ban is None:
            raise ValueError(f"User {user_id} is not currently banned")
        self._revoke_ban(active_ban)
