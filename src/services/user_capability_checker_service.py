from repos.user_repository import User, UserRepositoryProtocol, AccountState
from services.ban_service import BanServiceProtocol
from services.exceptions import NotAuthenticatedException
from typing import Protocol


class UserCapabilityCheckerServiceProtocol(Protocol):
    def get_capable_user_by_id_or_raise(self, user_id: str) -> User:
        ...


class UserCapabilityCheckerService:
    def __init__(self,
                 user_repo: UserRepositoryProtocol,
                 ban_service: BanServiceProtocol) -> None:
        self._user_repo = user_repo
        self._ban_service = ban_service

    def get_capable_user_by_id_or_raise(self, user_id: str) -> User:
        user: User | None = self._user_repo.get_user_by_id(user_id)

        if user is None:
            raise NotAuthenticatedException("User not found")

        if user.account_state != AccountState.active:
            raise NotAuthenticatedException("User is removed or pending removal")

        if self._ban_service.is_user_banned(user_id):
            raise NotAuthenticatedException("User is banned")

        return user
        
