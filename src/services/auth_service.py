from typing import Protocol, NoReturn
from services.token_service import TokenServiceProtocol, TokenPair
from repos.user_repository import UserRepositoryProtocol, User
from services.hashing_utils import HashingService
from services.exceptions import NotAuthenticatedException
from services.user_capability_checker_service import UserCapabilityCheckerServiceProtocol


class UserAuthServiceProtocol(Protocol):
    def login(self, email: str, password: str) -> TokenPair:
        ...

    def logout(self, refresh_token: str) -> None:
        ...

    def logout_all(self, refresh_token: str) -> None:
        ...

    def refresh_token_pair(self, refresh_token: str) -> TokenPair:
        ...

    def get_active_user_from_refresh_token_or_raise(self, refresh_token: str) -> User:
        ...

    def get_active_user_from_access_token_or_raise(self, access_token: str) -> User:
        ...


class UserAuthService:
    def __init__(self,
                 user_repo: UserRepositoryProtocol,
                 token_service: TokenServiceProtocol,
                 capability_checker: UserCapabilityCheckerServiceProtocol) -> None:
        self._user_repo = user_repo
        self._token_service = token_service
        self._capability_checker = capability_checker

    def get_active_user_from_refresh_token_or_raise(self, refresh_token: str) -> User:
        ref_token = self._token_service.get_valid_refresh_token_or_raise(refresh_token)
        return self._capability_checker.get_capable_user_by_id_or_raise(ref_token.user_id)

    def get_active_user_from_access_token_or_raise(self, access_token: str) -> User:
        user_id: str = self._token_service.get_user_id_from_access_token_or_raise(access_token)
        return self._capability_checker.get_capable_user_by_id_or_raise(user_id)

    def _update_user_password_hash(self, user: User, new_hash: str) -> None:
        user.password_hash = new_hash
        self._user_repo.update_user(user)

    def _raise_authentication_failure(self) -> NoReturn:
        """Raises NotAuthenticatedException after running a dummy hash
        to prevent timing-based user enumeration."""
        HashingService.run_some_dummy_hash()
        raise NotAuthenticatedException()

    def _get_user_by_email_or_reject(self, email: str) -> User:
        user = self._user_repo.get_user_by_email(email)
        if user is None:
            self._raise_authentication_failure()

        return user

    def _ensure_user_capable_or_reject(self, user: User) -> None:
        try:
            self._capability_checker.get_capable_user_by_id_or_raise(user.id)
        except NotAuthenticatedException:
            self._raise_authentication_failure()

    def login(self, email: str, password: str) -> TokenPair:
        user = self._get_user_by_email_or_reject(email)
        self._ensure_user_capable_or_reject(user)

        if not HashingService.verify_password_hash(user.password_hash, password):
            raise NotAuthenticatedException()

        if HashingService.needs_rehash(user.password_hash):
            self._update_user_password_hash(user, HashingService.hash_password(password))

        return self._token_service.generate_token_pair_for_user(user.id, user.username, user.role)

    def logout(self, refresh_token: str) -> None:
        self.get_active_user_from_refresh_token_or_raise(refresh_token)
        self._token_service.revoke_token_pair(refresh_token)

    def logout_all(self, refresh_token: str) -> None:
        user: User = self.get_active_user_from_refresh_token_or_raise(refresh_token)
        self._token_service.revoke_all_user_refresh_tokens(user.id)

    def refresh_token_pair(self, refresh_token: str) -> TokenPair:
        user: User = self.get_active_user_from_refresh_token_or_raise(refresh_token)
        return self._token_service.rotate_token_pair(refresh_token, user.id, user.username, user.role)
