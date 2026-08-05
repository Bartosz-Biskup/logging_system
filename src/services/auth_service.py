from typing import Protocol, NoReturn
from pydantic import BaseModel
from enum import Enum
from services.token_service import TokenServiceProtocol, TokenPair
from repos.user_repository import UserRepositoryProtocol, User
from services.hashing_utils import HashingService
from services.exceptions import InvalidPasswordException, MFAException, NotAuthenticatedException, UserNotFoundException
from services.user_capability_checker_service import UserCapabilityCheckerServiceProtocol
from services.password_validator import is_password_valid
from services.mfa_service import MFAServiceProtocol, MfaLoginCode


class LoginStatus(Enum):
    authenticated = "authenticated"
    mfa_required = "mfa_required"


class LoginResponse(BaseModel):
    status: LoginStatus
    token_pair: TokenPair | None
    mfa_request_id: str | None


class UserAuthServiceProtocol(Protocol):
    def login(self, email: str, password: str) -> LoginResponse:
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

    def verify_password_or_reject(self, user: User, password: str) -> None:
        ...

    def confirm_mfa(self, mfa_code: MfaLoginCode) -> TokenPair:
        ...


class UserAuthService:
    def __init__(self,
                 user_repo: UserRepositoryProtocol,
                 token_service: TokenServiceProtocol,
                 capability_checker: UserCapabilityCheckerServiceProtocol,
                 mfa_service: MFAServiceProtocol) -> None:
        self._user_repo = user_repo
        self._token_service = token_service
        self._capability_checker = capability_checker
        self._mfa_service = mfa_service

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

    def verify_password_or_reject(self, user: User, password: str) -> None:
        if not HashingService.verify_password_hash(user.password_hash, password):
            self._raise_authentication_failure()

    def login(self, email: str, password: str) -> LoginResponse:
        user = self._get_user_by_email_or_reject(email)
        self._ensure_user_capable_or_reject(user)

        self.verify_password_or_reject(user, password)

        if HashingService.needs_rehash(user.password_hash):
            self._update_user_password_hash(user, HashingService.hash_password(password))

        if self._mfa_service.has_mfa(user.id):
            mfa_code = self._mfa_service.request_login_code(user.id)
            return LoginResponse(
                status=LoginStatus.mfa_required,
                token_pair=None,
                mfa_request_id=mfa_code.id
            )

        return LoginResponse(
            status=LoginStatus.authenticated,
            token_pair=self._token_service.generate_token_pair_for_user(user.id, user.username, user.role),
            mfa_request_id=None
        )

    def confirm_mfa(self, mfa_code: MfaLoginCode) -> TokenPair:
        user_id = self._mfa_service.confirm_login_code(mfa_code)
        user = self._user_repo.get_user_by_id(user_id)
        assert user is not None

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

    def change_password(self,
                        user: User,
                        current_password: str,
                        new_password: str) -> User:
        self._ensure_user_capable_or_reject(user)

        if not HashingService.verify_password_hash(user.password_hash, current_password):
            raise NotAuthenticatedException("Invalid current password provided")

        if not is_password_valid(new_password):
            raise InvalidPasswordException("Invalid new password")

        user.password_hash = HashingService.hash_password(new_password)
        self._user_repo.update_user(user)
        return user



        
