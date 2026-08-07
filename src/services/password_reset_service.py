from datetime import datetime, timezone, timedelta
from typing import Protocol
from uuid import uuid4
from repos.password_reset_repo import PasswordResetRequestRepositoryProtocol, PasswordResetRequest
from repos.user_repository import UserRepositoryProtocol, User
from services.config import (PASSWORD_RESET_REQUEST_EXPIRATION_TIME_HOURS,
                             PASSWORD_RESET_REQUEST_DELAY_HOURS)
from services.mail_sender_service import MailSenderProtocol
from services.hashing_utils import HashingServiceProtocol
from services.password_validator import is_password_valid
from services.exceptions import NotAuthenticatedException, InvalidPasswordException
from services.user_capability_checker_service import UserCapabilityCheckerServiceProtocol


class PasswordResetServiceProtocol(Protocol):
    def generate_and_send_password_reset_link(self, user_email: str) -> None:
        ...

    def reset_password_with_reset_request(self,
                                          reset_request_id: str,
                                          new_password: str) -> None:
        ...


class PasswordResetService:
    def __init__(self,
                 password_reset_repository: PasswordResetRequestRepositoryProtocol,
                 user_repository: UserRepositoryProtocol,
                 mail_sender: MailSenderProtocol,
                 capability_checker: UserCapabilityCheckerServiceProtocol,
                 hashing_service: HashingServiceProtocol) -> None:
        self._password_reset_repo = password_reset_repository
        self._user_repo = user_repository
        self._mail_sender = mail_sender
        self._capability_checker = capability_checker
        self._hashing_service = hashing_service

    def _get_capable_user_by_email_or_raise(self, email: str) -> User:
        user: User | None = self._user_repo.get_user_by_email(email.lower())

        if user is None:
            raise ValueError("User not found")

        try:
            self._capability_checker.get_capable_user_by_id_or_raise(user.id)
        except NotAuthenticatedException:
            raise ValueError("User not found")

        return user

    def _is_reset_request_valid(self, reset_request: PasswordResetRequest) -> bool:
        now = datetime.now(timezone.utc)

        if reset_request.created_at > now:
            return False

        if reset_request.used_at is not None:
            return False

        if reset_request.expires_at < now:
            return False

        return True

    def generate_and_send_password_reset_link(self, user_email: str) -> None:
        user: User = self._get_capable_user_by_email_or_raise(user_email)
        last_link: PasswordResetRequest | None = self._password_reset_repo.get_last_user_reset_request(user.id)
        
        now = datetime.now(timezone.utc)
        if last_link is None:
            req_id: str = str(uuid4())
            new_request = PasswordResetRequest(
                id=req_id,
                user_id=user.id,
                created_at=now,
                expires_at=now + timedelta(hours=PASSWORD_RESET_REQUEST_EXPIRATION_TIME_HOURS),
                used_at=None
            )
            self._password_reset_repo.create_reset_request(new_request)
            self._mail_sender.send(user_email, 
                                               "5012 password reset request",
                                               f"Hey, here is your password reset link: {req_id}")
        elif self._is_reset_request_valid(last_link):
            ...
        elif last_link.created_at + timedelta(hours=PASSWORD_RESET_REQUEST_DELAY_HOURS) > now:
            raise ValueError('Cannot generate new password request link')
        else:
            req_id = str(uuid4())
            new_request = PasswordResetRequest(
                id=req_id,
                user_id=user.id,
                created_at=now,
                expires_at=now + timedelta(hours=PASSWORD_RESET_REQUEST_EXPIRATION_TIME_HOURS),
                used_at=None
            )
            self._password_reset_repo.create_reset_request(new_request)
            self._mail_sender.send(user_email, 
                                   "5012 password reset request",
                                   f"Hey, here is your password reset link: {req_id}")

    def reset_password_with_reset_request(self,
                                          reset_request_id: str,
                                          new_password: str) -> None:
        reset_req: PasswordResetRequest | None = self._password_reset_repo.get_reset_request_by_id(reset_request_id)
        if reset_req is None:
            raise ValueError('Invalid reset request id.')
        if not self._is_reset_request_valid(reset_req):
            raise ValueError("Reset request invalid or expired")

        user: User | None = self._user_repo.get_user_by_id(reset_req.user_id)
        if user is None:
            raise ValueError("User doesn't exist")

        try:
            self._capability_checker.get_capable_user_by_id_or_raise(user.id)
        except NotAuthenticatedException:
            raise ValueError("User cannot reset their password")

        if not is_password_valid(new_password):
            raise InvalidPasswordException()

        user.password_hash = self._hashing_service.hash_password(new_password)
        reset_req.used_at = datetime.now(timezone.utc)
        self._password_reset_repo.update_reset_request(reset_req)
        self._user_repo.update_user(user)

