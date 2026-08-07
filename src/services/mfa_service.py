from typing import Protocol
from uuid import uuid4
from datetime import datetime, timezone, timedelta
from random import randint
from services.config import MFA_REQUEST_EXPIRATION_TIME_MINUTES
from services.user_capability_checker_service import UserCapabilityCheckerServiceProtocol
from services.message_sender import MessageSenderProtocol
from services.hashing_utils import HashingServiceProtocol
from services.exceptions import MFAException, NotAuthenticatedException
from repos.mfa_setup import MfaSetupRepositoryProtocol, MfaSetup
from repos.mfa_login_request import MfaLoginRequestRepositoryProtocol, MfaLoginRequest
from pydantic import BaseModel, Field


class MfaLoginCode(BaseModel):
    id: str = Field(min_length=36, max_length=36)
    code: int


class MFAServiceProtocol(Protocol):
    def setup_mfa(self, 
                  user_id: str,
                  phone_number: str) -> MfaSetup:
        ...

    def remove_mfa(self,
                   user_id: str) -> None:
        ...

    def request_login_code(self, 
                           user_id: str) -> MfaLoginCode:
        ...

    def confirm_login_code(self, mfa_login_code: MfaLoginCode) -> str:
        ...

    def has_mfa(self, 
                user_id: str) -> bool:
        ...


class MFAService:
    def __init__(self,
                 mfa_setup_repo: MfaSetupRepositoryProtocol,
                 mfa_login_request_repo: MfaLoginRequestRepositoryProtocol,
                 user_capability_checker: UserCapabilityCheckerServiceProtocol,
                 message_sender: MessageSenderProtocol,
                 hashing_service: HashingServiceProtocol) -> None:
        self._mfa_setup_repo = mfa_setup_repo
        self._mfa_login_repo = mfa_login_request_repo
        self._user_capability_service = user_capability_checker
        self._message_sender = message_sender
        self._hashing_service = hashing_service

    def setup_mfa(self, 
                  user_id: str,
                  phone_number: str) -> MfaSetup:
        self._user_capability_service.get_capable_user_by_id_or_raise(user_id)

        existing_setup = self._mfa_setup_repo.get_mfa_setup_by_user(user_id)
        if existing_setup is not None:
            raise MFAException("MFA is already set up for this user")

        try:
            setup = MfaSetup(
                user_id=user_id,
                user_phone_number=phone_number
            )
        except ValueError:
            raise MFAException("Invalid phone number format")

        self._mfa_setup_repo.create_mfa_setup(setup)
        return setup
    
    def remove_mfa(self,
                   user_id: str) -> None:
        self._user_capability_service.get_capable_user_by_id_or_raise(user_id)

        existing_setup = self._mfa_setup_repo.get_mfa_setup_by_user(user_id)
        if existing_setup is None:
            raise MFAException("MFA is not set up for this user")

        self._mfa_setup_repo.delete_mfa_setup(user_id)

    def request_login_code(self, 
                           user_id: str) -> MfaLoginCode:
        self._user_capability_service.get_capable_user_by_id_or_raise(user_id)

        mfa_setup = self._mfa_setup_repo.get_mfa_setup_by_user(user_id)
        if mfa_setup is None:
            raise MFAException("MFA is not set up for this user")

        code = randint(100000, 999999)
        code_hash = self._hashing_service.hash_password(str(code))

        request_id = str(uuid4())
        now = datetime.now(timezone.utc)

        login_request = MfaLoginRequest(
            id=request_id,
            user_id=user_id,
            code_hash=code_hash,
            expires_at=now + timedelta(minutes=MFA_REQUEST_EXPIRATION_TIME_MINUTES),
            confirmed_at=None,
            created_at=now
        )
        self._mfa_login_repo.create_request(login_request)

        self._message_sender.send_message(
            receiver=mfa_setup.user_phone_number,
            content=f"Your login code is: {code}"
        )

        return MfaLoginCode(id=request_id, code=code)

    def confirm_login_code(self, 
                           mfa_login_code: MfaLoginCode) -> str:
        request = self._mfa_login_repo.get_request_by_id(mfa_login_code.id)
        if request is None:
            raise MFAException("MFA login request not found")

        now = datetime.now(timezone.utc)
        if request.expires_at <= now:
            raise MFAException("MFA login request has expired")

        if request.confirmed_at is not None:
            raise MFAException("MFA login request has already been confirmed")

        if not self._hashing_service.verify_password_hash(
            request.code_hash,
            str(mfa_login_code.code)
        ):
            raise MFAException("Invalid MFA login code")

        self._mfa_login_repo.confirm_request(request.id, now)
        
        return request.user_id

    def has_mfa(self, 
                user_id: str) -> bool:
        return self._mfa_setup_repo.get_mfa_setup_by_user(user_id) is not None