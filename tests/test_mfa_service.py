from uuid import uuid4
import pytest
from datetime import datetime, timezone, timedelta
from db_and_models.user import AccountState
from services.mfa_service import MFAService, MfaLoginCode
from services.hashing_utils import HashingService
from services.user_capability_checker_service import UserCapabilityCheckerService
from services.message_sender import MessageSender
from services.exceptions import MFAException, NotAuthenticatedException
from repos.user_repository import User, UserRepositoryProtocol
from repos.mfa_login_request import MfaLoginRequest, MfaLoginRequestRepositoryProtocol
from repos.mfa_setup import MfaSetup, MfaSetupRepositoryProtocol


class FakeBanService:
    def __init__(self) -> None:
        self._banned_users: set[str] = set()

    def is_user_banned(self, user_id: str) -> bool:
        return user_id in self._banned_users

    def ban_user(self, user_id: str,
                 banned_for_days: int,
                 reason: str,
                 banned_by: str | None = None) -> None:
        self._banned_users.add(user_id)

    def unban_user(self, user_id: str) -> None:
        self._banned_users.discard(user_id)


class FakeMfaSetupRepository:
    def __init__(self) -> None:
        self.setups: dict[str, MfaSetup] = {}

    def create_mfa_setup(self, setup: MfaSetup) -> None:
        self.setups[setup.user_id] = setup

    def update_mfa_setup(self, setup: MfaSetup) -> None:
        if self.setups.get(setup.user_id) is None:
            raise ValueError(f"MFA setup {setup.user_id} not found")
        self.setups[setup.user_id] = setup

    def get_mfa_setup_by_user(self, user_id: str) -> MfaSetup | None:
        return self.setups.get(user_id)

    def delete_mfa_setup(self, user_id: str) -> None:
        if self.setups.get(user_id) is None:
            raise ValueError(f"MFA setup {user_id} not found")
        del self.setups[user_id]


class FakeMfaLoginRequestRepository:
    def __init__(self) -> None:
        self.requests: dict[str, MfaLoginRequest] = {}

    def create_request(self, request: MfaLoginRequest) -> None:
        self.requests[request.id] = request

    def confirm_request(self, request_id: str, confirmed_at: datetime) -> None:
        request = self.requests.get(request_id)
        if request is None:
            raise ValueError(f"MFA login request {request_id} not found")
        request.confirmed_at = confirmed_at

    def get_request_by_id(self, request_id: str) -> MfaLoginRequest | None:
        return self.requests.get(request_id)

    def get_active_request_by_user(self, user_id: str) -> MfaLoginRequest | None:
        now = datetime.now(timezone.utc)
        for request in self.requests.values():
            if (request.user_id == user_id
                    and request.confirmed_at is None
                    and request.expires_at > now):
                return request
        return None

    def update_request(self, request: MfaLoginRequest) -> None:
        if self.requests.get(request.id) is None:
            raise ValueError(f"MFA login request {request.id} not found")
        self.requests[request.id] = request


@pytest.fixture
def mfa_setup_repo():
    return FakeMfaSetupRepository()


@pytest.fixture
def mfa_login_request_repo():
    return FakeMfaLoginRequestRepository()


@pytest.fixture
def ban_service():
    return FakeBanService()


@pytest.fixture
def user_capability_checker(user_repo, ban_service):
    return UserCapabilityCheckerService(user_repo, ban_service)


@pytest.fixture
def message_sender():
    return MessageSender()


@pytest.fixture
def hashing_service():
    return HashingService()


@pytest.fixture
def mfa_service(mfa_setup_repo, mfa_login_request_repo, user_capability_checker, message_sender, hashing_service):
    return MFAService(mfa_setup_repo, mfa_login_request_repo, user_capability_checker, message_sender, hashing_service)


def get_user_with_mfa(user_repo: UserRepositoryProtocol, 
                      mfa_repo: MfaSetupRepositoryProtocol) -> User:
    user_id = str(uuid4())
    user: User = User(
        id=user_id,
        username="Broski",
        email="abc@example.com",
        password_hash="SomeHash",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc)
    )

    user_repo.create_user(user)

    mfa_setup = MfaSetup(
        user_id=user_id,
        user_phone_number="+48123456789"
    )

    mfa_repo.create_mfa_setup(mfa_setup)

    return user


def get_user_without_mfa(user_repo: UserRepositoryProtocol) -> User:
    user_id = str(uuid4())
    user: User = User(
        id=user_id,
        username="Broski",
        email="abc@example.com",
        password_hash="SomeHash",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc)
    )

    user_repo.create_user(user)

    return user


def test_setup_mfa_happy_path(mfa_service, mfa_setup_repo, user_repo):
    user = get_user_without_mfa(user_repo)

    mfa_service.setup_mfa(user.id, "+33202020202")

    assert mfa_setup_repo.get_mfa_setup_by_user(user.id) is not None
    assert mfa_setup_repo.get_mfa_setup_by_user(user.id).user_phone_number == "+33202020202"

def test_setup_mfa_raises_when_invalid_number_format(mfa_service, mfa_setup_repo, user_repo):
    user = get_user_without_mfa(user_repo)

    with pytest.raises(MFAException):
        mfa_service.setup_mfa(user.id, "1234")

    assert mfa_setup_repo.get_mfa_setup_by_user(user.id) is None

def test_setup_mfa_raises_when_user_not_capable(mfa_service, mfa_setup_repo, user_repo):
    user = get_user_without_mfa(user_repo)
    user.account_state = AccountState.removed
    user_repo.update_user(user)

    with pytest.raises(NotAuthenticatedException):
        mfa_service.setup_mfa(user.id, "+33202020202")
    assert mfa_setup_repo.get_mfa_setup_by_user(user.id) is None

def test_setup_mfa_raises_when_mfa_already_set_up(mfa_service, mfa_setup_repo, user_repo):
    user = get_user_with_mfa(user_repo, mfa_setup_repo)

    with pytest.raises(MFAException):
        mfa_service.setup_mfa(user.id, "+33202020202")

def test_remove_mfa_happy_path(mfa_service, mfa_setup_repo, user_repo):
    user = get_user_with_mfa(user_repo, mfa_setup_repo)

    mfa_service.remove_mfa(user.id)

    assert mfa_setup_repo.get_mfa_setup_by_user(user.id) is None

def test_remove_mfa_raises_when_user_not_capable(mfa_service, mfa_setup_repo, user_repo):
    user = get_user_without_mfa(user_repo)
    user.account_state = AccountState.removed
    user_repo.update_user(user)

    with pytest.raises(NotAuthenticatedException):
        mfa_service.remove_mfa(user.id)

def test_remove_mfa_raises_when_mfa_not_set_up(mfa_service, user_repo):
    user = get_user_without_mfa(user_repo)

    with pytest.raises(MFAException):
        mfa_service.remove_mfa(user.id)

def test_request_login_code_happy_path(mfa_service, mfa_setup_repo, user_repo, mfa_login_request_repo):
    user = get_user_with_mfa(user_repo, mfa_setup_repo)

    result = mfa_service.request_login_code(user.id)

    assert isinstance(result, MfaLoginCode)
    assert len(result.id) == 36
    assert 100000 <= result.code <= 999999

    # Verify that a login request was created
    active_request = mfa_login_request_repo.get_active_request_by_user(user.id)
    assert active_request is not None
    assert active_request.confirmed_at is None

def test_request_login_code_raises_when_mfa_not_set_up(mfa_service, user_repo):
    user = get_user_without_mfa(user_repo)

    with pytest.raises(MFAException):
        mfa_service.request_login_code(user.id)

def test_confirm_login_code_happy_path(mfa_service, mfa_setup_repo, user_repo, mfa_login_request_repo):
    user = get_user_with_mfa(user_repo, mfa_setup_repo)

    # First request a login code
    login_code = mfa_service.request_login_code(user.id)

    # Then confirm it
    mfa_service.confirm_login_code(login_code)

    # Verify the request was confirmed
    request = mfa_login_request_repo.get_request_by_id(login_code.id)
    assert request is not None
    assert request.confirmed_at is not None

def test_confirm_login_code_raises_when_request_expired(mfa_service, mfa_setup_repo, user_repo, mfa_login_request_repo):
    user = get_user_with_mfa(user_repo, mfa_setup_repo)

    login_code = mfa_service.request_login_code(user.id)

    # Manually expire the request
    request = mfa_login_request_repo.get_request_by_id(login_code.id)
    request.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)

    with pytest.raises(MFAException):
        mfa_service.confirm_login_code(login_code)

def test_confirm_login_code_raises_when_request_already_confirmed(mfa_service, mfa_setup_repo, user_repo, mfa_login_request_repo):
    user = get_user_with_mfa(user_repo, mfa_setup_repo)

    login_code = mfa_service.request_login_code(user.id)

    # Confirm it once
    mfa_service.confirm_login_code(login_code)

    # Try to confirm again
    with pytest.raises(MFAException):
        mfa_service.confirm_login_code(login_code)

def test_confirm_login_code_raises_when_code_invalid(mfa_service, mfa_setup_repo, user_repo):
    user = get_user_with_mfa(user_repo, mfa_setup_repo)

    login_code = mfa_service.request_login_code(user.id)

    # Tamper with the code
    wrong_code = MfaLoginCode(id=login_code.id, code=000000)

    with pytest.raises(MFAException):
        mfa_service.confirm_login_code(wrong_code)


def test_resend_mfa_happy_path(mfa_service, mfa_login_request_repo, user_repo, mfa_setup_repo):
    user = get_user_with_mfa(user_repo, mfa_setup_repo)
    login_code = mfa_service.request_login_code(user.id)

    new_code = mfa_service.resend_mfa_code(login_code.id)

    assert mfa_login_request_repo.get_request_by_id(login_code.id).expires_at < datetime.now(timezone.utc)
    assert isinstance(new_code, MfaLoginCode)
    assert mfa_login_request_repo.get_request_by_id(new_code.id) is not None


def test_resend_mfa_raises_when_mfa_expired(mfa_service, mfa_login_request_repo, user_repo, mfa_setup_repo):
    user = get_user_with_mfa(user_repo, mfa_setup_repo)
    login_code = mfa_service.request_login_code(user.id)
    mfa_login_request = mfa_login_request_repo.get_request_by_id(login_code.id)
    mfa_login_request.expires_at = datetime.now(timezone.utc) - timedelta(minutes=3)

    with pytest.raises(MFAException):
        new_code = mfa_service.resend_mfa_code(login_code.id)

def test_resend_mfa_raises_when_used(mfa_service, mfa_login_request_repo, user_repo, mfa_setup_repo):
    user = get_user_with_mfa(user_repo, mfa_setup_repo)
    login_code = mfa_service.request_login_code(user.id)
    mfa_login_request = mfa_login_request_repo.get_request_by_id(login_code.id)
    mfa_login_request.confirmed_at = datetime.now(timezone.utc)

    with pytest.raises(MFAException):
        new_code = mfa_service.resend_mfa_code(login_code.id)