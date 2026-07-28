from datetime import datetime, timezone, timedelta
from uuid import uuid4

import pytest

from db_and_models.user import AccountState
from repos.password_reset_repo import PasswordResetRequest
from services.password_reset_service import PasswordResetService
from repos.user_repository import User
from services.user_capability_checker_service import UserCapabilityCheckerService
from services.ban_service import BanService
from services.config import PASSWORD_RESET_REQUEST_DELAY_HOURS


class FakeUserRepository:
    def __init__(self) -> None:
        self.users: dict[str, User] = {}

    def create_user(self, user: User) -> None:
        self.users[user.id] = user

    def update_user(self, user: User) -> None:
        if self.users.get(user.id) is None:
            raise ValueError
        self.users[user.id] = user

    def get_user_by_id(self, u_id: str) -> User | None:
        return self.users.get(u_id)

    def get_user_by_username(self, username: str) -> User | None:
        for user in self.users.values():
            if user.username == username:
                return user

    def get_user_by_email(self, email: str) -> User | None:
        for user in self.users.values():
            if user.email == email.lower():
                return user


class FakePasswordResetRequestRepository:
    def __init__(self) -> None:
        self.requests: list[PasswordResetRequest] = []

    def get_reset_request_by_id(self, id: str) -> PasswordResetRequest | None:
        for request in self.requests:
            if request.id == id:
                return request

    def update_reset_request(self, request_: PasswordResetRequest) -> None:
        id = request_.id
        for index, request in enumerate(self.requests):
            if request.id == id:
                self.requests[index] = request_
                return

        raise ValueError


    def create_reset_request(self, request: PasswordResetRequest) -> None:
        if self.get_reset_request_by_id(request.id) is not None:
            raise ValueError

        self.requests.append(request)

    def get_last_user_reset_request(self, user_id: str) -> PasswordResetRequest | None:
        requests = [r for r in self.requests if r.user_id == user_id]

        if not requests:
            return None

        last_request: PasswordResetRequest = requests[0]
        for request in requests[1::]:
            if request.created_at < last_request.created_at:
                last_request = request

        return last_request


class FakeMailSender:
    def __init__(self) -> None:
        self.send_calls: list[tuple[str, str, str]] = []

    def send(self, recipient, subject, content) -> None:
        self.send_calls.append((recipient.lower(), subject, content))


from repos.ban_repository import Ban as BanModel

class FakeBanRepository:
    def __init__(self) -> None:
        self.bans: dict[str, BanModel] = {}

    def create_ban(self, ban: BanModel) -> None:
        if ban.id in self.bans:
            raise ValueError(f"Ban {ban.id} already exists")
        self.bans[ban.id] = ban

    def update_ban(self, ban: BanModel) -> None:
        if ban.id not in self.bans:
            raise ValueError(f"Ban {ban.id} not found")
        self.bans[ban.id] = ban

    def get_ban_by_id(self, ban_id: str) -> BanModel | None:
        return self.bans.get(ban_id)

    def get_ban_by_user(self, user_id: str) -> list[BanModel]:
        return [b for b in self.bans.values() if b.user_id == user_id]


@pytest.fixture
def user_repo():
    return FakeUserRepository()

@pytest.fixture
def password_repo():
    return FakePasswordResetRequestRepository()

@pytest.fixture
def mail_sender():
    return FakeMailSender()

@pytest.fixture
def ban_repo():
    return FakeBanRepository()

@pytest.fixture
def ban_service(ban_repo, user_repo):
    return BanService(ban_repo, user_repo)

@pytest.fixture
def capability_checker(user_repo, ban_service):
    return UserCapabilityCheckerService(user_repo, ban_service)

@pytest.fixture
def reset_service(password_repo, user_repo, mail_sender, capability_checker):
    return PasswordResetService(password_repo, 
                                user_repo, 
                                mail_sender,
                                capability_checker)


def test_generate_and_send_creates_new_link_when_none_exists(reset_service,
                                                             user_repo,
                                                             password_repo,
                                                             mail_sender):
    user_id = str(uuid4())
    user = User(
        id=user_id,
        username="Broski",
        email="Some@gmail.com",
        password_hash="SomeHashMyNigga",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc)
    )
    user_repo.create_user(user)

    reset_service.generate_and_send_password_reset_link("some@gmail.com")

    assert len(mail_sender.send_calls) == 1
    assert mail_sender.send_calls[0][0] == "some@gmail.com"
    assert password_repo.get_last_user_reset_request(user_id) is not None


def test_generate_and_send_does_nothing_when_user_has_active_request(reset_service,
                                                                      user_repo,
                                                                      password_repo,
                                                                      mail_sender):
    user_id = str(uuid4())
    user = User(
        id=user_id,
        username="Broski",
        email="Some@gmail.com",
        password_hash="SomeHashMyNigga",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc)
    )
    user_repo.create_user(user)
    reset_service.generate_and_send_password_reset_link("some@gmail.com")

    # generating the link for the same email again
    reset_service.generate_and_send_password_reset_link("some@gmail.com")

    assert len(mail_sender.send_calls) == 1
    assert len(password_repo.requests) == 1

def test_generate_and_send_does_raises_when_user_not_found(reset_service): 
    with pytest.raises(ValueError):
        reset_service.generate_and_send_password_reset_link("notexistingemail@gmail.com")


def test_generate_and_send_raises_when_user_banned(reset_service, user_repo, ban_service): 
    user_id = str(uuid4())
    user = User(
        id=user_id,
        username="Broski",
        email="some@gmail.com",
        password_hash="SomeHashMyNigga",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc)
    )
    user_repo.create_user(user)
    ban_service.ban_user(user_id, 5012, "idk")

    with pytest.raises(ValueError):
        reset_service.generate_and_send_password_reset_link("some@gmail.com")

def test_generate_and_send_creates_and_send_new_link_when_last_link_expired(reset_service, password_repo, user_repo, mail_sender):
    user_id = str(uuid4())
    user = User(
            id=user_id,
            username="Broski",
            email="some@gmail.com",
            password_hash="SomeHashMyNigga",
            account_state=AccountState.active,
            role="user",
            created_at=datetime.now(timezone.utc)
        )
    user_repo.create_user(user)
    reset_service.generate_and_send_password_reset_link("some@gmail.com")
    last_reset_link = password_repo.get_last_user_reset_request(user_id)
    last_reset_link.created_at = datetime.now(timezone.utc) - timedelta(hours=PASSWORD_RESET_REQUEST_DELAY_HOURS, minutes=10)
    last_reset_link.expires_at = datetime.now(timezone.utc) - timedelta(hours=PASSWORD_RESET_REQUEST_DELAY_HOURS, minutes=20)

    reset_service.generate_and_send_password_reset_link("some@gmail.com")

    assert len(mail_sender.send_calls) == 2
    assert len(password_repo.requests) == 2


def test_generate_and_send_raises_when_delay_not_passed_since_last_request(
    reset_service,
    user_repo,
    password_repo,
    mail_sender,
):
    user_id = str(uuid4())
    user = User(
        id=user_id,
        username="Broski",
        email="some@gmail.com",
        password_hash="SomeHashMyNigga",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc),
    )
    user_repo.create_user(user)
    reset_service.generate_and_send_password_reset_link("some@gmail.com")


    last_link = password_repo.get_last_user_reset_request(user_id)
    last_link.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)

    with pytest.raises(ValueError):
        reset_service.generate_and_send_password_reset_link("some@gmail.com")

    # Nothing new was created or sent
    assert len(mail_sender.send_calls) == 1
    assert len(password_repo.requests) == 1


def test_reset_password_happy_path(reset_service, password_repo, mocker, user_repo): 
    user_id = str(uuid4())
    user = User(
        id=user_id,
        username="Broski",
        email="some@gmail.com",
        password_hash="SomeHashMyNigga",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc),
    )
    user_repo.create_user(user)

    reset_service.generate_and_send_password_reset_link("some@gmail.com")
    reset_link: PasswordResetRequest = password_repo.requests[0]

    mock_func = mocker.patch("services.hashing_utils.HashingService.hash_password", 
                 return_value="NewPasswordHash")

    reset_service.reset_password_with_reset_request(reset_link.id, "SomeNewPassword1!")

    updated_user = user_repo.get_user_by_id(user_id)
    

    mock_func.assert_called_once()
    assert updated_user.password_hash == "NewPasswordHash"
    assert password_repo.get_reset_request_by_id(reset_link.id).used_at is not None


def test_reset_password_raises_when_user_removed_after_link_generated(reset_service, user_repo, password_repo): 
    user_id = str(uuid4())
    user = User(
        id=user_id,
        username="Broski",
        email="some@gmail.com",
        password_hash="SomeHashMyNigga",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc),
    )
    user_repo.create_user(user)

    reset_service.generate_and_send_password_reset_link("some@gmail.com")
    user.account_state = AccountState.removed
    user_repo.update_user(user)

    with pytest.raises(ValueError):
        reset_service.reset_password_with_reset_request(password_repo.requests[0].id, "SomePasswordDoesntMatter1!")
    assert user_repo.get_user_by_id(user_id).password_hash == "SomeHashMyNigga" # making sure password hasn't changed before raising an error


def test_reset_password_raises_when_link_already_used(reset_service, user_repo, password_repo, mocker): 
    user_id = str(uuid4())
    user = User(
        id=user_id,
        username="Broski",
        email="some@gmail.com",
        password_hash="SomeHashMyNigga",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc),
    )
    user_repo.create_user(user)

    def fake_hash(password: str) -> str:
        return password
    mocker.patch("services.hashing_utils.HashingService.hash_password", new=fake_hash)

    reset_service.generate_and_send_password_reset_link("some@gmail.com")
    reset_service.reset_password_with_reset_request(password_repo.requests[0].id, "NewPassword1!")

    with pytest.raises(ValueError):
        reset_service.reset_password_with_reset_request(password_repo.requests[0].id, "NewPassword2!")
    assert user_repo.get_user_by_id(user_id).password_hash == "NewPassword1!"


def test_reset_password_raises_when_link_expired(reset_service, user_repo, password_repo): 
    user_id = str(uuid4())
    user = User(
        id=user_id,
        username="Broski",
        email="some@gmail.com",
        password_hash="SomeHashMyNigga",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc),
    )
    user_repo.create_user(user)

    reset_service.generate_and_send_password_reset_link("some@gmail.com")
    req = password_repo.requests[0]
    req.created_at = datetime.now(timezone.utc) - timedelta(minutes=60)
    req.expires_at = datetime.now(timezone.utc) - timedelta(minutes=50)

    with pytest.raises(ValueError):
        reset_service.reset_password_with_reset_request(password_repo.requests[0].id, "NewPassword1!")
    assert user_repo.get_user_by_id(user_id).password_hash == "SomeHashMyNigga" # # making sure password hasn't changed before raising an error
