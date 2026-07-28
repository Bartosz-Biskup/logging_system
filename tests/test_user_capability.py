from uuid import uuid4
import pytest
from datetime import datetime, timezone, timedelta
from services.user_capability_checker_service import UserCapabilityCheckerService
from services.ban_service import BanService
from services.exceptions import NotAuthenticatedException
from repos.user_repository import User, AccountState
from repos.ban_repository import Ban



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


class FakeBanRepository:
    def __init__(self) -> None:
        self.bans: dict[str, Ban] = {}

    def create_ban(self, ban: Ban):
        self.bans[ban.id] = ban

    def update_ban(self, ban: Ban):
        self.bans[ban.id] = ban

    def get_ban_by_id(self, ban_id: str) -> Ban | None:
        return self.bans.get(ban_id, None)

    def get_ban_by_user(self, user_id: str) -> list[Ban]:
        user_bans: list[Ban] = []
        for ban in self.bans.values():
            if ban.user_id == user_id:
                user_bans.append(ban)

        return user_bans


@pytest.fixture
def user_repo():
    return FakeUserRepository()

@pytest.fixture
def ban_repo():
    return FakeBanRepository()

@pytest.fixture
def ban_service(ban_repo, user_repo):
    return BanService(ban_repo, user_repo)

@pytest.fixture
def capability_service(user_repo, ban_service):
    return UserCapabilityCheckerService(user_repo, ban_service)


def test_get_capable_user_happy_path(capability_service, user_repo):
    user_id = str(uuid4())
    user = User(
        id=user_id, 
        username="Broski", 
        email="some@gmail.com", 
        password_hash="somehash", 
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc),
    )
    user_repo.create_user(user)

    user_retrieved = capability_service.get_capable_user_by_id_or_raise(user_id)

    assert user == user_retrieved

def test_get_capable_user_not_found(capability_service, user_repo):
    with pytest.raises(NotAuthenticatedException):
        capability_service.get_capable_user_by_id_or_raise("SomeUserIdThatDoesntExist")

def test_get_capable_user_not_active(capability_service, user_repo):
    user_id = str(uuid4())
    user = User(
        id=user_id, 
        username="Broski", 
        email="some@gmail.com", 
        password_hash="somehash", 
        account_state=AccountState.pending_removal,
        role="user",
        created_at=datetime.now(timezone.utc),
    )
    user_repo.create_user(user)

    with pytest.raises(NotAuthenticatedException):
        capability_service.get_capable_user_by_id_or_raise(user_id)

def test_get_capable_user_banned(capability_service, user_repo, ban_repo):
    user_id = str(uuid4())
    user = User(
        id=user_id, 
        username="Broski", 
        email="some@gmail.com", 
        password_hash="somehash", 
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc),
    )
    user_repo.create_user(user)

    ban = Ban(
        id=str(uuid4()),
        user_id=user_id,
        banned_at=datetime.now(timezone.utc) - timedelta(days=1),
        banned_until=datetime.now(timezone.utc) + timedelta(days=1),
        reason="Spam",
        banned_by=None,
        revoked_at=None,
    )
    ban_repo.create_ban(ban)
    
    with pytest.raises(NotAuthenticatedException):
        capability_service.get_capable_user_by_id_or_raise(user_id)