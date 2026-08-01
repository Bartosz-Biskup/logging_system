from db_and_models.user import AccountState
from services.auth_service import UserAuthService
from repos.user_repository import User
from services.hashing_utils import HashingService
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from services.config import HASHING_TIME_COST
from argon2 import PasswordHasher

from services.token_service import TokenPair
from repos.refresh_token_repository import RefreshToken
from services.exceptions import NotAuthenticatedException


class FakeTokenService:
    def __init__(self) -> None:
        # kontrolujesz z zewnątrz co ma się stać przy get_valid_refresh_token_or_raise
        self.token_to_return: RefreshToken | None = None
        self.should_raise_invalid: bool = False

        # spy — do sprawdzania "czy i z czym zostałam wywołana"
        self.revoke_token_pair_calls: list[str] = []
        self.revoke_all_calls: list[str] = []
        self.rotate_calls: list[tuple] = []
        self.generate_calls: list[tuple] = []

        # co zwrócić z metod generujących nowe pary
        self.token_pair_to_return: TokenPair = TokenPair(
            access_token="fake-access", refresh_token="fake-refresh"
        )

    def get_valid_refresh_token_or_raise(self, refresh_token: str) -> RefreshToken:
        if self.should_raise_invalid:
            raise NotAuthenticatedException("Invalid refresh token.")
        return self.token_to_return

    def generate_token_pair_for_user(self, user_id: str, username: str, role: str) -> TokenPair:
        self.generate_calls.append((user_id, username, role))
        return self.token_pair_to_return

    def rotate_token_pair(self, refresh_token: str, user_id: str, username: str, role: str) -> TokenPair:
        self.rotate_calls.append((refresh_token, user_id, username, role))
        return self.token_pair_to_return

    def revoke_token_pair(self, refresh_token: str) -> None:
        self.revoke_token_pair_calls.append(refresh_token)

    def revoke_all_user_refresh_tokens(self, user_id: str) -> None:
        self.revoke_all_calls.append(user_id)

    def get_user_id_from_access_token_or_raise(self, access_token: str) -> str:
        if self.should_raise_invalid:
            raise NotAuthenticatedException()
        return self.token_to_return.user_id if self.token_to_return else "unknown"


class FakeCapabilityChecker:
    def __init__(self, user_repo) -> None:
        self._user_repo = user_repo

    def get_capable_user_by_id_or_raise(self, user_id: str) -> User:
        user = self._user_repo.get_user_by_id(user_id)
        if user is None:
            raise NotAuthenticatedException()
        if user.account_state != AccountState.active:
            raise NotAuthenticatedException()
        return user


@pytest.fixture
def fake_token_service():
    return FakeTokenService()

@pytest.fixture
def fake_capability_checker(user_repo):
    return FakeCapabilityChecker(user_repo)

@pytest.fixture
def auth_service(user_repo, fake_token_service, fake_capability_checker):
    return UserAuthService(user_repo, fake_token_service, fake_capability_checker)


def test_get_active_user_or_raise_happy_path(auth_service, user_repo, fake_token_service):
    user_id = str(uuid4())
    fake_token_service.token_to_return = RefreshToken(
        id=user_id,
        user_id=user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        revoked_at=None,
        created_at=datetime.now(timezone.utc)
    )

    user_repo.create_user(
        User(
            id=user_id,
            username="some_username",
            email="example@gmail.com",
            password_hash="somehash",
            account_state=AccountState.active,
            role="user",
            created_at=datetime.now()
        )
    )

    res = auth_service.get_active_user_from_refresh_token_or_raise("some-token")

    assert res.id == user_id

def test_get_active_user_or_raise_user_is_none(auth_service,
                                               user_repo,
                                               fake_token_service):
    user_id = str(uuid4())
    fake_token_service.token_to_return = RefreshToken(
        id=user_id,
        user_id=user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        revoked_at=None,
        created_at=datetime.now(timezone.utc)
    )

    with pytest.raises(NotAuthenticatedException):
        auth_service.get_active_user_from_refresh_token_or_raise("some-token")


def test_get_active_user_or_raise_user_not_capable(auth_service, user_repo, fake_token_service):
    user_id = str(uuid4())
    fake_token_service.token_to_return = RefreshToken(
        id=user_id,
        user_id=user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        revoked_at=None,
        created_at=datetime.now(timezone.utc)
    )

    user_repo.create_user(
        User(
            id=user_id,
            username="some_username",
            email="example@gmail.com",
            password_hash="somehash",
            account_state=AccountState.pending_removal,
            role="user",
            created_at=datetime.now()
        )
    )

    with pytest.raises(NotAuthenticatedException):
        auth_service.get_active_user_from_refresh_token_or_raise("some-token")


def test_login_happy_path(auth_service, user_repo, fake_token_service):
    user_id = str(uuid4())
    password = "SomePassword1!"
    user_repo.create_user(
        User(
            id=user_id,
            username="some_username",
            email="example@gmail.com",
            password_hash=HashingService.hash_password(password),
            account_state=AccountState.active,
            role="user",
            created_at=datetime.now(timezone.utc)
        )
    )

    res = auth_service.login("example@gmail.com", password)

    assert isinstance(res, TokenPair)
    assert fake_token_service.generate_calls == [(user_id, "some_username", "user")]


def test_login_raises_when_user_not_found(auth_service, user_repo):
    with pytest.raises(NotAuthenticatedException):
        auth_service.login("nieistniejacy@gmail.com", "cokolwiek")


def test_login_raises_when_user_not_active(auth_service, user_repo):
    user_repo.create_user(User(
        id=str(uuid4()), username="Broski", email="x@gmail.com",
        password_hash=HashingService.hash_password("Password1!"),
        account_state=AccountState.pending_removal,
        role="user", created_at=datetime.now(timezone.utc)
    ))
    with pytest.raises(NotAuthenticatedException):
        auth_service.login("x@gmail.com", "Password1!")


def test_login_raises_when_password_invalid(auth_service, user_repo):
    user_repo.create_user(User(
        id=str(uuid4()), username="Broski", email="x@gmail.com",
        password_hash=HashingService.hash_password("Password1!"),
        account_state=AccountState.active,
        role="user", created_at=datetime.now(timezone.utc)
    ))
    with pytest.raises(NotAuthenticatedException):
        auth_service.login("x@gmail.com", password="IncorrectPassword1!")

def test_login_password_rehash_when_needed(auth_service, user_repo, monkeypatch):
    # Arrange
    user_id = str(uuid4())
    old_hash = HashingService.hash_password("Password1!")
    user_repo.create_user(User(
        id=user_id, username="Broski", email="x@gmail.com",
        password_hash=old_hash,
        account_state=AccountState.active,
        role="user", created_at=datetime.now(timezone.utc)
    ))

    def fake_needs_rehash(hash_):
        return True

    monkeypatch.setattr("services.auth_service.HashingService.needs_rehash", fake_needs_rehash)

    # Act
    auth_service.login("x@gmail.com", "Password1!")

    # Assert
    updated_user = user_repo.get_user_by_id(user_id)
    assert updated_user.password_hash != old_hash

def test_logout(auth_service, user_repo, fake_token_service):
    user_id = str(uuid4())
    user_repo.create_user(User(
        id=user_id, username="Broski", email="x@gmail.com",
        password_hash=HashingService.hash_password("Password1!"),
        account_state=AccountState.active,
        role="user", created_at=datetime.now(timezone.utc)
    ))

    token_id = str(uuid4())
    fake_token_service.token_to_return = RefreshToken(
        id=token_id,
        user_id=user_id,
        expires_at=datetime.now(timezone.utc)+timedelta(minutes=5),
        revoked_at=None,
        created_at=datetime.now(timezone.utc)
    )

    auth_service.logout("some-refresh-token")

    assert fake_token_service.revoke_token_pair_calls == ["some-refresh-token"]


def test_logout_all_happy_path(auth_service,
                               user_repo,
                               fake_token_service,
                               monkeypatch):
    user_id = str(uuid4())
    user_repo.create_user(User(
        id=user_id, username="Broski", email="x@gmail.com",
        password_hash=HashingService.hash_password("Password1!"),
        account_state=AccountState.active,
        role="user", created_at=datetime.now(timezone.utc)
    ))

    fake_token_service.token_to_return = RefreshToken(
        id=str(uuid4()), user_id=user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        revoked_at=None, created_at=datetime.now(timezone.utc)
    )

    auth_service.logout_all("some-refresh_token")

    assert fake_token_service.revoke_all_calls == [user_id]

def test_refresh_token_pair_happy_path(auth_service, user_repo, fake_token_service):
    user_id = str(uuid4())
    user_repo.create_user(User(
        id=user_id, username="Broski", email="x@gmail.com",
        password_hash=HashingService.hash_password("Password1!"),
        account_state=AccountState.active,
        role="user", created_at=datetime.now(timezone.utc)
    ))

    token_id = str(uuid4())
    fake_token_service.token_to_return = RefreshToken(
        id=str(token_id), user_id=user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        revoked_at=None, created_at=datetime.now(timezone.utc)
    )

    token_pair = TokenPair(refresh_token="some_token", access_token="another_token")
    fake_token_service.token_pair_to_return = token_pair
    res = auth_service.refresh_token_pair("some-refresh-token")

    assert fake_token_service.rotate_calls == [("some-refresh-token",
                                                user_id,
                                                "Broski",
                                                "user")]
    assert res == token_pair


def test_get_active_user_from_access_token_happy_path(auth_service, user_repo, fake_token_service):
    user_id = str(uuid4())
    user_repo.create_user(User(
        id=user_id, username="Broski", email="x@gmail.com",
        password_hash="hash", account_state=AccountState.active,
        role="user", created_at=datetime.now(timezone.utc),
    ))
    fake_token_service.token_to_return = RefreshToken(
        id=str(uuid4()), user_id=user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        revoked_at=None, created_at=datetime.now(timezone.utc),
    )

    result = auth_service.get_active_user_from_access_token_or_raise("valid-access-token")

    assert result.id == user_id


def test_get_active_user_from_access_token_invalid_token(auth_service, fake_token_service):
    fake_token_service.should_raise_invalid = True

    with pytest.raises(NotAuthenticatedException):
        auth_service.get_active_user_from_access_token_or_raise("invalid-token")


def test_get_active_user_from_access_token_user_not_capable(auth_service, user_repo, fake_token_service):
    user_id = str(uuid4())
    user_repo.create_user(User(
        id=user_id, username="Broski", email="x@gmail.com",
        password_hash="hash", account_state=AccountState.pending_removal,
        role="user", created_at=datetime.now(timezone.utc),
    ))
    fake_token_service.token_to_return = RefreshToken(
        id=str(uuid4()), user_id=user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        revoked_at=None, created_at=datetime.now(timezone.utc),
    )

    with pytest.raises(NotAuthenticatedException):
        auth_service.get_active_user_from_access_token_or_raise("valid-token")