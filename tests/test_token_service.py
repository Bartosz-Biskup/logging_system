import pytest
from datetime import datetime, timezone, timedelta
from services.token_service import TokenService, TokenPair
from services.exceptions import NotAuthenticatedException
from repos.refresh_token_repository import RefreshToken
from uuid import uuid4


class FakeRefreshTokenRepository:
    def __init__(self):
        self.tokens: dict[str, RefreshToken] = {}

    def create_refresh_token(self, token: RefreshToken) -> None:
        self.tokens[token.id] = token

    def get_refresh_token_by_id(self, token_id: str):
        return self.tokens.get(token_id)

    def update_refresh_token(self, token: RefreshToken) -> None:
        self.tokens[token.id] = token

    def get_active_by_user(self, user_id: str):
        return [t for t in self.tokens.values() if t.user_id == user_id and t.revoked_at is None]


class FakeAccessTokenBlacklist:
    def __init__(self):
        self.blacklisted: set[str] = set()

    def blacklist_access_token(self, jti: str) -> None:
        self.blacklisted.add(jti)

    def is_access_token_blacklisted(self, jti: str) -> bool:
        return jti in self.blacklisted


@pytest.fixture
def token_repo():
    return FakeRefreshTokenRepository()


@pytest.fixture
def blacklist():
    return FakeAccessTokenBlacklist()


@pytest.fixture
def token_service(token_repo, blacklist):
    return TokenService(token_repo=token_repo, access_token_blacklist=blacklist)


def test_get_valid_refresh_token_happy_path(token_service, token_repo, monkeypatch):
    # Arrange
    jti = str(uuid4())  # ten sam string użyty w payloadzie i w id tokenu w repo

    class DummyPayload:
        pass
    DummyPayload.jti = jti

    monkeypatch.setattr(
        "services.token_service.JWTTokenIssuer.decode_refresh_token",
        lambda token: DummyPayload()  # <- wywołujesz klasę, nie zwracasz jej samej
    )

    stored_token = RefreshToken(
        id=jti,
        user_id=str(uuid4()),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        revoked_at=None,
        created_at=datetime.now(timezone.utc),
    )
    token_repo.create_refresh_token(stored_token)

    # Act
    result = token_service.get_valid_refresh_token_or_raise("any-raw-token-string")

    # Assert
    assert result is stored_token


def test_get_valid_refresh_token_invalid_token_signature(token_service,
                                                         token_repo,
                                                         monkeypatch):
    def raise_value_error(token):
        raise ValueError()
    monkeypatch.setattr("services.token_service.JWTTokenIssuer.decode_refresh_token",
                        raise_value_error
    )

    with pytest.raises(NotAuthenticatedException):
        token_service.get_valid_refresh_token_or_raise("some-refresh-token")


def test_get_valid_refresh_token_token_not_in_db(token_service, token_repo, monkeypatch):
    class DummyPayload:
        pass
    DummyPayload.jti = "some-jti"

    monkeypatch.setattr("services.token_service.JWTTokenIssuer.decode_refresh_token",
                        lambda token: DummyPayload())

    with pytest.raises(NotAuthenticatedException):
        token_service.get_valid_refresh_token_or_raise("some non existing rt")


def test_get_valid_refresh_token_revoked(token_service, token_repo, monkeypatch):
    class DummyPayload:
        pass
    jti= str(uuid4())
    DummyPayload.jti = jti
    DummyPayload.revoked_at = datetime.now()

    stored_token = RefreshToken(
        id=jti,
        user_id=str(uuid4()),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        revoked_at=datetime.now(),
        created_at=datetime.now(timezone.utc),
    )
    token_service._token_repo.create_refresh_token(stored_token)

    monkeypatch.setattr("services.token_service.JWTTokenIssuer.decode_refresh_token",
                        lambda token: DummyPayload())

    with pytest.raises(NotAuthenticatedException):
        token_service.get_valid_refresh_token_or_raise("some_ref_token")


def test_generate_token_pair_for_user(token_service, token_repo, monkeypatch):
    class DummyToken:
        def __init__(self, jti, user_id):
            self.jti = jti
            self.user_id = user_id

    access_token_called = False
    refresh_token_called = False

    def create_access_token(user_id, username, role, jti):
        nonlocal access_token_called
        access_token_called = True
        return jti

    def create_refresh_token(user_id, jti):
        nonlocal refresh_token_called
        refresh_token_called = True
        return jti, jti, user_id, datetime.now(timezone.utc)+timedelta(minutes=15)

    monkeypatch.setattr("services.token_service.JWTTokenIssuer.create_access_token",
                        create_access_token)

    monkeypatch.setattr("services.token_service.JWTTokenIssuer.create_refresh_token",
                        create_refresh_token)

    user_id = str(uuid4())

    result = token_service.generate_token_pair_for_user(user_id,
                                                        "username",
                                                        "admin")

    assert result.access_token == result.refresh_token
    assert access_token_called and refresh_token_called
    assert len(token_service._token_repo.get_active_by_user(user_id)) == 1
    assert token_service._token_repo.get_refresh_token_by_id(result.refresh_token) is not None

from services.JWT_utils import JWTTokenIssuer


def test_rotate_token_pair_happy_path(token_service, token_repo, blacklist):
    # Arrange
    user_id = str(uuid4())
    old_pair = token_service.generate_token_pair_for_user(user_id, "some_username", "user")
    old_jti = JWTTokenIssuer.decode_refresh_token(old_pair.refresh_token).jti

    # Act
    new_pair = token_service.rotate_token_pair(old_pair.refresh_token, user_id, "some_username", "user")

    # Assert — stary token revoked i zablacklistowany
    old_token = token_repo.get_refresh_token_by_id(old_jti)
    assert old_token.revoked_at is not None
    assert blacklist.is_access_token_blacklisted(old_jti)

    # Assert — nowy token aktywny, inny jti niż stary
    new_jti = JWTTokenIssuer.decode_refresh_token(new_pair.refresh_token).jti
    new_token = token_repo.get_refresh_token_by_id(new_jti)
    assert new_token is not None
    assert new_token.revoked_at is None
    assert new_jti != old_jti


def test_rotate_token_pair_user_id_mismatch(token_service, token_repo, blacklist):
    # Arrange
    real_user_id = str(uuid4())
    someone_elses_id = str(uuid4())
    pair = token_service.generate_token_pair_for_user(real_user_id, "some_username", "user")
    jti = JWTTokenIssuer.decode_refresh_token(pair.refresh_token).jti

    # Act & Assert
    with pytest.raises(NotAuthenticatedException):
        token_service.rotate_token_pair(pair.refresh_token, someone_elses_id, "some_username", "user")

    # Assert — nic się nie zmutowało, oryginalny token dalej aktywny
    token = token_repo.get_refresh_token_by_id(jti)
    assert token.revoked_at is None
    assert not blacklist.is_access_token_blacklisted(jti)


def test_revoke_token_pair(token_service, token_repo, blacklist):
    user_id = str(uuid4())
    username = "Gordzo"
    role = "Boss"

    token_pair = token_service.generate_token_pair_for_user(user_id, username, role)
    token_pair_jti = JWTTokenIssuer.decode_refresh_token(token_pair.refresh_token).jti

    token_service.revoke_token_pair(token_pair.refresh_token)
    users_token = [token.jti for token in token_repo.get_active_by_user(user_id)]

    assert token_repo.get_refresh_token_by_id(token_pair_jti).revoked_at is not None
    assert blacklist.is_access_token_blacklisted(token_pair_jti)
    assert token_pair_jti not in users_token

def test_revoke_all_users_refresh_token(token_service, token_repo, blacklist):
    user_id = str(uuid4())
    username = "Gordzo"
    role = "Boss"

    tokens: list[TokenPair] = [token_service.generate_token_pair_for_user(user_id,
                                                                          username,
                                                                          role) for _ in range(10)]
    another_user_token = token_service.generate_token_pair_for_user(str(uuid4()), "a", "b")

    #revoking some of the tokens just to see what happens to previously revoked tokens
    token_service.revoke_token_pair(tokens[0].refresh_token)
    token_service.revoke_token_pair(tokens[1].refresh_token)

    token_service.revoke_all_user_refresh_tokens(user_id)

    for token in tokens:
        token_jti = JWTTokenIssuer.decode_refresh_token(token.refresh_token).jti
        assert token_repo.get_refresh_token_by_id(token_jti).revoked_at is not None
        assert blacklist.is_access_token_blacklisted(token_jti)

    another_token_jti = JWTTokenIssuer.decode_refresh_token(another_user_token.refresh_token).jti
    assert token_repo.get_refresh_token_by_id(another_token_jti).revoked_at is None
    assert not blacklist.is_access_token_blacklisted(another_token_jti)


def test_get_user_id_from_access_token_happy_path(token_service, blacklist, monkeypatch):
    # Arrange
    class DummyPayload:
        pass
    DummyPayload.jti = "some-jti"
    DummyPayload.sub = "user-123"

    monkeypatch.setattr(
        "services.token_service.JWTTokenIssuer.decode_access_token",
        lambda token: DummyPayload(),
    )

    # Act
    user_id = token_service.get_user_id_from_access_token_or_raise("valid-access-token")

    # Assert
    assert user_id == "user-123"


def test_get_user_id_from_access_token_invalid(token_service, monkeypatch):
    monkeypatch.setattr(
        "services.token_service.JWTTokenIssuer.decode_access_token",
        lambda token: (_ for _ in ()).throw(ValueError()),
    )

    with pytest.raises(NotAuthenticatedException):
        token_service.get_user_id_from_access_token_or_raise("invalid-token")


def test_get_user_id_from_access_token_blacklisted(token_service, blacklist, monkeypatch):
    # Arrange
    class DummyPayload:
        pass
    DummyPayload.jti = "blacklisted-jti"
    DummyPayload.sub = "user-123"

    monkeypatch.setattr(
        "services.token_service.JWTTokenIssuer.decode_access_token",
        lambda token: DummyPayload(),
    )
    blacklist.blacklist_access_token("blacklisted-jti")

    # Act & Assert
    with pytest.raises(NotAuthenticatedException):
        token_service.get_user_id_from_access_token_or_raise("blacklisted-token")

