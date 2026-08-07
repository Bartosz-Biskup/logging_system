import pytest
from datetime import datetime, timezone, timedelta
from services.token_service import TokenService, TokenPair
from services.exceptions import NotAuthenticatedException
from services.JWT_utils import JWTTokenIssuer
from repos.refresh_token_repository import RefreshToken
from uuid import uuid4


# ---------------------------------------------------------------------------
#  Fakes
# ---------------------------------------------------------------------------

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
        return [t for t in self.tokens.values()
                if t.user_id == user_id and t.revoked_at is None]


class FakeAccessTokenBlacklist:
    def __init__(self):
        self.blacklisted: set[str] = set()

    def blacklist_access_token(self, jti: str) -> None:
        self.blacklisted.add(jti)

    def is_access_token_blacklisted(self, jti: str) -> bool:
        return jti in self.blacklisted


# ---------------------------------------------------------------------------
#  Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def token_repo():
    return FakeRefreshTokenRepository()


@pytest.fixture
def blacklist():
    return FakeAccessTokenBlacklist()


@pytest.fixture
def jwt_issuer():
    """A real JWTTokenIssuer with fake secrets — no monkeypatching needed."""
    return JWTTokenIssuer(
        access_token_secret="test-access-secret",
        refresh_token_secret="test-refresh-secret",
    )


@pytest.fixture
def token_service(token_repo, blacklist, jwt_issuer):
    return TokenService(token_repo, blacklist, jwt_issuer)


# ---------------------------------------------------------------------------
#  get_valid_refresh_token_or_raise
# ---------------------------------------------------------------------------

def test_get_valid_refresh_token_happy_path(token_service, token_repo, jwt_issuer):
    user_id = str(uuid4())
    token_str, jti, _sub, exp = jwt_issuer.create_refresh_token(user_id)

    stored_token = RefreshToken(
        id=jti,
        user_id=user_id,
        expires_at=exp,
        revoked_at=None,
        created_at=datetime.now(timezone.utc),
    )
    token_repo.create_refresh_token(stored_token)

    result = token_service.get_valid_refresh_token_or_raise(token_str)
    assert result is stored_token


def test_get_valid_refresh_token_invalid_signature(token_service):
    with pytest.raises(NotAuthenticatedException):
        token_service.get_valid_refresh_token_or_raise("garbage-token")


def test_get_valid_refresh_token_not_in_db(token_service, token_repo, jwt_issuer):
    user_id = str(uuid4())
    token_str, _jti, _sub, _exp = jwt_issuer.create_refresh_token(user_id)
    # token decodes fine but is never stored in the repo

    with pytest.raises(NotAuthenticatedException):
        token_service.get_valid_refresh_token_or_raise(token_str)


def test_get_valid_refresh_token_revoked(token_service, token_repo, jwt_issuer):
    user_id = str(uuid4())
    token_str, jti, _sub, exp = jwt_issuer.create_refresh_token(user_id)

    stored_token = RefreshToken(
        id=jti,
        user_id=user_id,
        expires_at=exp,
        revoked_at=datetime.now(timezone.utc),  # ← already revoked
        created_at=datetime.now(timezone.utc),
    )
    token_repo.create_refresh_token(stored_token)

    with pytest.raises(NotAuthenticatedException):
        token_service.get_valid_refresh_token_or_raise(token_str)


# ---------------------------------------------------------------------------
#  generate_token_pair_for_user
# ---------------------------------------------------------------------------

def test_generate_token_pair_for_user(token_service, token_repo, jwt_issuer):
    user_id = str(uuid4())

    result = token_service.generate_token_pair_for_user(user_id, "username", "admin")

    # Both tokens should be valid JWTs
    access_payload = jwt_issuer.decode_access_token(result.access_token)
    refresh_payload = jwt_issuer.decode_refresh_token(result.refresh_token)

    assert access_payload.sub == user_id
    assert refresh_payload.sub == user_id

    # Refresh token persisted in repo
    stored = token_repo.get_refresh_token_by_id(refresh_payload.jti)
    assert stored is not None
    assert stored.user_id == user_id
    assert stored.revoked_at is None


# ---------------------------------------------------------------------------
#  rotate_token_pair
# ---------------------------------------------------------------------------

def test_rotate_token_pair_happy_path(token_service, token_repo, blacklist, jwt_issuer):
    user_id = str(uuid4())
    old_pair = token_service.generate_token_pair_for_user(user_id, "some_username", "user")
    old_jti = jwt_issuer.decode_refresh_token(old_pair.refresh_token).jti

    new_pair = token_service.rotate_token_pair(
        old_pair.refresh_token, user_id, "some_username", "user",
    )

    # Old token revoked & blacklisted
    old_token = token_repo.get_refresh_token_by_id(old_jti)
    assert old_token.revoked_at is not None
    assert blacklist.is_access_token_blacklisted(old_jti)

    # New token is active and has a different jti
    new_jti = jwt_issuer.decode_refresh_token(new_pair.refresh_token).jti
    new_token = token_repo.get_refresh_token_by_id(new_jti)
    assert new_token is not None
    assert new_token.revoked_at is None
    assert new_jti != old_jti


def test_rotate_token_pair_user_id_mismatch(token_service, token_repo, blacklist, jwt_issuer):
    real_user_id = str(uuid4())
    someone_elses_id = str(uuid4())
    pair = token_service.generate_token_pair_for_user(real_user_id, "some_username", "user")
    jti = jwt_issuer.decode_refresh_token(pair.refresh_token).jti

    with pytest.raises(NotAuthenticatedException):
        token_service.rotate_token_pair(
            pair.refresh_token, someone_elses_id, "some_username", "user",
        )

    # Nothing mutated — original token still active
    token = token_repo.get_refresh_token_by_id(jti)
    assert token.revoked_at is None
    assert not blacklist.is_access_token_blacklisted(jti)


# ---------------------------------------------------------------------------
#  revoke_token_pair / revoke_all_user_refresh_tokens
# ---------------------------------------------------------------------------

def test_revoke_token_pair(token_service, token_repo, blacklist, jwt_issuer):
    user_id = str(uuid4())
    pair = token_service.generate_token_pair_for_user(user_id, "Gordzo", "Boss")
    pair_jti = jwt_issuer.decode_refresh_token(pair.refresh_token).jti

    token_service.revoke_token_pair(pair.refresh_token)
    active_jtis = [t.id for t in token_repo.get_active_by_user(user_id)]

    assert token_repo.get_refresh_token_by_id(pair_jti).revoked_at is not None
    assert blacklist.is_access_token_blacklisted(pair_jti)
    assert pair_jti not in active_jtis


def test_revoke_all_users_refresh_token(token_service, token_repo, blacklist, jwt_issuer):
    user_id = str(uuid4())

    tokens: list[TokenPair] = [
        token_service.generate_token_pair_for_user(user_id, "Gordzo", "Boss")
        for _ in range(10)
    ]
    another_user_token = token_service.generate_token_pair_for_user(
        str(uuid4()), "a", "b",
    )

    # Revoke a couple first to check idempotency
    token_service.revoke_token_pair(tokens[0].refresh_token)
    token_service.revoke_token_pair(tokens[1].refresh_token)

    token_service.revoke_all_user_refresh_tokens(user_id)

    for token_pair in tokens:
        jti = jwt_issuer.decode_refresh_token(token_pair.refresh_token).jti
        assert token_repo.get_refresh_token_by_id(jti).revoked_at is not None
        assert blacklist.is_access_token_blacklisted(jti)

    another_jti = jwt_issuer.decode_refresh_token(another_user_token.refresh_token).jti
    assert token_repo.get_refresh_token_by_id(another_jti).revoked_at is None
    assert not blacklist.is_access_token_blacklisted(another_jti)


# ---------------------------------------------------------------------------
#  get_user_id_from_access_token_or_raise
# ---------------------------------------------------------------------------

def test_get_user_id_from_access_token_happy_path(token_service, jwt_issuer):
    user_id = str(uuid4())
    access_token = jwt_issuer.create_access_token(user_id, "u", "user")

    result = token_service.get_user_id_from_access_token_or_raise(access_token)
    assert result == user_id


def test_get_user_id_from_access_token_invalid(token_service):
    with pytest.raises(NotAuthenticatedException):
        token_service.get_user_id_from_access_token_or_raise("not-a-valid-jwt")


def test_get_user_id_from_access_token_blacklisted(token_service, blacklist, jwt_issuer):
    user_id = str(uuid4())
    access_token = jwt_issuer.create_access_token(user_id, "u", "user")
    jti = jwt_issuer.decode_access_token(access_token).jti
    blacklist.blacklist_access_token(jti)

    with pytest.raises(NotAuthenticatedException):
        token_service.get_user_id_from_access_token_or_raise(access_token)


