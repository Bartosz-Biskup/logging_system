from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from db_and_models.user import AccountState
from services.ban_service import BanService
from repos.user_repository import User
from repos.ban_repository import Ban


@pytest.fixture
def ban_service(ban_repo, user_repo):
    return BanService(ban_repo, user_repo)


def test_is_user_banned_user_not_banned(ban_service, 
                                        ban_repo, 
                                        user_repo):
    user_id = str(uuid4())
    user = User(id=user_id,
                username="Broski",
                email="some@gmail.com",
                password_hash="someHash",
                account_state=AccountState.active,
                role="user",
                created_at=datetime.now(timezone.utc))
    user_repo.create_user(user)

    is_user_banned = ban_service.is_user_banned(user_id)

    assert not is_user_banned

def test_is_user_banned_user_banned(ban_service, user_repo, ban_repo):
    user_id = str(uuid4())
    user = User(id=user_id,
                username="Broski",
                email="some@gmail.com",
                password_hash="someHash",
                account_state=AccountState.active,
                role="user",
                created_at=datetime.now(timezone.utc))
    user_repo.create_user(user)

    ban_repo.create_ban(Ban(
        id=str(uuid4()),
        user_id=user_id,
        banned_at=datetime.now(timezone.utc),
        banned_until=datetime.now(timezone.utc) + timedelta(hours=1),
        reason="User used n-word multiple times",
        banned_by=None,
        revoked_at=None
    ))

    assert ban_service.is_user_banned(user_id)

def test_is_user_banned_user_ban_expired(ban_service, user_repo, ban_repo):
    user_id = str(uuid4())
    user = User(id=user_id,
                username="Broski",
                email="some@gmail.com",
                password_hash="someHash",
                account_state=AccountState.active,
                role="user",
                created_at=datetime.now(timezone.utc))
    user_repo.create_user(user)

    ban_repo.create_ban(Ban(
        id=str(uuid4()),
        user_id=user_id,
        banned_at=datetime.now(timezone.utc) - timedelta(hours=5),
        banned_until=datetime.now(timezone.utc) - timedelta(hours=1),
        reason="User used n-word multiple times",
        banned_by=None,
        revoked_at=None
    ))

    assert not ban_service.is_user_banned(user_id)

def test_is_user_banned_user_ban_not_expired_but_revoked(ban_service, user_repo, ban_repo):
    user_id = str(uuid4())
    user = User(id=user_id,
                username="Broski",
                email="some@gmail.com",
                password_hash="someHash",
                account_state=AccountState.active,
                role="user",
                created_at=datetime.now(timezone.utc))
    user_repo.create_user(user)

    ban_repo.create_ban(Ban(
        id=str(uuid4()),
        user_id=user_id,
        banned_at=datetime.now(timezone.utc) - timedelta(hours=5),
        banned_until=datetime.now(timezone.utc) + timedelta(hours=5),
        reason="User used n-word multiple times",
        banned_by=None,
        revoked_at=datetime.now(timezone.utc)
    ))

    assert not ban_service.is_user_banned(user_id)

def test_ban_user_creates_new_ban(ban_service, user_repo, ban_repo):
    user_id = str(uuid4())
    user = User(id=user_id,
                username="Broski",
                email="some@gmail.com",
                password_hash="someHash",
                account_state=AccountState.active,
                role="user",
                created_at=datetime.now(timezone.utc))
    user_repo.create_user(user)

    banned_by = str(uuid4())
    ban_service.ban_user(user_id, banned_for_days=7, reason="Spam", banned_by=banned_by)

    bans = ban_repo.get_ban_by_user(user_id)
    assert len(bans) == 1
    assert bans[0].reason == "Spam"
    assert bans[0].banned_by == banned_by
    assert bans[0].revoked_at is None
    assert bans[0].banned_until > datetime.now(timezone.utc)


def test_ban_user_revokes_old_ban_and_creates_new(ban_service, user_repo, ban_repo):
    user_id = str(uuid4())
    user = User(id=user_id,
                username="Broski",
                email="some@gmail.com",
                password_hash="someHash",
                account_state=AccountState.active,
                role="user",
                created_at=datetime.now(timezone.utc))
    user_repo.create_user(user)

    ban_service.ban_user(user_id, banned_for_days=7, reason="First ban")
    first_ban = ban_repo.get_ban_by_user(user_id)[0]

    ban_service.ban_user(user_id, banned_for_days=14, reason="Second ban")

    assert first_ban.revoked_at is not None
    bans = ban_repo.get_ban_by_user(user_id)
    assert len(bans) == 2
    active_bans = [b for b in bans if b.revoked_at is None]
    assert len(active_bans) == 1
    assert active_bans[0].reason == "Second ban"


def test_ban_user_raises_when_user_not_found(ban_service):
    with pytest.raises(ValueError):
        ban_service.ban_user(str(uuid4()), banned_for_days=7, reason="Spam")


def test_ban_user_raises_when_banned_for_days_not_positive(ban_service, user_repo):
    user_id = str(uuid4())
    user = User(id=user_id,
                username="Broski",
                email="some@gmail.com",
                password_hash="someHash",
                account_state=AccountState.active,
                role="user",
                created_at=datetime.now(timezone.utc))
    user_repo.create_user(user)

    with pytest.raises(ValueError):
        ban_service.ban_user(user_id, banned_for_days=0, reason="Spam")

    with pytest.raises(ValueError):
        ban_service.ban_user(user_id, banned_for_days=-5, reason="Spam")


def test_unban_user_revokes_active_ban(ban_service, user_repo, ban_repo):
    user_id = str(uuid4())
    user = User(id=user_id,
                username="Broski",
                email="some@gmail.com",
                password_hash="someHash",
                account_state=AccountState.active,
                role="user",
                created_at=datetime.now(timezone.utc))
    user_repo.create_user(user)

    ban_service.ban_user(user_id, banned_for_days=7, reason="Spam")
    assert ban_service.is_user_banned(user_id)

    ban_service.unban_user(user_id)

    assert not ban_service.is_user_banned(user_id)
    bans = ban_repo.get_ban_by_user(user_id)
    assert len(bans) == 1
    assert bans[0].revoked_at is not None


def test_unban_user_raises_when_no_active_ban(ban_service, user_repo):
    user_id = str(uuid4())
    user = User(id=user_id,
                username="Broski",
                email="some@gmail.com",
                password_hash="someHash",
                account_state=AccountState.active,
                role="user",
                created_at=datetime.now(timezone.utc))
    user_repo.create_user(user)

    with pytest.raises(ValueError):
        ban_service.unban_user(user_id)

