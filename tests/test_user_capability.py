from uuid import uuid4
import pytest
from datetime import datetime, timezone, timedelta
from services.user_capability_checker_service import UserCapabilityCheckerService
from services.ban_service import BanService
from services.exceptions import NotAuthenticatedException
from repos.user_repository import User, AccountState
from repos.ban_repository import Ban


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