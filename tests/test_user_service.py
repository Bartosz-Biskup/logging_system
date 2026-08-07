import pytest
from datetime import datetime, timezone
from uuid import uuid4

from services.user_service import UserService
from services.hashing_utils import HashingService
from repos.user_repository import User, AccountState
from services.exceptions import (InvalidPasswordException, 
                                 UserAlreadyRegisteredException,
                                 UserNotFoundException)


@pytest.fixture
def hashing_service():
    return HashingService()


@pytest.fixture
def user_service(user_repo, hashing_service):
    return UserService(user_repo, hashing_service)


def test_register_user_creates_and_returns_user(user_service, user_repo):
    new_user = user_service.register_user("Bartosz", 
                                          "bartosz@gmail.com", 
                                          "SomePassword1!")

    assert user_repo.get_user_by_username("Bartosz") == new_user != None


def test_register_user_password_is_hashed(user_service, user_repo, hashing_service):
    # Patch the instance, not the class
    hashing_service.hash_password = lambda pw: "some_hash"
    new_user = user_service.register_user("Bartosz", 
                                              "bartosz@gmail.com", 
                                              "SomePassword1!")

    assert user_repo.get_user_by_username("Bartosz").password_hash == "some_hash"


def test_register_user_raises_when_password_invalid(user_service, user_repo, mocker):
    mocker.patch("services.user_service.is_password_valid", return_value=False)
    with pytest.raises(InvalidPasswordException):
        new_user = user_service.register_user("Bartosz", 
                                                      "bartosz@gmail.com", 
                                                      "SomePassword1!")


def test_register_user_raises_when_username_taken(user_service, user_repo):
    user_service.register_user("Bartosz",
                               "someemail@gmail.com",
                               "SomePassword1!")

    with pytest.raises(UserAlreadyRegisteredException):
        new_user = user_service.register_user("Bartosz", 
                                            "bartosz@gmail.com", 
                                            "SomePassword1!")


def test_register_user_raises_when_email_taken(user_service, user_repo):
    user_service.register_user("Bartosz",
                                   "bartosz@gmail.com",
                                   "SomePassword1!")
    
    with pytest.raises(UserAlreadyRegisteredException):
        new_user = user_service.register_user("Bartosz2", 
                                            "bartosz@gmail.com", 
                                            "SomePassword1!")


def test_register_user_sets_account_state_to_active(user_service, user_repo):
    user_service.register_user("Bartosz",
                                       "bartosz@gmail.com",
                                       "SomePassword1!")

    assert user_repo.get_user_by_username("Bartosz").account_state == AccountState.active

def test_register_user_sets_default_role_to_user(user_service, user_repo):
    user_service.register_user("Bartosz",
                                           "bartosz@gmail.com",
                                           "SomePassword1!")
    
    assert user_repo.get_user_by_username("Bartosz").role == "user"

def test_update_email_happy_path(user_service, user_repo):
    user_id: str = str(uuid4())
    user: User = User(
        id=user_id,
        username="Broski",
        email="example@gmail.com",
        password_hash="SomeHash",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc)
    )
    user_repo.create_user(user)

    user_service.update_email(user_id, "example2@gmail.com")

    assert user_repo.get_user_by_id(user_id).email == "example2@gmail.com"
    assert user_repo.get_user_by_email("example2@gmail.com") is not None

def test_update_email_raises_email_taken(user_service, user_repo):
    user_id: str = str(uuid4())
    user: User = User(
        id=user_id,
        username="Broski",
        email="example@gmail.com",
        password_hash="SomeHash",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc)
    )
    user_repo.create_user(user)

    user_id2: str = str(uuid4())
    user: User = User(
        id=user_id2,
        username="Broski",
        email="example2@gmail.com",
        password_hash="SomeHash",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc)
    )
    user_repo.create_user(user)

    with pytest.raises(UserAlreadyRegisteredException):
        user_service.update_email(user_id2, "example@gmail.com")

    assert user_repo.get_user_by_email("example@gmail.com").id == user_id


def test_update_email_raises_when_email_taken_case_insensitive(user_service, user_repo):
    user_id: str = str(uuid4())
    user: User = User(
        id=user_id,
        username="Broski",
        email="example@gmail.com",
        password_hash="SomeHash",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc)
    )
    user_repo.create_user(user)

    user_id2: str = str(uuid4())
    user: User = User(
        id=user_id2,
        username="Broski",
        email="example2@gmail.com",
        password_hash="SomeHash",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc)
    )
    user_repo.create_user(user)

    with pytest.raises(UserAlreadyRegisteredException):
        user_service.update_email(user_id2, "EXAMPLE@Gmail.com")

    assert user_repo.get_user_by_email("example@gmail.com").id == user_id

def test_update_username_happy_path(user_service, user_repo):
    user_id: str = str(uuid4())
    user: User = User(
        id=user_id,
        username="Broski",
        email="example@gmail.com",
        password_hash="SomeHash",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc)
    )
    user_repo.create_user(user)

    user_service.update_username(user_id, "Broski2")

    assert user_repo.get_user_by_id(user_id).username == "Broski2"
    assert user_repo.get_user_by_username("Broski2") is not None

def test_update_username_raises_username_taken(user_service, user_repo):
    user_id: str = str(uuid4())
    user: User = User(
        id=user_id,
        username="Broski",
        email="example@gmail.com",
        password_hash="SomeHash",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc)
    )
    user_repo.create_user(user)

    user_id2: str = str(uuid4())
    user: User = User(
        id=user_id2,
        username="Broski2",
        email="example2@gmail.com",
        password_hash="SomeHash",
        account_state=AccountState.active,
        role="user",
        created_at=datetime.now(timezone.utc)
    )
    user_repo.create_user(user)

    with pytest.raises(UserAlreadyRegisteredException):
        user_service.update_username(user_id2, "Broski")

    assert user_repo.get_user_by_username("Broski").id == user_id


def test_update_email_raises_when_user_not_found(user_service):
    with pytest.raises(UserNotFoundException):
        user_service.update_email(str(uuid4()), "anything@gmail.com")


def test_update_username_raises_when_user_not_found(user_service):
    with pytest.raises(UserNotFoundException):
        user_service.update_username(str(uuid4()), "Anything")

