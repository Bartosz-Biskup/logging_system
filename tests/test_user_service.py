import pytest
from datetime import datetime, timezone
from uuid import uuid4

from services.user_service import UserService
from repos.user_repository import User, AccountState
from services.exceptions import (InvalidPasswordException, 
                                 UserAlreadyRegisteredException)


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


@pytest.fixture
def user_repo():
    return FakeUserRepository()


@pytest.fixture
def user_service(user_repo):
    return UserService(user_repo)


def test_register_user_creates_and_returns_user(user_service, user_repo):
    new_user = user_service.register_user("Bartosz", 
                                          "bartosz@gmail.com", 
                                          "SomePassword1!")

    assert user_repo.get_user_by_username("Bartosz") == new_user != None


def test_register_user_password_is_hashed(user_service, user_repo, mocker):
    mock_hash = mocker.patch("services.hashing_utils.HashingService.hash_password",
                 return_value="some_hash")
    new_user = user_service.register_user("Bartosz", 
                                              "bartosz@gmail.com", 
                                              "SomePassword1!")

    mock_hash.assert_called_once_with("SomePassword1!")
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
