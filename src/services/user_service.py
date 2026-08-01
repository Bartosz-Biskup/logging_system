from time import timezone
from typing import Protocol
from uuid import uuid4
from datetime import datetime, timezone
from repos.user_repository import User, AccountState, UserRepositoryProtocol
from services.exceptions import (InvalidPasswordException,
                                 UserAlreadyRegisteredException,
                                 UserNotFoundException)
from services.hashing_utils import HashingService
from services.password_validator import is_password_valid
from repos.user_repository import UserRepositoryProtocol


class UserServiceProtocol(Protocol):
    def register_user(self,
                      username: str,
                      email: str,
                      password: str) -> User:
        ...

    def update_email(self, user_id: str, new_email: str) -> User:
        ...
    
    def update_username(self, user_id: str, new_username: str) -> User:
        ...


class UserService:
    def __init__(self, 
                 user_repo: UserRepositoryProtocol) -> None:
        self._user_repo = user_repo

    def register_user(self,
                          username: str,
                          email: str,
                          password: str) -> User:
        if self._user_repo.get_user_by_username(username) is not None:
            raise UserAlreadyRegisteredException("User with this nickname is already registered")

        if self._user_repo.get_user_by_email(email) is not None:
            raise UserAlreadyRegisteredException("User with this nickname is already registered")

        if not is_password_valid(password):
            raise InvalidPasswordException()

        new_user: User = User(id=str(uuid4()),
                              username=username,
                              email=email,
                              password_hash=HashingService.hash_password(password),
                              account_state=AccountState.active,
                              role="user",
                              created_at=datetime.now(timezone.utc))
        self._user_repo.create_user(new_user)

        return new_user

    def update_email(self, user_id: str, new_email: str) -> User:
        user: User | None = self._user_repo.get_user_by_id(user_id)
        if user is None:
            raise UserNotFoundException()

        user_by_email: User | None = self._user_repo.get_user_by_email(new_email)
        if user_by_email is not None and user_by_email.id != user.id:
            raise UserAlreadyRegisteredException()

        user.email = new_email.lower()
        self._user_repo.update_user(user)

    
    def update_username(self, user_id: str, new_username: str) -> User:
        user: User | None = self._user_repo.get_user_by_id(user_id)
        if user is None:
            raise UserNotFoundException()

        user_by_username: User | None = self._user_repo.get_user_by_username(new_username)
        if user_by_username is not None and user_by_username.id != user.id:
            raise UserAlreadyRegisteredException()

        user.username = new_username
        self._user_repo.update_user(user)