import pytest
from repos.user_repository import User
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

    def create_ban(self, ban: Ban) -> None:
        if ban.id in self.bans:
            raise ValueError(f"Ban {ban.id} already exists")
        self.bans[ban.id] = ban

    def update_ban(self, ban: Ban) -> None:
        if ban.id not in self.bans:
            raise ValueError(f"Ban {ban.id} not found")
        self.bans[ban.id] = ban

    def get_ban_by_id(self, ban_id: str) -> Ban | None:
        return self.bans.get(ban_id)

    def get_ban_by_user(self, user_id: str) -> list[Ban]:
        return [b for b in self.bans.values() if b.user_id == user_id]


@pytest.fixture
def user_repo():
    return FakeUserRepository()


@pytest.fixture
def ban_repo():
    return FakeBanRepository()
