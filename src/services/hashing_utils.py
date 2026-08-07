from argon2 import PasswordHasher
from typing import Protocol
from services.config import HASHING_TIME_COST


class HashingServiceProtocol(Protocol):
    def hash_password(self, password: str) -> str:
        ...

    def verify_password_hash(self, _hash: str, password: str) -> bool:
        ...

    def needs_rehash(self, _hash: str) -> bool:
        ...

    def run_some_dummy_hash(self) -> None:
        ...


class HashingService:
    def __init__(self) -> None:
        self.password_hasher = PasswordHasher(time_cost=HASHING_TIME_COST)
        self._DUMMY_HASH: str = self.password_hasher.hash("some dummy password")

    def hash_password(self, password: str) -> str:
        return self.password_hasher.hash(password=password)

    def verify_password_hash(self, _hash: str, password: str) -> bool:
        try:
            return self.password_hasher.verify(hash=_hash, password=password)
        except Exception:
            return False

    def needs_rehash(self, _hash: str) -> bool:
        return self.password_hasher.check_needs_rehash(_hash)

    def run_some_dummy_hash(self) -> None:
        self.verify_password_hash(self._DUMMY_HASH,
                                            "some dummy password")

