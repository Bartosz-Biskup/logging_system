from argon2 import PasswordHasher
from services.config import HASHING_TIME_COST


class HashingService:
    password_hasher = PasswordHasher(time_cost=HASHING_TIME_COST)
    _DUMMY_HASH: str = password_hasher.hash("some dummy password")

    @classmethod
    def hash_password(cls, password: str) -> str:
        return cls.password_hasher.hash(password=password)

    @classmethod
    def verify_password_hash(cls, _hash: str, password: str) -> bool:
        try:
            return cls.password_hasher.verify(hash=_hash, password=password)
        except Exception:
            return False

    @classmethod
    def needs_rehash(cls, _hash: str) -> bool:
        return cls.password_hasher.check_needs_rehash(_hash)

    @classmethod
    def run_some_dummy_hash(cls) -> None:
        HashingService.verify_password_hash(cls._DUMMY_HASH,
                                            "some dummy password")
