import string
from services.config import (MIN_PASSWORD_LENGTH, 
                            MAX_PASSWORD_LENGTH,
                            REQUIRE_SPECIAL_CHARACTER)

LOWERCASE = string.ascii_lowercase 
UPPERCASE = string.ascii_uppercase   
DIGITS    = string.digits             
SPECIAL   = "!@#$%^&*()-_=+[]{};:,.<>?/|~`"

ALL_ALLOWED = LOWERCASE + UPPERCASE + DIGITS + SPECIAL


def is_password_valid(password: str) -> bool:
    if not (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH):
        return False

    if not all(character in ALL_ALLOWED for character in password):
        return False

    if not any(character in LOWERCASE for character in password):
        return False

    if not any(character in UPPERCASE for character in password):
        return False

    if not any(character in DIGITS for character in password):
        return False

    if REQUIRE_SPECIAL_CHARACTER:
         if not any(character in SPECIAL for character in password):
            return False

    return True