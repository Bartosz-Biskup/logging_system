from typing import Final


# jwt tokens
JWT_TOKEN_ISSUER: Final[str] = "5012accounts"
ACCESS_TOKEN_EXP_TIME_MINUTES: Final[int] = 5
REFRESH_TOKEN_EXP_TIME_DAYS: Final[int] = 14
TOKEN_AUD: Final[str] = "5012_logging_system"

# hashing
HASHING_TIME_COST: Final[int] = 3

# password resetting
PASSWORD_RESET_REQUEST_EXPIRATION_TIME_HOURS: Final[int] = 1
PASSWORD_RESET_REQUEST_DELAY_HOURS: Final[int] = 24

# smtp
SMTP_HOST: Final[str] = ""
SMTP_PORT: Final[int] = 587
SMTP_EMAIL: Final[str] = ""

# passwords
MIN_PASSWORD_LENGTH: Final[int] = 8
MAX_PASSWORD_LENGTH: Final[int] = 255
REQUIRE_SPECIAL_CHARACTER: Final[bool] = True