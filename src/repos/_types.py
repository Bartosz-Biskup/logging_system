from datetime import datetime, timezone
from typing import Annotated
from pydantic import BeforeValidator


def _ensure_utc(value: datetime | None) -> datetime | None:
    """Replace tzinfo with UTC on every datetime that comes in."""
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc)


# Reusable type aliases — annotate datetime fields with these
# instead of writing a @field_validator in every model.
UTCDateTime = Annotated[datetime, BeforeValidator(_ensure_utc)]
UTCDateTimeOrNone = Annotated[datetime | None, BeforeValidator(_ensure_utc)]
