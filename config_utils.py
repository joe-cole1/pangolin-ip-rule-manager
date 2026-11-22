import os
from datetime import UTC, datetime


def now_utc_iso() -> str:
    """Return the current UTC timestamp as an ISO 8601 string without microseconds."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def parse_bool_env(name: str, default: bool = False) -> bool:
    """Parse a boolean environment variable using common truthy literals."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def parse_int_env(name: str, default: int, errors: list[str] | None = None) -> int:
    """Parse an integer environment variable, recording invalid values instead of raising."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        if errors is not None:
            errors.append(f"{name} must be an integer; got {raw!r}")
        return default
