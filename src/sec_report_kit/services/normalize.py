from __future__ import annotations

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}


def normalize_severity(value: str | None) -> str:
    if not value:
        return "UNKNOWN"
    upper = value.upper()
    return upper if upper in SEVERITY_ORDER else "UNKNOWN"
