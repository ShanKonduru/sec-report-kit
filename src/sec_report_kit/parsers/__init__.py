"""Input format parsers."""


def detect_source_type(data: dict) -> str:
    """Detect whether *data* came from Trivy or pip-audit.

    Returns ``"trivy"`` or ``"pip-audit"``.
    Raises ``ValueError`` if the format cannot be recognised.
    """
    if isinstance(data, dict):
        if "Results" in data:
            return "trivy"
        if "dependencies" in data or "vulnerabilities" in data:
            return "pip-audit"
    raise ValueError(
        "Cannot detect source type: JSON does not match any known format "
        "(expected 'Results' for Trivy or 'dependencies'/'vulnerabilities' for pip-audit)."
    )
