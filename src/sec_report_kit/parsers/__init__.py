"""Input format parsers."""


def detect_source_type(data: dict | list) -> str:
    """Detect whether *data* came from Trivy, pip-audit, Bandit, or Gitleaks.

    Returns ``"trivy"``, ``"pip-audit"``, ``"bandit"``, or ``"gitleaks"``.
    Raises ``ValueError`` if the format cannot be recognised.
    """
    if isinstance(data, list):
        # Gitleaks commonly emits a top-level JSON array of findings.
        if all(isinstance(item, dict) for item in data):
            sample = data[0] if data else {}
            if isinstance(sample, dict) and (
                "RuleID" in sample
                or "Description" in sample
                or "File" in sample
                or "StartLine" in sample
                or "Fingerprint" in sample
            ):
                return "gitleaks"

    if isinstance(data, dict):
        if "Results" in data:
            return "trivy"
        if "results" in data and isinstance(data.get("results"), list):
            return "bandit"
        if "findings" in data and isinstance(data.get("findings"), list):
            return "gitleaks"
        if "dependencies" in data or "vulnerabilities" in data:
            return "pip-audit"
    raise ValueError(
        "Cannot detect source type: JSON does not match any known format "
        "(expected 'Results' for Trivy, 'dependencies'/'vulnerabilities' for pip-audit, "
        "'results' for Bandit, or top-level array/'findings' for Gitleaks)."
    )
