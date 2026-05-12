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
        if "runs" in data and isinstance(data.get("runs"), list):
            return "codeql"
        if "results" in data and isinstance(data.get("results"), list):
            if "errors" in data or "paths" in data or "version" in data:
                return "semgrep"
            return "bandit"
        if "findings" in data and isinstance(data.get("findings"), list):
            return "gitleaks"
        if "results" in data and isinstance(data.get("results"), dict):
            return "checkov"
        if "dependencies" in data or "vulnerabilities" in data:
            return "pip-audit"
    raise ValueError(
        "Cannot detect source type: JSON does not match any known format "
        "(expected 'Results' for Trivy, 'runs' for CodeQL SARIF, 'dependencies'/'vulnerabilities' for pip-audit, 'errors'/'paths'/'version' with 'results' for Semgrep, "
        "'results' (list) for Bandit, 'results' (dict) for Checkov, or top-level array/'findings' for Gitleaks)."
    )
