"""Input format parsers."""


def detect_source_type(data: dict | list) -> str:
    """Detect whether *data* came from one of the supported scanners.

    Returns one of:
    ``"trivy"``, ``"pip-audit"``, ``"bandit"``, ``"gitleaks"``,
    ``"semgrep"``, ``"codeql"``, ``"osv-scanner"``, ``"checkov"``,
    ``"tfsec"``, or ``"trufflehog"``.
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
            if isinstance(sample, dict) and (
                "DetectorName" in sample
                or "DetectorType" in sample
                or "SourceName" in sample
            ):
                return "trufflehog"

    if isinstance(data, dict):
        if "Results" in data:
            return "trivy"
        if "runs" in data and isinstance(data.get("runs"), list):
            return "codeql"
        if "dependencies" in data or "vulnerabilities" in data:
            return "pip-audit"
        if "results" in data and isinstance(data.get("results"), dict):
            return "checkov"
        if "results" in data and isinstance(data.get("results"), list):
            sample = data["results"][0] if data["results"] else {}
            if isinstance(sample, dict) and "packages" in sample:
                return "osv-scanner"
            if isinstance(sample, dict) and (
                "DetectorName" in sample
                or "DetectorType" in sample
                or "SourceName" in sample
            ):
                return "trufflehog"
        if "results" in data and isinstance(data.get("results"), list):
            if "errors" in data or "paths" in data or "version" in data:
                return "semgrep"
            if all(isinstance(item, dict) and "rule_id" in item for item in data.get("results", [])):
                return "tfsec"
            return "bandit"
        if "findings" in data and isinstance(data.get("findings"), list):
            return "gitleaks"
    raise ValueError(
        "Cannot detect source type: JSON does not match any known format "
        "(expected supported scanner output such as Trivy, pip-audit, Bandit, "
        "Gitleaks, Semgrep, CodeQL SARIF, OSV-Scanner, Checkov, tfsec, or TruffleHog)."
    )
