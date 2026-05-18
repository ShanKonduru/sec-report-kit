"""Input format parsers."""


def detect_source_type(data: dict | list) -> str:
    """Detect whether *data* came from one of the supported scanners.

    Returns one of:
    ``"trivy"``, ``"pip-audit"``, ``"bandit"``, ``"gitleaks"``,
    ``"semgrep"``, ``"codeql"``, ``"osv-scanner"``, ``"checkov"``,
    ``"tfsec"``, ``"trufflehog"``, or ``"safety"``.
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
        if "vulnerabilities" in data and isinstance(data.get("vulnerabilities"), list):
            sample = data["vulnerabilities"][0] if data["vulnerabilities"] else {}
            if "report_meta" in data or "scanned_packages" in data:
                return "safety"
            if isinstance(sample, dict) and (
                "package_name" in sample
                or "analyzed_version" in sample
                or "vulnerability_id" in sample
                or "more_info_url" in sample
                or "CVE" in sample
            ):
                return "safety"
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
            sample = data["results"][0] if data["results"] else {}
            if isinstance(sample, dict) and (
                "check_id" in sample
                or (
                    "extra" in sample
                    and isinstance(sample.get("extra"), dict)
                    and ("severity" in sample["extra"] or "message" in sample["extra"])
                )
            ):
                return "semgrep"
            if all(isinstance(item, dict) and "rule_id" in item for item in data.get("results", [])):
                return "tfsec"
            if isinstance(sample, dict) and (
                "issue_severity" in sample
                or "issue_text" in sample
                or "test_id" in sample
                or "test_name" in sample
            ):
                return "bandit"
            return "bandit"
        if "findings" in data and isinstance(data.get("findings"), list):
            return "gitleaks"
    raise ValueError(  # pragma: no cover
        "Cannot detect source type: JSON does not match any known format "
        "(expected supported scanner output such as Trivy, pip-audit, Bandit, "
        "Gitleaks, Semgrep, CodeQL SARIF, OSV-Scanner, Checkov, tfsec, TruffleHog, or Safety)."
    )
