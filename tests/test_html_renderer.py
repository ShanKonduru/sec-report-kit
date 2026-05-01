from sec_report_kit.models import Finding
from sec_report_kit.report.html_renderer import render_html_report


EMPTY_COUNTS = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}


def _finding(severity="HIGH", primary_url="https://example.com"):
    return Finding(
        source_type="test",
        target="myimage:1",
        severity=severity,
        vulnerability_id="CVE-2024-0001",
        package="openssl",
        installed_version="1.0",
        fixed_version="1.1",
        title="Test vuln",
        primary_url=primary_url,
    )


def test_render_html_with_finding_with_url():
    counts = {**EMPTY_COUNTS, "HIGH": 1}
    html = render_html_report(
        target_ref="myimage:1",
        source_label="trivy",
        findings=[_finding(primary_url="https://example.com")],
        counts=counts,
    )
    assert "CVE-2024-0001" in html
    assert "https://example.com" in html
    assert "openssl" in html


def test_render_html_with_finding_no_url():
    counts = {**EMPTY_COUNTS, "HIGH": 1}
    html = render_html_report(
        target_ref="myimage:1",
        source_label="trivy",
        findings=[_finding(primary_url="")],
        counts=counts,
    )
    assert "CVE-2024-0001" in html
    # no anchor tag when url is empty
    assert 'href=""' not in html


def test_render_html_no_findings():
    html = render_html_report(
        target_ref="myimage:1",
        source_label="trivy",
        findings=[],
        counts=EMPTY_COUNTS,
    )
    assert "No vulnerabilities found" in html


def test_render_html_escapes_special_chars():
    finding = Finding(
        source_type="test",
        target='target<script>alert(1)</script>',
        severity="LOW",
        vulnerability_id="CVE-X",
        package='pkg"quoted"',
        installed_version="1.0",
        fixed_version="-",
        title="<b>bold</b>",
        primary_url="",
    )
    counts = {**EMPTY_COUNTS, "LOW": 1}
    html = render_html_report(
        target_ref="ref",
        source_label="test",
        findings=[finding],
        counts=counts,
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
