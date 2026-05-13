#!/usr/bin/env python3
"""Install external scanner CLIs into .tools/bin from GitHub releases."""

from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import urllib.error
import urllib.request
import zipfile


def detect_platform() -> str:
    if os.name == "nt":
        return "windows"
    if os.uname().sysname.lower() == "darwin":
        return "darwin"
    return "linux"


def github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "sec-report-kit-installer",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


class RateLimitError(RuntimeError):
    """Raised when the GitHub API rate limit is exceeded."""


def fetch_latest_release(repo: str) -> dict:
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest", headers=github_headers())
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        # Detect rate limit via body, reason phrase, or the exception string itself.
        combined = " ".join([body, str(exc.reason or ""), str(exc)]).lower()
        if exc.code == 403 and ("rate limit" in combined or "rate limit exceeded" in combined or "x-ratelimit" in combined):
            raise RateLimitError(
                "GitHub API rate limit exceeded. "
                "Set GITHUB_TOKEN (or GH_TOKEN) env var to authenticate and increase limits.\n"
                "  PowerShell:  $env:GITHUB_TOKEN='<your_token>'\n"
                "  bash:        export GITHUB_TOKEN='<your_token>'\n"
                "Then re-run: scripts\\install_external_clis.py --repo-root ."
            ) from exc
        if exc.code == 403:
            # Generic 403 - treat as rate limit too since unauthenticated calls are most common cause.
            raise RateLimitError(
                f"GitHub API returned 403 for {repo}. This is usually a rate limit on unauthenticated requests.\n"
                "Set GITHUB_TOKEN (or GH_TOKEN) env var to authenticate and increase limits.\n"
                "  PowerShell:  $env:GITHUB_TOKEN='<your_token>'\n"
                "  bash:        export GITHUB_TOKEN='<your_token>'"
            ) from exc
        raise RuntimeError(f"Failed to fetch latest release for {repo}: HTTP {exc.code}") from exc


def pick_asset(assets: list[dict], patterns: list[str]) -> dict:
    for pattern in patterns:
        regex = re.compile(pattern)
        for asset in assets:
            name = asset.get("name", "")
            if regex.search(name):
                return asset
    raise RuntimeError(f"No matching release asset found for patterns: {patterns}")


def download_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers=github_headers())
    with urllib.request.urlopen(req, timeout=300) as resp:
        return resp.read()


def ensure_executable(path: Path) -> None:
    if os.name == "nt":
        return
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def extract_binary_from_archive(data: bytes, archive_name: str, binary_names: list[str], dest: Path) -> None:
    lower_name = archive_name.lower()
    candidates = set(binary_names)

    if lower_name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                base = Path(name).name
                if base in candidates:
                    with zf.open(name) as src, open(dest, "wb") as out:
                        shutil.copyfileobj(src, out)
                    ensure_executable(dest)
                    return
    elif lower_name.endswith(".tar.gz") or lower_name.endswith(".tgz"):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                base = Path(member.name).name
                if base in candidates:
                    src = tf.extractfile(member)
                    if src is None:
                        continue
                    with src, open(dest, "wb") as out:
                        shutil.copyfileobj(src, out)
                    ensure_executable(dest)
                    return
    raise RuntimeError(f"Could not find expected binary in archive: {archive_name}")


def install_codeql(asset_data: bytes, asset_name: str, tools_bin: Path) -> None:
    target_dir = tools_bin / "codeql"
    if target_dir.exists():
        shutil.rmtree(target_dir)

    if asset_name.lower().endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(asset_data)) as zf:
            zf.extractall(tools_bin)
    elif asset_name.lower().endswith(".tar.gz") or asset_name.lower().endswith(".tgz"):
        with tarfile.open(fileobj=io.BytesIO(asset_data), mode="r:gz") as tf:
            tf.extractall(tools_bin)
    else:
        raise RuntimeError(f"Unsupported codeql archive format: {asset_name}")

    if not target_dir.exists():
        raise RuntimeError("CodeQL extraction failed: missing .tools/bin/codeql directory")

    codeql_bin = target_dir / ("codeql.exe" if os.name == "nt" else "codeql")
    if codeql_bin.exists():
        ensure_executable(codeql_bin)


def install_tool(tool_name: str, repo: str, patterns: list[str], tools_bin: Path, binary_names: list[str], dest_name: str) -> None:
    release = fetch_latest_release(repo)
    asset = pick_asset(release.get("assets", []), patterns)
    asset_name = asset["name"]
    download_url = asset["browser_download_url"]
    print(f"Installing {tool_name} from {repo} release {release.get('tag_name', 'latest')} ({asset_name})")
    data = download_bytes(download_url)

    if tool_name == "codeql":
        install_codeql(data, asset_name, tools_bin)
        return

    dest = tools_bin / dest_name
    lower_name = asset_name.lower()
    if lower_name.endswith(".zip") or lower_name.endswith(".tar.gz") or lower_name.endswith(".tgz"):
        extract_binary_from_archive(data, asset_name, binary_names, dest)
    else:
        with open(dest, "wb") as f:
            f.write(data)
        ensure_executable(dest)


def has_installed_tool(tool_name: str, tools_bin: Path, dest_name: str) -> bool:
    if tool_name == "codeql":
        candidate = tools_bin / "codeql" / ("codeql.exe" if os.name == "nt" else "codeql")
        return candidate.exists()
    return (tools_bin / dest_name).exists()


def main() -> int:
    parser = argparse.ArgumentParser(description="Install external scanner CLIs into .tools/bin")
    parser.add_argument("--repo-root", required=True, help="Repository root path")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    tools_bin = repo_root / ".tools" / "bin"
    tools_bin.mkdir(parents=True, exist_ok=True)

    platform_name = detect_platform()
    ext = ".exe" if platform_name == "windows" else ""

    tool_matrix: dict[str, dict[str, object]] = {
        "codeql": {
            "repo": "github/codeql-action",
            "patterns": {
                "windows": [r"codeql-bundle-win64\.tar\.gz$", r"codeql-bundle-win64\.zip$"],
                "linux": [r"codeql-bundle-linux64\\.tar\\.gz$"],
                "darwin": [r"codeql-bundle-osx64\\.tar\\.gz$", r"codeql-bundle-osx64\\.zip$"],
            },
            "binary_names": [f"codeql{ext}"],
            "dest_name": f"codeql{ext}",
        },
        "tfsec": {
            "repo": "aquasecurity/tfsec",
            "patterns": {
                "windows": [r"tfsec-windows-amd64(?:\\.exe)?$"],
                "linux": [r"tfsec-linux-amd64$"],
                "darwin": [r"tfsec-darwin-amd64$", r"tfsec-darwin-arm64$"],
            },
            "binary_names": [f"tfsec{ext}"],
            "dest_name": f"tfsec{ext}",
        },
        "gitleaks": {
            "repo": "gitleaks/gitleaks",
            "patterns": {
                "windows": [r"gitleaks_.*_windows_x64\\.zip$"],
                "linux": [r"gitleaks_.*_linux_x64\\.tar\\.gz$"],
                "darwin": [r"gitleaks_.*_darwin_arm64\\.tar\\.gz$", r"gitleaks_.*_darwin_x64\\.tar\\.gz$"],
            },
            "binary_names": [f"gitleaks{ext}"],
            "dest_name": f"gitleaks{ext}",
        },
        "trufflehog": {
            "repo": "trufflesecurity/trufflehog",
            "patterns": {
                "windows": [r"trufflehog_.*_windows_amd64\\.tar\\.gz$", r"trufflehog_.*_windows_amd64\\.zip$"],
                "linux": [r"trufflehog_.*_linux_amd64\\.tar\\.gz$"],
                "darwin": [r"trufflehog_.*_darwin_arm64\\.tar\\.gz$", r"trufflehog_.*_darwin_amd64\\.tar\\.gz$"],
            },
            "binary_names": [f"trufflehog{ext}"],
            "dest_name": f"trufflehog{ext}",
        },
        "osv-scanner": {
            "repo": "google/osv-scanner",
            "patterns": {
                "windows": [r"osv-scanner_windows_amd64(?:\\.exe)?(?:\\.zip)?$", r"osv-scanner_.*_windows_amd64(?:\\.exe)?(?:\\.zip)?$", r"osv-scanner-windows-amd64(?:\\.exe)?$"],
                "linux": [r"osv-scanner_.*_linux_amd64(?:\\.tar\\.gz)?$", r"osv-scanner-linux-amd64$"],
                "darwin": [r"osv-scanner_.*_darwin_amd64(?:\\.tar\\.gz)?$", r"osv-scanner_.*_darwin_arm64(?:\\.tar\\.gz)?$"],
            },
            "binary_names": [f"osv-scanner{ext}"],
            "dest_name": f"osv-scanner{ext}",
        },
    }

    failures: list[str] = []
    rate_limited = False

    for tool_name, cfg in tool_matrix.items():
        patterns = cfg["patterns"][platform_name]
        try:
            install_tool(
                tool_name=tool_name,
                repo=cfg["repo"],
                patterns=patterns,
                tools_bin=tools_bin,
                binary_names=cfg["binary_names"],
                dest_name=cfg["dest_name"],
            )
        except RateLimitError as exc:
            rate_limited = True
            if has_installed_tool(tool_name, tools_bin, cfg["dest_name"]):
                print(f"Warning: could not update {tool_name} (rate limited); keeping existing install.")
                continue
            failures.append(f"{tool_name}: {exc}")
        except Exception as exc:
            if has_installed_tool(tool_name, tools_bin, cfg["dest_name"]):
                print(f"Warning: failed to update {tool_name}: {exc}")
                print(f"Continuing with existing local install for {tool_name}.")
                continue
            failures.append(f"{tool_name}: {exc}")

    if failures:
        print("\nFailed to install the following external scanner CLIs:")
        for item in failures:
            print(f"  - {item}")
        if rate_limited:
            print("\nTip: set GITHUB_TOKEN (or GH_TOKEN) env var to avoid GitHub API rate limits,")
            print("     then re-run: scripts\\install_external_clis.py --repo-root .")
            return 2  # Special exit code: rate limit (caller can treat as warning)
        return 1

    print("Installed external CLIs into .tools/bin")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
