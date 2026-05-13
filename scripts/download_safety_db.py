"""
Download the Safety CLI vulnerability database (schema 2.0.0) for offline use.

Usage:
    python scripts/download_safety_db.py [--output-dir .tools/safety-db] [--no-verify-ssl]

The script downloads insecure.json (and optionally insecure_full.json) from the
Safety free open mirror and saves them to a local directory that can be passed
to `safety check --db <dir>` for offline scanning.
"""
import argparse
import json
import ssl
import sys
import urllib.request
from pathlib import Path

OPEN_MIRROR = "https://pyup.io/aws/safety/free/2.0.0/"
SCHEMA_VERSION = "2.0.0"
DB_FILES = ["insecure.json", "insecure_full.json"]


def _make_ssl_context(verify: bool) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
        # Try to load certifi certs if available (helps in corporate environments)
        try:
            import certifi  # type: ignore[import]
            ctx = ssl.create_default_context(cafile=certifi.where())
        except ImportError:
            pass
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def download_db(output_dir: str = ".tools/safety-db", full: bool = False, verify_ssl: bool = True) -> int:
    """
    Download Safety vulnerability DB files to *output_dir*.

    Returns 0 on success, 1 on failure.
    """
    dest = Path(output_dir)
    dest.mkdir(parents=True, exist_ok=True)

    files_to_download = DB_FILES if full else [DB_FILES[0]]

    headers = {
        "schema-version": SCHEMA_VERSION,
        "ecosystem": "python",
        "User-Agent": "sec-report-kit/1.0 safety-db-downloader",
    }

    ssl_ctx = _make_ssl_context(verify_ssl)
    if not verify_ssl:
        import warnings
        warnings.warn("SSL certificate verification is disabled.", UserWarning, stacklevel=2)

    success = True
    for db_file in files_to_download:
        url = OPEN_MIRROR + db_file
        dest_file = dest / db_file
        print(f"Downloading {url} ...", end=" ", flush=True)
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as response:
                raw = response.read()

            # Validate JSON and schema version
            data = json.loads(raw)
            schema = (data.get("meta") or {}).get("schema_version", "unknown")
            if schema != SCHEMA_VERSION:
                print(f"FAIL (unexpected schema version: {schema})")
                success = False
                continue

            dest_file.write_bytes(raw)
            size_kb = len(raw) // 1024
            print(f"OK ({size_kb} KB, schema {schema})")

        except Exception as exc:
            print(f"FAIL ({exc})")
            success = False

    if success:
        print(f"\nSafety DB saved to: {dest.resolve()}")
        print(f"Use it with: safety check --db \"{dest.resolve()}\"")
    else:
        print("\nOne or more files failed to download.", file=sys.stderr)
        if verify_ssl:
            print(
                "If you are behind a corporate proxy, try adding --no-verify-ssl",
                file=sys.stderr,
            )

    return 0 if success else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download Safety CLI vulnerability DB for offline use."
    )
    parser.add_argument(
        "--output-dir",
        default=".tools/safety-db",
        help="Directory to save DB files (default: .tools/safety-db)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Also download insecure_full.json (larger, includes CVE descriptions)",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification (use in corporate/proxy environments)",
    )
    args = parser.parse_args()
    return download_db(output_dir=args.output_dir, full=args.full, verify_ssl=not args.no_verify_ssl)


if __name__ == "__main__":
    sys.exit(main())
