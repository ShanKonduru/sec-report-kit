from __future__ import annotations

import argparse
from pathlib import Path

from sec_report_kit.cli import render_consolidated


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a consolidated HTML security report from scanner JSON/SARIF files"
    )
    parser.add_argument("--input", required=True, help="Input folder containing report files")
    parser.add_argument("--output", required=True, help="Output folder for generated HTML")
    parser.add_argument("--target", default="consolidated-scan", help="Target label used in HTML report")
    parser.add_argument(
        "--modified-since",
        help="Only include files modified on or after this time. Accepts ISO date/datetime or: today, yesterday, last-week, last-7-days",
    )
    parser.add_argument(
        "--modified-until",
        help="Only include files modified on or before this time. Accepts ISO date/datetime, today, or yesterday. Combine with --modified-since for a date range.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Maximum number of most recently modified report files to include after filtering",
    )
    args = parser.parse_args()

    render_consolidated(
        input=Path(args.input),
        output=Path(args.output),
        target=args.target,
        modified_since=args.modified_since,
        modified_until=args.modified_until,
        limit=args.limit,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
