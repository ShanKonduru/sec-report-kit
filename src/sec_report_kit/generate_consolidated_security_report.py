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
    args = parser.parse_args()

    render_consolidated(
        input=Path(args.input),
        output=Path(args.output),
        target=args.target,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
