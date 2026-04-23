from __future__ import annotations

import argparse
from pathlib import Path

from accessguard.core.analyzer import analyze_project
from accessguard.output.formatter import print_json_report, print_text_report


def app() -> int:
    """Entry point for the accessguard CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command != "scan":
        parser.print_help()
        return 1

    return _scan(
        project_path=Path(args.path),
        json_output=args.json_output,
        quiet=args.quiet,
        fail_on_high=args.fail_on_high,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="accessguard",
        description="Detect unintended data access and privilege escalation in backend code.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a project directory for access risks.",
    )
    scan_parser.add_argument("path", help="Project directory to scan.")
    scan_parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output JSON report instead of text.",
    )
    scan_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print only the risk section in text mode.",
    )
    scan_parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with code 1 if any HIGH risk is found.",
    )
    return parser


def _scan(
    project_path: Path,
    json_output: bool,
    quiet: bool,
    fail_on_high: bool,
) -> int:
    if not project_path.exists() or not project_path.is_dir():
        print(f"Error: path does not exist or is not a directory: {project_path}")
        return 2

    result = analyze_project(project_path)

    if json_output:
        print_json_report(result)
    else:
        print_text_report(result, quiet=quiet)

    has_high_risk = any(risk.severity == "HIGH" for risk in result.risks)
    if fail_on_high and has_high_risk:
        return 1
    return 0


def main() -> None:
    raise SystemExit(app())


if __name__ == "__main__":
    main()
