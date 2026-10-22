"""Command line entry point: `python -m secscan <path>`."""

import argparse
import sys

from . import __version__
from .rules import SEVERITY_ORDER, RULES
from .scanner import scan_path
from .report import to_console, to_json, to_html


def build_parser():
    p = argparse.ArgumentParser(
        prog="secscan",
        description="Static security and code quality scanner.")
    p.add_argument("target", nargs="?", help="File or folder to scan")
    p.add_argument("-f", "--format", choices=["console", "json", "html"], default="console")
    p.add_argument("-o", "--output", help="Write the report to this file")
    p.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="INFO",
                   help="Hide findings below this severity")
    p.add_argument("--no-quality", action="store_true", help="Security checks only")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                   help="Exit with code 1 if any security finding is at or above this severity (for CI)")
    p.add_argument("--list-rules", action="store_true", help="Print all security rules and exit")
    p.add_argument("--no-colour", action="store_true")
    p.add_argument("--version", action="version", version=f"secscan {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.list_rules:
        for r in RULES:
            print(f"{r.id:<7} {r.severity:<9} {r.cwe:<9} {r.title}")
        return 0

    if not args.target:
        print("error: give a file or folder to scan (see --help)", file=sys.stderr)
        return 2

    try:
        findings, scanned = scan_path(args.target, not args.no_quality, args.min_severity)
    except FileNotFoundError:
        print(f"error: '{args.target}' not found", file=sys.stderr)
        return 2

    if args.format == "json":
        report = to_json(findings, scanned)
    elif args.format == "html":
        report = to_html(findings, scanned, args.target)
    else:
        colour = not args.no_colour and not args.output and sys.stdout.isatty()
        report = to_console(findings, scanned, colour)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Report written to {args.output}")
    else:
        print(report)

    if args.fail_on:
        limit = SEVERITY_ORDER[args.fail_on]
        if any(f.category == "security" and SEVERITY_ORDER[f.severity] >= limit for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
