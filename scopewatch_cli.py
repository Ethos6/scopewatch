"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

__version__ = "0.1.0"
from scopewatch_scanner import scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scopewatch",
        description="A bounded, passive security posture snapshot for one authorized website.",
        epilog="ScopeWatch makes at most four fixed-path GET requests. It does not exploit, crawl, or mutate the target.",
    )
    parser.add_argument("target", nargs="?", help="Website origin, such as https://example.com")
    parser.add_argument("--authorized", action="store_true", help="Confirm that you own or have permission to assess this target.")
    parser.add_argument("--allow-private", action="store_true", help="Permit private or loopback IPs for an authorized test lab.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds (default: 5; maximum: 15).")
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text", help="Report format (default: text).")
    parser.add_argument("--output", type=Path, help="Write report to a file instead of stdout.")
    parser.add_argument("--version", action="version", version=f"ScopeWatch {__version__}")
    return parser


def _render_text(report: dict) -> str:
    lines = [f"ScopeWatch report: {report['target']}", f"Scanned: {report['scanned_at']}", f"Resolved IP: {report['resolved_ip']}", f"Requests: {report['requests_made']}", ""]
    for item in report["findings"]:
        lines.append(f"[{item['severity'].upper()}] {item['title']} — {item['status']}")
        lines.append(f"  {item['detail']}")
        if item["recommendation"]:
            lines.append(f"  Next step: {item['recommendation']}")
    if report["errors"]:
        lines.append("\nRequest errors:")
        lines.extend(f"  - {error}" for error in report["errors"])
    return "\n".join(lines) + "\n"


def _render_markdown(report: dict) -> str:
    lines = [f"# ScopeWatch report: {report['target']}", "", f"- Scanned: {report['scanned_at']}", f"- Resolved IP: `{report['resolved_ip']}`", f"- Requests made: {report['requests_made']}", "", "## Findings", "", "| Severity | Finding | Status | Detail |", "|---|---|---|---|"]
    for item in report["findings"]:
        detail = item["detail"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {item['severity']} | {item['title']} | {item['status']} | {detail} |")
        if item["recommendation"]:
            lines.extend(["", f"**Recommendation — {item['title']}:** {item['recommendation']}"])
    if report["errors"]:
        lines.extend(["", "## Request errors", ""])
        lines.extend(f"- `{error}`" for error in report["errors"])
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.target:
        parser.error("a target origin is required")
    if not args.authorized:
        parser.error("pass --authorized after confirming you own or have permission to assess the target")
    if not 0.5 <= args.timeout <= 15:
        parser.error("--timeout must be between 0.5 and 15 seconds")
    try:
        report = scan(args.target, timeout=args.timeout, allow_private=args.allow_private).to_dict()
    except ValueError as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, indent=2) + "\n" if args.format == "json" else _render_markdown(report) if args.format == "markdown" else _render_text(report)
    if args.output:
        try:
            args.output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(f"Could not write report: {exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

