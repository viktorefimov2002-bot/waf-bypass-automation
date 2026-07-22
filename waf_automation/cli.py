from __future__ import annotations

import argparse
import json
from pathlib import Path

from .diffing import diff_runs
from .importer import import_report
from .recheck import recheck_records
from .report import create_report
from .rules import suggest_rules
from .validation import validate_fixes


def _path(value: str) -> Path:
    return Path(value).expanduser().resolve()


def _add_verify_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--input", required=True, type=_path)
    command.add_argument("--output", required=True, type=_path)
    command.add_argument("--group", type=int, help="Verify only one group. Omit to verify all imported bypass variants.")
    command.add_argument("--execute", action="store_true")
    command.add_argument("--allow-host")
    command.add_argument("--limit", type=int)
    command.add_argument("--timeout", type=float, default=15.0)
    command.add_argument("--delay", type=float, default=0.2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="waf-bypass-tool",
        description="Normalize, verify and analyze nemesida/waf-bypass reports",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    command = subparsers.add_parser("import", help="Import BYPASSED records into normalized JSONL")
    command.add_argument("--report", required=True, type=_path)
    command.add_argument("--groups", required=True, type=_path)
    command.add_argument("--taxonomy", type=_path)
    command.add_argument("--overrides", type=_path, help="Legacy fallback for categories not present in taxonomy.json")
    command.add_argument("--output", required=True, type=_path)

    command = subparsers.add_parser("report", help="Create a compact XLSX report from JSONL")
    command.add_argument("--input", required=True, type=_path)
    command.add_argument("--groups", required=True, type=_path)
    command.add_argument("--taxonomy", type=_path)
    command.add_argument("--output", required=True, type=_path)

    command = subparsers.add_parser("verify", help="Dry-run or execute imported cURL variants and confirm real bypasses")
    _add_verify_arguments(command)

    command = subparsers.add_parser("recheck", help="Deprecated alias for verify")
    _add_verify_arguments(command)

    command = subparsers.add_parser(
        "validate-fix",
        help="Replay only previously confirmed bypasses after WAF rules are deployed",
    )
    command.add_argument("--before", required=True, type=_path)
    command.add_argument("--output-jsonl", required=True, type=_path)
    command.add_argument("--output-xlsx", required=True, type=_path)
    command.add_argument("--group", type=int)
    command.add_argument("--execute", action="store_true")
    command.add_argument("--allow-host")
    command.add_argument("--limit", type=int)
    command.add_argument("--timeout", type=float, default=15.0)
    command.add_argument("--delay", type=float, default=0.2)

    command = subparsers.add_parser("diff", help="Compare verification runs before and after WAF rule changes")
    command.add_argument("--before", required=True, type=_path)
    command.add_argument("--after", required=True, type=_path)
    command.add_argument("--output-jsonl", required=True, type=_path)
    command.add_argument("--output-xlsx", required=True, type=_path)

    command = subparsers.add_parser("suggest-rules", help="Generate candidate SecLang rules for confirmed origin bypasses")
    command.add_argument("--input", required=True, type=_path)
    command.add_argument("--output-dir", required=True, type=_path)
    command.add_argument("--id-start", required=True, type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "import":
        result = import_report(args.report, args.groups, args.output, args.taxonomy, args.overrides)
    elif args.command == "report":
        result = create_report(args.input, args.groups, args.output, args.taxonomy)
    elif args.command in {"verify", "recheck"}:
        result = recheck_records(
            args.input,
            args.output,
            group_id=args.group,
            execute=args.execute,
            allow_host=args.allow_host,
            limit=args.limit,
            timeout=args.timeout,
            delay=args.delay,
        )
        result["command"] = "verify"
        if args.command == "recheck":
            result["warning"] = "The recheck command is deprecated; use verify instead."
    elif args.command == "validate-fix":
        result = validate_fixes(
            args.before,
            args.output_jsonl,
            args.output_xlsx,
            execute=args.execute,
            allow_host=args.allow_host,
            group_id=args.group,
            limit=args.limit,
            timeout=args.timeout,
            delay=args.delay,
        )
    elif args.command == "diff":
        result = diff_runs(args.before, args.after, args.output_jsonl, args.output_xlsx)
    elif args.command == "suggest-rules":
        result = suggest_rules(args.input, args.output_dir, args.id_start)
    else:
        raise AssertionError(args.command)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0
