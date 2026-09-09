from __future__ import annotations

import argparse
import json
from pathlib import Path

from .diagnosis import diagnose_observations
from .diffing import diff_runs
from .gap_analysis import analyze_gap_clusters
from .handoff import export_rule_engineering_corpus
from .importer import import_report
from .merge_cases import merge_case_records
from .recheck import recheck_records
from .refinement import refine_rules
from .report import create_compact_report, create_report
from .rules import suggest_rules
from .telemetry import correlate_logs
from .validation import validate_fixes


def _path(value: str) -> Path:
    return Path(value).expanduser().resolve()


def _add_verify_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--input", required=True, type=_path)
    command.add_argument("--output", required=True, type=_path)
    command.add_argument("--report-xlsx", type=_path, help="Optional compact XLSX report for verification results")
    command.add_argument("--group", type=int, help="Verify only one group. Omit to verify all imported bypass variants.")
    command.add_argument("--execute", action="store_true")
    command.add_argument("--allow-host")
    command.add_argument("--limit", type=int)
    command.add_argument("--timeout", type=float, default=15.0)
    command.add_argument("--delay", type=float, default=0.2)
    command.add_argument(
        "--only-verdict",
        action="append",
        default=None,
        help="Replay only records with this prior final_verdict; repeat for multiple values (for example CHECK_ERROR).",
    )


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
    command.add_argument("--groups", type=_path, help="Deprecated; group metadata is already stored in JSONL")
    command.add_argument("--taxonomy", type=_path, help="Deprecated; group metadata is already stored in JSONL")
    command.add_argument("--output", required=True, type=_path)

    command = subparsers.add_parser("verify", help="Dry-run or execute imported cURL variants and confirm real bypasses")
    _add_verify_arguments(command)

    command = subparsers.add_parser("recheck", help="Deprecated alias for verify")
    _add_verify_arguments(command)

    command = subparsers.add_parser(
        "correlate-logs",
        help="Join replay JSONL with WAF security-log telemetry by waf-fp-test-id/test_id",
    )
    command.add_argument("--replay", required=True, type=_path, help="verified/replayed JSONL containing test_id")
    command.add_argument("--security-log", required=True, type=_path, help="Security log as JSONL/JSONEachRow, JSON array, or object with rows/data/result")
    command.add_argument("--output", required=True, type=_path)

    command = subparsers.add_parser(
        "diagnose",
        help="Classify correlated observations as detection/scoring/policy/telemetry outcomes",
    )
    command.add_argument("--input", required=True, type=_path, help="observations.jsonl from correlate-logs")
    command.add_argument("--output", required=True, type=_path)

    command = subparsers.add_parser(
        "merge-cases",
        help="Replace older JSONL records with newer records using stable case_id identity",
    )
    command.add_argument("--base", required=True, type=_path)
    command.add_argument("--updates", required=True, type=_path)
    command.add_argument("--output", required=True, type=_path)

    command = subparsers.add_parser(
        "analyze-gaps",
        help="Cluster diagnosed variants and identify normalization/target/partial/scoring candidates",
    )
    command.add_argument("--input", required=True, type=_path, help="diagnosed.jsonl from diagnose")
    command.add_argument("--output-dir", required=True, type=_path)
    command.add_argument(
        "--rule-pack",
        type=_path,
        help="Optional deployed YAML/JSON ruleset. Enables same-family vs cross-family matched-rule analysis.",
    )

    command = subparsers.add_parser(
        "export-corpus",
        help="Export diagnosed attack cases as a neutral handoff corpus for waf-rule-engineering",
    )
    command.add_argument("--input", required=True, type=_path, help="diagnosed.jsonl or analyze-gaps cases.jsonl")
    command.add_argument("--output-dir", required=True, type=_path)
    command.add_argument(
        "--diagnosis",
        action="append",
        default=None,
        help="Diagnosis to export; repeat for multiple values. Default: DETECTION_GAP and SCORING_GAP.",
    )

    command = subparsers.add_parser(
        "validate-fix",
        help="Replay only previously confirmed bypasses after WAF rules are deployed",
    )
    command.add_argument("--before", required=True, type=_path)
    command.add_argument("--output-jsonl", required=True, type=_path)
    command.add_argument("--output-xlsx", required=True, type=_path)
    command.add_argument("--coverage", type=_path, help="coverage.csv from suggest-rules for payload-to-rule mapping")
    command.add_argument("--manifest", type=_path, help="manifest.json from suggest-rules for rule pattern and transform metadata")
    command.add_argument("--group", type=int)
    command.add_argument("--execute", action="store_true")
    command.add_argument("--allow-host")
    command.add_argument("--limit", type=int)
    command.add_argument("--timeout", type=float, default=15.0)
    command.add_argument("--delay", type=float, default=0.2)

    command = subparsers.add_parser("diff", help="Compare arbitrary verification runs")
    command.add_argument("--before", required=True, type=_path)
    command.add_argument("--after", required=True, type=_path)
    command.add_argument("--output-jsonl", required=True, type=_path)
    command.add_argument("--output-xlsx", required=True, type=_path)

    command = subparsers.add_parser("suggest-rules", help="Generate candidate SecLang rules for confirmed bypasses")
    command.add_argument("--input", required=True, type=_path)
    command.add_argument("--output-dir", required=True, type=_path)
    command.add_argument("--id-start", required=True, type=int)

    command = subparsers.add_parser("refine-rules", help="Refine candidate rules for STILL_BYPASSED validation results")
    command.add_argument("--validation", required=True, type=_path, help="fix-validation.jsonl from validate-fix")
    command.add_argument("--manifest", required=True, type=_path, help="manifest.json used for the failed validation")
    command.add_argument("--coverage", required=True, type=_path, help="coverage.csv used for the failed validation")
    command.add_argument("--output-dir", required=True, type=_path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "import":
        result = import_report(args.report, args.groups, args.output, args.taxonomy, args.overrides)
    elif args.command == "report":
        if args.groups:
            result = create_report(args.input, args.groups, args.output, args.taxonomy)
        else:
            result = create_compact_report(args.input, args.output)
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
            only_verdicts=args.only_verdict,
        )
        result["command"] = "verify"
        if args.report_xlsx:
            report_result = create_compact_report(args.output, args.report_xlsx)
            result["report_xlsx"] = report_result["output"]
        if args.command == "recheck":
            result["warning"] = "The recheck command is deprecated; use verify instead."
    elif args.command == "correlate-logs":
        result = correlate_logs(args.replay, args.security_log, args.output)
    elif args.command == "diagnose":
        result = diagnose_observations(args.input, args.output)
    elif args.command == "merge-cases":
        result = merge_case_records(args.base, args.updates, args.output)
    elif args.command == "analyze-gaps":
        result = analyze_gap_clusters(args.input, args.output_dir, args.rule_pack)
    elif args.command == "export-corpus":
        result = export_rule_engineering_corpus(args.input, args.output_dir, args.diagnosis)
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
            coverage_path=args.coverage,
            manifest_path=args.manifest,
        )
    elif args.command == "diff":
        result = diff_runs(args.before, args.after, args.output_jsonl, args.output_xlsx)
    elif args.command == "suggest-rules":
        result = suggest_rules(args.input, args.output_dir, args.id_start)
    elif args.command == "refine-rules":
        result = refine_rules(args.validation, args.manifest, args.coverage, args.output_dir)
    else:
        raise AssertionError(args.command)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0
