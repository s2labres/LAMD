"""Command-line interface for slicing, analysis, inspection, and evaluation."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from dotenv import load_dotenv

from .datasets import SHA256_RE, default_split_paths, load_api_catalog, load_labels, load_split
from .evaluation import evaluate_predictions, load_json_predictions, load_legacy_predictions
from .graphs import discover_api_contexts, relation_path_for_slice
from .llm import OpenAIChatClient, OpenAIConfig
from .pipeline import AnalysisConfig, LAMDAnalyzer
from .slicer import SlicerConfig, slice_many

LOGGER = logging.getLogger("lamd")


def _default_data_path(filename: str) -> Path:
    """Resolve catalogues from a checkout or an installed wheel."""

    repository_file = Path(__file__).resolve().parents[2] / "dataset" / filename
    if repository_file.is_file():
        return repository_file
    return Path(__file__).resolve().parent / "data" / filename


DEFAULT_API_MAP = _default_data_path("sink_api_permission_mapping.csv")
DEFAULT_API_LIST = _default_data_path("sensitive_and_sink_apis.txt")
DEFAULT_SLICER_JAR = Path("java-slicer/target/lamd-slicer.jar")


def _add_target_arguments(parser: argparse.ArgumentParser) -> None:
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--sha256",
        action="append",
        help="SHA256 to process; may be supplied more than once",
    )
    target.add_argument("--split", type=Path, help="CSV/TXT split whose SHA256s to process")
    target.add_argument("--all", action="store_true", help="Process every available input")
    parser.add_argument("--limit", type=int, help="Process at most this many inputs")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lamd",
        description="Reproducible implementation of LAMD Android malware detection",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Run tier-wise LLM reasoning")
    analyze.add_argument("--processed-dir", type=Path, required=True)
    _add_target_arguments(analyze)
    analyze.add_argument("--api-map", type=Path, default=DEFAULT_API_MAP)
    analyze.add_argument("--dataset-dir", type=Path, default=Path("dataset"))
    analyze.add_argument("--output-dir", type=Path, default=Path("results"))
    analyze.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    analyze.add_argument("--base-url", help="OpenAI-compatible endpoint override")
    analyze.add_argument("--drc-threshold", type=float, default=0.5)
    analyze.add_argument(
        "--ablation",
        choices=("none", "no-verification", "flat"),
        default="none",
        help="none=LAMD, no-verification=LAMD-F, flat=LAMD-R",
    )
    analyze.add_argument("--max-concurrency", type=int, default=5)
    analyze.add_argument("--request-interval", type=float, default=0.0)
    analyze.add_argument("--timeout", type=float, default=120.0)
    analyze.add_argument("--max-input-tokens", type=int, default=120_000)
    analyze.add_argument("--overwrite", action="store_true")

    slicing = subparsers.add_parser("slice", help="Extract graph context from APKs")
    slicing.add_argument("--apk-dir", type=Path, required=True)
    slicing.add_argument("--output-dir", type=Path, required=True)
    slicing.add_argument("--android-platforms", type=Path, required=True)
    slicing.add_argument("--slicer-jar", type=Path, default=DEFAULT_SLICER_JAR)
    slicing.add_argument("--api-list", type=Path, default=DEFAULT_API_LIST)
    _add_target_arguments(slicing)
    slicing.add_argument("--workers", type=int, default=1)
    slicing.add_argument("--timeout", type=int, default=900)
    slicing.add_argument(
        "--k",
        type=int,
        default=1,
        help="caller context hops added after interprocedural variable resolution",
    )
    slicing.add_argument("--msdroid", action="store_true")
    slicing.add_argument("--debug-slicer", action="store_true")
    slicing.add_argument("--overwrite", action="store_true")

    inspect = subparsers.add_parser("inspect", help="Validate processed graph artefacts")
    inspect.add_argument("apk_dir", type=Path)
    inspect.add_argument("--api-map", type=Path, default=DEFAULT_API_MAP)

    evaluate = subparsers.add_parser("evaluate", help="Compute F1, FPR, and FNR")
    source = evaluate.add_mutually_exclusive_group(required=True)
    source.add_argument("--results-dir", type=Path)
    source.add_argument("--legacy-logs", type=Path)
    evaluate.add_argument("--split", type=Path, required=True)
    evaluate.add_argument("--allow-missing", action="store_true")
    evaluate.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    doctor = subparsers.add_parser("doctor", help="Check the local runtime and data files")
    doctor.add_argument("--require-openai", action="store_true")
    doctor.add_argument("--require-slicer", action="store_true")
    doctor.add_argument("--api-map", type=Path, default=DEFAULT_API_MAP)
    doctor.add_argument("--api-list", type=Path, default=DEFAULT_API_LIST)
    doctor.add_argument("--slicer-jar", type=Path, default=DEFAULT_SLICER_JAR)
    doctor.add_argument("--android-platforms", type=Path)
    return parser


def _validate_hash(value: str) -> str:
    sha256 = value.strip().upper()
    if not SHA256_RE.fullmatch(sha256):
        raise ValueError(f"Invalid SHA256: {value!r}")
    return sha256


def _target_hashes(args: argparse.Namespace, available_dir: Path | None = None) -> list[str]:
    if args.sha256:
        values = [_validate_hash(value) for value in args.sha256]
    elif args.split:
        values = [sample.sha256 for sample in load_split(args.split)]
    else:
        if available_dir is None or not available_dir.is_dir():
            raise NotADirectoryError(f"Input directory not found: {available_dir}")
        values = sorted(
            path.stem.upper()
            for path in available_dir.iterdir()
            if path.is_dir() or path.suffix.lower() == ".apk"
        )
        values = [value for value in values if SHA256_RE.fullmatch(value)]
    values = list(dict.fromkeys(values))
    if args.limit is not None:
        if args.limit < 1:
            raise ValueError("--limit must be positive")
        values = values[: args.limit]
    return values


def _case_insensitive_child(root: Path, sha256: str, suffix: str = "") -> Path:
    for name in (sha256 + suffix, sha256.lower() + suffix):
        candidate = root / name
        if candidate.exists():
            return candidate
    return root / (sha256 + suffix)


async def _run_analysis(args: argparse.Namespace) -> int:
    catalog = load_api_catalog(args.api_map)
    splits = default_split_paths(args.dataset_dir)
    labels = load_labels(splits) if splits else {}
    hashes = _target_hashes(args, args.processed_dir)
    base_url = args.base_url or os.environ.get("OPENAI_BASE_URL")
    client = OpenAIChatClient(
        OpenAIConfig(
            model=args.model,
            base_url=base_url,
            timeout_seconds=args.timeout,
            max_concurrency=args.max_concurrency,
            min_request_interval=args.request_interval,
            max_input_tokens=args.max_input_tokens,
        )
    )
    analyzer = LAMDAnalyzer(
        client,
        catalog,
        labels,
        AnalysisConfig(
            output_dir=args.output_dir,
            drc_threshold=args.drc_threshold,
            ablation=args.ablation,
            overwrite=args.overwrite,
        ),
    )
    failures: list[dict[str, str]] = []
    try:
        for index, sha256 in enumerate(hashes, start=1):
            apk_dir = _case_insensitive_child(args.processed_dir, sha256)
            LOGGER.info("[%d/%d] analyzing %s", index, len(hashes), sha256)
            try:
                result = await analyzer.analyze_apk(apk_dir)
                print(f"{sha256}: {result['prediction']}")
            except Exception as exc:  # Keep long batch experiments resumable.
                LOGGER.exception("Analysis failed for %s", sha256)
                failures.append({"sha256": sha256, "error": str(exc)})
    finally:
        await client.close()

    if failures:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "failures.jsonl").write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in failures),
            encoding="utf-8",
        )
        LOGGER.error("%d/%d analyses failed", len(failures), len(hashes))
        return 1
    failure_path = args.output_dir / "failures.jsonl"
    if failure_path.is_file():
        failure_path.unlink()
    return 0


def _run_slicing(args: argparse.Namespace) -> int:
    hashes = _target_hashes(args, args.apk_dir)
    apk_paths = [_case_insensitive_child(args.apk_dir, sha256, ".apk") for sha256 in hashes]
    config = SlicerConfig(
        jar_path=args.slicer_jar,
        output_dir=args.output_dir,
        android_platforms=args.android_platforms,
        sensitive_api_list=args.api_list,
        k=args.k,
        msdroid=args.msdroid,
        debug=args.debug_slicer,
        timeout_seconds=args.timeout,
        overwrite=args.overwrite,
    )
    results = slice_many(apk_paths, config, workers=args.workers)
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    print(json.dumps(counts, sort_keys=True))
    return int(bool(counts.get("error")))


def _run_inspection(args: argparse.Namespace) -> int:
    contexts = discover_api_contexts(args.apk_dir, load_api_catalog(args.api_map))
    instances = sum(len(context.instances) for context in contexts)
    slices = [
        path
        for context in contexts
        for instance in context.instances
        for path in instance.slice_graphs
    ]
    relations = sum(relation_path_for_slice(path).is_file() for path in slices)
    report = {
        "apk_dir": str(args.apk_dir),
        "apis": len(contexts),
        "call_graphs": instances,
        "slice_graphs": len(slices),
        "relation_files": relations,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return int(not contexts)


def _run_evaluation(args: argparse.Namespace) -> int:
    predictions = (
        load_json_predictions(args.results_dir)
        if args.results_dir
        else load_legacy_predictions(args.legacy_logs)
    )
    report = evaluate_predictions(predictions, args.split)
    if report.missing and not args.allow_missing:
        raise RuntimeError(
            f"Missing {report.missing}/{report.total_expected} predictions; "
            "pass --allow-missing to evaluate the available subset"
        )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(
            f"n={report.evaluated}/{report.total_expected}  "
            f"F1={report.f1 * 100:.2f}%  FPR={report.fpr * 100:.2f}%  "
            f"FNR={report.fnr * 100:.2f}%"
        )
    return 0


def _check(name: str, ok: bool, detail: str) -> bool:
    print(f"[{'OK' if ok else 'MISSING'}] {name}: {detail}")
    return ok


def _run_doctor(args: argparse.Namespace) -> int:
    required_ok = _check(
        "Python",
        sys.version_info >= (3, 10),
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )
    api_map_ok = _check("API mapping", args.api_map.is_file(), str(args.api_map))
    api_list_ok = _check("API list", args.api_list.is_file(), str(args.api_list))
    required_ok = required_ok and api_map_ok and api_list_ok

    key_ok = bool(os.environ.get("OPENAI_API_KEY"))
    _check("OPENAI_API_KEY", key_ok, "set" if key_ok else "not set")
    if args.require_openai:
        required_ok = required_ok and key_ok

    java = shutil.which("java")
    java_ok = java is not None
    java_detail = java or "not on PATH"
    if java:
        completed = subprocess.run([java, "-version"], capture_output=True, text=True, check=False)
        java_detail = (completed.stderr or completed.stdout).splitlines()[0]
    _check("Java", java_ok, java_detail)
    jar_ok = args.slicer_jar.is_file()
    _check("Slicer JAR", jar_ok, str(args.slicer_jar))
    platforms_ok = bool(args.android_platforms and args.android_platforms.is_dir())
    _check(
        "Android platforms",
        platforms_ok,
        str(args.android_platforms) if args.android_platforms else "not provided",
    )
    if args.require_slicer:
        required_ok = required_ok and java_ok and jar_ok and platforms_ok
    return int(not required_ok)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit status."""

    load_dotenv(override=False)
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    try:
        if args.command == "analyze":
            return asyncio.run(_run_analysis(args))
        if args.command == "slice":
            return _run_slicing(args)
        if args.command == "inspect":
            return _run_inspection(args)
        if args.command == "evaluate":
            return _run_evaluation(args)
        if args.command == "doctor":
            return _run_doctor(args)
    except (FileNotFoundError, NotADirectoryError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    return 2
