"""Load LAMD dataset splits and the suspicious-API catalogue."""

from __future__ import annotations

import ast
import csv
import re
from collections.abc import Iterable
from pathlib import Path

from .models import ApiInfo, DatasetSample

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
DEFAULT_SPLIT_NAMES = (
    "train.csv",
    "test_1.csv",
    "test_2.csv",
    "test_3.csv",
    "test_ood_lamd.txt",
)


def _clean_row(row: dict[str | None, str | list[str] | None]) -> dict[str, str]:
    """Normalize whitespace introduced by the original CSV exports."""

    if None in row:
        raise ValueError(f"CSV row contains unexpected extra columns: {row[None]}")
    return {
        key.strip(): (value or "").strip()
        for key, value in row.items()
        if key is not None and not isinstance(value, list)
    }


def _parse_label(value: str) -> int:
    label = float(value)
    if label not in (0.0, 1.0):
        raise ValueError(f"Expected a binary label, got {value!r}")
    return int(label)


def load_split(path: str | Path) -> list[DatasetSample]:
    """Load one temporal split while validating hashes and binary labels."""

    split_path = Path(path)
    if not split_path.is_file():
        raise FileNotFoundError(f"Dataset split not found: {split_path}")

    samples: list[DatasetSample] = []
    seen: set[str] = set()
    with split_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        required = {"sha256", "label"}
        fields = {(field or "").strip() for field in (reader.fieldnames or [])}
        if not required.issubset(fields):
            raise ValueError(
                f"{split_path} must contain columns {sorted(required)}; found {sorted(fields)}"
            )

        for line_number, raw_row in enumerate(reader, start=2):
            row = _clean_row(raw_row)
            sha256 = row["sha256"].upper()
            if not SHA256_RE.fullmatch(sha256):
                raise ValueError(f"Invalid SHA256 in {split_path}:{line_number}: {sha256!r}")
            if sha256 in seen:
                raise ValueError(f"Duplicate SHA256 in {split_path}: {sha256}")
            seen.add(sha256)
            samples.append(
                DatasetSample(
                    sha256=sha256,
                    label=_parse_label(row["label"]),
                    family=row.get("family", ""),
                    date=row.get("date", ""),
                    vt_scan_date=row.get("vt_scan_date", ""),
                )
            )
    return samples


def load_labels(paths: Iterable[str | Path]) -> dict[str, int]:
    """Combine labels from multiple splits and reject conflicting entries."""

    labels: dict[str, int] = {}
    for path in paths:
        for sample in load_split(path):
            previous = labels.get(sample.sha256)
            if previous is not None and previous != sample.label:
                raise ValueError(f"Conflicting labels for {sample.sha256}")
            labels[sample.sha256] = sample.label
    return labels


def default_split_paths(dataset_dir: str | Path) -> list[Path]:
    """Return the canonical split files that are present in ``dataset_dir``."""

    root = Path(dataset_dir)
    return [root / name for name in DEFAULT_SPLIT_NAMES if (root / name).is_file()]


def _parse_permissions(raw_value: str) -> tuple[str, ...]:
    if not raw_value or raw_value == "[]":
        return ()
    try:
        parsed = ast.literal_eval(raw_value)
    except (SyntaxError, ValueError):
        parsed = [raw_value]
    if isinstance(parsed, str):
        parsed = [parsed]
    if not isinstance(parsed, (list, tuple)):
        raise ValueError(f"Unsupported permission value: {raw_value!r}")
    return tuple(
        str(value).removeprefix("Permission:").strip() for value in parsed if str(value).strip()
    )


def load_api_catalog(path: str | Path) -> dict[int, ApiInfo]:
    """Load the stable slicer index to suspicious-API mapping."""

    mapping_path = Path(path)
    if not mapping_path.is_file():
        raise FileNotFoundError(f"API mapping not found: {mapping_path}")

    catalog: dict[int, ApiInfo] = {}
    with mapping_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        fields = {(field or "").strip() for field in (reader.fieldnames or [])}
        required = {"API", "Index", "Permissions"}
        if not required.issubset(fields):
            raise ValueError(f"{mapping_path} must contain columns {sorted(required)}")
        for line_number, raw_row in enumerate(reader, start=2):
            row = _clean_row(raw_row)
            try:
                index = int(row["Index"])
            except ValueError as exc:
                raise ValueError(f"Invalid API index in {mapping_path}:{line_number}") from exc
            if index in catalog:
                raise ValueError(f"Duplicate API index in {mapping_path}: {index}")
            catalog[index] = ApiInfo(
                index=index,
                signature=row["API"],
                permissions=_parse_permissions(row["Permissions"]),
            )
    return catalog
