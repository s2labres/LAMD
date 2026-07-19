"""Compute the paper's F1, FPR, and FNR from saved LAMD predictions."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path

from .datasets import SHA256_RE, load_split

LEGACY_PREDICTION_RE = re.compile(
    r"Final Prediction:\s*(?:\*\*)?(MALWARE|BENIGN)(?:\*\*)?",
    flags=re.IGNORECASE,
)


@dataclass(frozen=True)
class EvaluationReport:
    """Binary classification metrics with explicit confusion-matrix counts."""

    total_expected: int
    evaluated: int
    missing: int
    true_positive: int
    true_negative: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    fpr: float
    fnr: float

    def to_dict(self) -> dict[str, int | float]:
        return asdict(self)


def load_json_predictions(results_dir: str | Path) -> dict[str, int]:
    """Load structured result files emitted by :class:`LAMDAnalyzer`."""

    predictions: dict[str, int] = {}
    for path in sorted(Path(results_dir).glob("*.json")):
        with path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError(f"Result must contain a JSON object: {path}")
        prediction = str(payload.get("prediction", "")).upper()
        if prediction not in {"MALWARE", "BENIGN"}:
            raise ValueError(f"Invalid prediction in {path}: {prediction!r}")
        sha256 = str(payload.get("sha256", path.stem)).upper()
        if not SHA256_RE.fullmatch(sha256):
            raise ValueError(f"Invalid SHA256 in {path}: {sha256!r}")
        if path.stem.upper() != sha256:
            raise ValueError(f"Result SHA256 does not match its filename: {path}")
        if sha256 in predictions:
            raise ValueError(f"Duplicate result for SHA256 {sha256}")
        predictions[sha256] = int(prediction == "MALWARE")
    return predictions


def load_legacy_predictions(log_dir: str | Path) -> dict[str, int]:
    """Load final predictions from the text logs distributed on Zenodo."""

    predictions: dict[str, int] = {}
    for path in sorted(Path(log_dir).glob("*.log")):
        matches = LEGACY_PREDICTION_RE.findall(path.read_text(encoding="utf-8", errors="replace"))
        if matches:
            predictions[path.stem.upper()] = int(matches[-1].upper() == "MALWARE")
    return predictions


def evaluate_predictions(
    predictions: Mapping[str, int], split_path: str | Path
) -> EvaluationReport:
    """Evaluate predictions on one split using malware as the positive class."""

    samples = load_split(split_path)
    tp = tn = fp = fn = evaluated = 0
    for sample in samples:
        prediction = predictions.get(sample.sha256)
        if prediction is None:
            continue
        if prediction not in (0, 1):
            raise ValueError(f"Non-binary prediction for {sample.sha256}: {prediction}")
        evaluated += 1
        if sample.label == 1 and prediction == 1:
            tp += 1
        elif sample.label == 0 and prediction == 0:
            tn += 1
        elif sample.label == 0 and prediction == 1:
            fp += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0
    return EvaluationReport(
        total_expected=len(samples),
        evaluated=evaluated,
        missing=len(samples) - evaluated,
        true_positive=tp,
        true_negative=tn,
        false_positive=fp,
        false_negative=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        fpr=fpr,
        fnr=fnr,
    )
