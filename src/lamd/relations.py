"""Parse static/LLM data relations and compute the paper's DRC metric."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

RELATION_LINE_RE = re.compile(r"^\s*\[([^]]+)]\s*(.*?)\s*$")
# Jimple locals may refer to an array element with either a literal or another
# local as the index (for example ``$r2[0]`` or ``$r7[$i0]``).
VARIABLE_RE = re.compile(r"\$?[A-Za-z_][A-Za-z0-9_]*(?:\[(?:\d+|\$?[A-Za-z_][A-Za-z0-9_]*)\])*")
TYPE_ALIASES = {
    "direct": "Direct",
    "transitive": "Transitive",
    "conditional": "Conditional",
    "parallel": "Parallel",
    "inheritance": "Derived",
    "derived": "Derived",
}


@dataclass(frozen=True, order=True)
class Relation:
    """Canonical representation of one variable/API dependency."""

    kind: str
    variables: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        if self.kind == "Derived" and len(self.variables) == 2:
            return {
                "type": self.kind,
                "target": self.variables[0],
                "source": self.variables[1],
            }
        if self.kind == "Parallel":
            return {"type": self.kind, "variables": list(self.variables)}
        return {"type": self.kind, "variable": self.variables[0]}


@dataclass(frozen=True)
class RelationMetrics:
    """Set-based agreement between selected and statically extracted relations."""

    matches: int
    selected: int
    expected: int
    drc: float
    recall: float
    f1: float

    def to_dict(self) -> dict[str, float | int]:
        return {
            "matches": self.matches,
            "selected": self.selected,
            "expected": self.expected,
            "drc": self.drc,
            "recall": self.recall,
            "f1": self.f1,
        }


def _canonical_type(value: Any) -> str:
    key = str(value).strip().lower()
    try:
        return TYPE_ALIASES[key]
    except KeyError as exc:
        raise ValueError(f"Unknown relation type: {value!r}") from exc


def _variable(value: Any) -> str:
    text = str(value).strip()
    if not VARIABLE_RE.fullmatch(text):
        raise ValueError(f"Invalid variable name: {value!r}")
    return text


def _make_relation(kind: str, variables: Iterable[Any]) -> Relation:
    cleaned = tuple(_variable(value) for value in variables)
    if kind == "Parallel":
        cleaned = tuple(sorted(set(cleaned)))
        if len(cleaned) < 2:
            raise ValueError(f"Parallel expects at least 2 distinct variables, got {cleaned}")
    else:
        expected_length = 2 if kind == "Derived" else 1
        if len(cleaned) != expected_length:
            raise ValueError(f"{kind} expects {expected_length} variable(s), got {cleaned}")
    return Relation(kind=kind, variables=cleaned)


def parse_relation_text(content: str) -> set[Relation]:
    """Parse relation files emitted by current and legacy slicers.

    Legacy files call derived relations ``Inheritance``. They are canonicalized
    to the ``Derived`` terminology used by the paper and maintained slicer.
    """

    relations: set[Relation] = set()
    for line_number, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        match = RELATION_LINE_RE.match(line)
        if not match:
            raise ValueError(f"Malformed relation at line {line_number}: {line!r}")
        kind = _canonical_type(match.group(1))
        body = match.group(2)
        if kind == "Derived":
            parts = [part.strip() for part in body.split("<-", maxsplit=1)]
        elif kind == "Parallel":
            compact = re.sub(r"\s+work\s+together\s*$", "", body, flags=re.I)
            parts = [part.strip() for part in re.split(r"\s+and\s+", compact)]
        else:
            parts = [body]
        relations.add(_make_relation(kind, parts))
    return relations


def parse_llm_relations(payload: Iterable[dict[str, Any]]) -> set[Relation]:
    """Normalize the structured relationship list returned by the LLM."""

    relations: set[Relation] = set()
    for item in payload:
        if not isinstance(item, Mapping):
            raise ValueError(f"Each model relationship must be an object, got {item!r}")
        kind = _canonical_type(item.get("type", ""))
        if kind == "Derived":
            values = (item.get("target"), item.get("source"))
        elif kind == "Parallel":
            values = item.get("variables") or (item.get("left"), item.get("right"))
        else:
            values = (item.get("variable"),)
        relations.add(_make_relation(kind, values))
    return relations


def parse_llm_relations_tolerant(
    payload: Iterable[dict[str, Any]],
) -> tuple[set[Relation], list[dict[str, Any]]]:
    """Parse valid model relations and retain malformed entries for auditing.

    Model JSON occasionally includes constants, field expressions, or incomplete
    pairs despite the prompt. Those entries must trigger grounded revision, but
    should not discard hundreds of otherwise valid APK-level requests.
    """

    relations: set[Relation] = set()
    invalid: list[dict[str, Any]] = []
    for index, item in enumerate(payload):
        try:
            relations.update(parse_llm_relations([item]))
        except (TypeError, ValueError) as exc:
            invalid.append({"index": index, "value": item, "error": str(exc)})
    return relations, invalid


def compare_relations(selected: set[Relation], expected: set[Relation]) -> RelationMetrics:
    """Compute Data Relationship Coverage (precision), recall, and F1.

    Equation (1) in the paper defines DRC as correctly selected dependencies
    divided by all selected dependencies. For an empty selection, DRC is 1
    only when the static relation set is also empty; otherwise it is 0.
    """

    matches = len(selected & expected)
    drc = matches / len(selected) if selected else float(not expected)
    recall = matches / len(expected) if expected else 1.0
    f1 = 2 * drc * recall / (drc + recall) if drc + recall else 0.0
    return RelationMetrics(
        matches=matches,
        selected=len(selected),
        expected=len(expected),
        drc=drc,
        recall=recall,
        f1=f1,
    )
