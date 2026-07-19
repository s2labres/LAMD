"""Shared, dependency-free data models used by the LAMD pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ApiInfo:
    """A suspicious API and the Android permissions associated with it."""

    index: int
    signature: str
    permissions: tuple[str, ...]


@dataclass(frozen=True)
class DatasetSample:
    """One row from a temporal dataset split."""

    sha256: str
    label: int
    family: str = ""
    date: str = ""
    vt_scan_date: str = ""


@dataclass(frozen=True)
class GraphInstance:
    """One function-call graph and the sliced CFGs reachable from it."""

    call_graph: Path
    slice_graphs: tuple[Path, ...]


@dataclass(frozen=True)
class ApiContext:
    """All graph instances associated with one suspicious API."""

    api: ApiInfo
    instances: tuple[GraphInstance, ...]
