"""Discover and read graph artefacts produced by the Java slicer."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from .models import ApiContext, ApiInfo, GraphInstance

SOOT_NODE_SUFFIX_RE = re.compile(r"---\d+")


def read_graph(path: str | Path) -> str:
    """Read a DOT graph and remove unstable Soot node-number suffixes."""

    graph_path = Path(path)
    content = graph_path.read_text(encoding="utf-8", errors="replace")
    return SOOT_NODE_SUFFIX_RE.sub("", content).strip()


def api_index_for_graph(call_graph: str | Path) -> int:
    """Extract ``<api-index>`` from ``<api-index>/<instance>/CallGraph/x.dot``."""

    path = Path(call_graph)
    try:
        return int(path.parent.parent.parent.name)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Unexpected call-graph layout: {path}") from exc


def relation_path_for_slice(slice_graph: str | Path) -> Path:
    """Return the static relation file corresponding to a sliced CFG."""

    path = Path(slice_graph)
    if path.parent.name != "SliceGraph":
        return path.parent.parent / "Relation" / f"{path.stem}.txt"
    return path.parent.with_name("Relation") / f"{path.stem}.txt"


def discover_api_contexts(
    apk_dir: str | Path,
    api_catalog: dict[int, ApiInfo],
) -> tuple[ApiContext, ...]:
    """Collect call graphs and sliced CFGs, grouped by suspicious API."""

    root = Path(apk_dir)
    if not root.is_dir():
        raise NotADirectoryError(f"Processed APK directory not found: {root}")

    grouped: dict[int, list[GraphInstance]] = defaultdict(list)
    for call_graph in sorted(root.rglob("CallGraph/*.dot")):
        api_index = api_index_for_graph(call_graph)
        if api_index not in api_catalog:
            raise KeyError(
                f"Graph directory uses API index {api_index}, which is absent from the API mapping"
            )

        instance_dir = call_graph.parent.parent
        slice_dir = instance_dir / "SliceGraph"
        cfg_dir = instance_dir / "cfg"
        slice_graphs = sorted(slice_dir.glob("*.dot")) if slice_dir.is_dir() else []
        slice_names = {path.name for path in slice_graphs}
        multi_callsite_bases = {
            path.stem.split("__callsite_", maxsplit=1)[0]
            for path in slice_graphs
            if "__callsite_" in path.stem
        }
        if cfg_dir.is_dir():
            slice_graphs.extend(
                path
                for path in sorted(cfg_dir.glob("*.dot"))
                if path.name not in slice_names and path.stem not in multi_callsite_bases
            )
        if slice_graphs:
            grouped[api_index].append(
                GraphInstance(call_graph=call_graph, slice_graphs=tuple(slice_graphs))
            )

    return tuple(
        ApiContext(api=api_catalog[index], instances=tuple(grouped[index]))
        for index in sorted(grouped)
    )
