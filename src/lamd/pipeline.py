"""Implementation of LAMD's tier-wise reasoning and consistency checking."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from .datasets import SHA256_RE
from .graphs import discover_api_contexts, read_graph, relation_path_for_slice
from .llm import LLMClient, PromptTooLongError, parse_json_object
from .models import ApiContext, ApiInfo
from .prompts import (
    flat_prompt,
    revision_prompt,
    tier1_prompt,
    tier1_summary_prompt,
    tier2_prompt,
    tier3_prompt,
)
from .relations import (
    compare_relations,
    parse_llm_relations_tolerant,
    parse_relation_text,
)

Ablation = Literal["none", "no-verification", "flat"]
LOGGER = logging.getLogger("lamd")


class NoGraphError(RuntimeError):
    """Raised when the slicer produced no analyzable suspicious-API context."""


@dataclass(frozen=True)
class AnalysisConfig:
    """Reproducibility-sensitive parameters for one analysis run."""

    output_dir: Path = Path("results")
    drc_threshold: float = 0.5
    ablation: Ablation = "none"
    overwrite: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.drc_threshold <= 1.0:
            raise ValueError("drc_threshold must be between 0 and 1")
        if self.ablation not in {"none", "no-verification", "flat"}:
            raise ValueError(f"Unsupported ablation: {self.ablation}")


def _function_summary(payload: dict[str, Any]) -> str:
    # The original prototype used camelCase keys. Accept snake_case as well so
    # existing cached responses and compatible backends remain readable.
    purpose = str(payload.get("functionPurpose", payload.get("function_purpose", ""))).strip()
    flow = str(payload.get("controlFlowAnalysis", payload.get("control_flow_analysis", ""))).strip()
    if not purpose or not flow:
        raise ValueError("Tier-1 JSON is missing its function purpose or control-flow analysis")
    return f"Function Purpose:\n{purpose}\n\nControl Flow Analysis:\n{flow}"


def _validate_final(payload: dict[str, Any]) -> dict[str, Any]:
    prediction = str(payload.get("prediction", "")).strip().upper()
    if prediction not in {"MALWARE", "BENIGN"}:
        raise ValueError(f"Invalid final prediction: {payload.get('prediction')!r}")
    findings = payload.get("key_findings", [])
    if (
        not isinstance(findings, list)
        or not 2 <= len(findings) <= 3
        or not all(isinstance(item, str) and item.strip() for item in findings)
    ):
        raise ValueError("key_findings must contain two or three non-empty strings")
    malware_type = payload.get("malware_type")
    if prediction == "BENIGN":
        malware_type = None
    elif malware_type is not None and not isinstance(malware_type, str):
        raise ValueError("malware_type must be a string or null")
    application_purpose = str(payload.get("application_purpose", "")).strip()
    conclusion = str(payload.get("conclusion", "")).strip()
    if not application_purpose or not conclusion:
        raise ValueError("Final JSON is missing application_purpose or conclusion")
    return {
        "prediction": prediction,
        "malware_type": malware_type,
        "application_purpose": application_purpose,
        "key_findings": [item.strip() for item in findings],
        "conclusion": conclusion,
    }


class LAMDAnalyzer:
    """Run the paper's function, API, and APK reasoning tiers."""

    def __init__(
        self,
        client: LLMClient,
        api_catalog: dict[int, ApiInfo],
        labels: dict[str, int] | None = None,
        config: AnalysisConfig | None = None,
    ) -> None:
        self.client = client
        self.api_catalog = api_catalog
        self.labels = labels or {}
        self.config = config or AnalysisConfig()
        self._slice_tasks: dict[tuple[Path, str], asyncio.Task[dict[str, Any]]] = {}
        self._apk_path: Path | None = None
        self._sha256 = ""
        self._cache_hits = 0

    def _slice_cache_path(self, path: Path, api_signature: str) -> Path:
        """Build a content-addressed checkpoint path for one Tier-1 result."""

        if self._apk_path is None or not self._sha256:
            raise RuntimeError("Slice cache requested outside an APK analysis")
        try:
            relative_path = str(path.resolve().relative_to(self._apk_path.resolve()))
        except ValueError:
            relative_path = str(path.resolve())
        relation_path = relation_path_for_slice(path)
        graph_content = read_graph(path)
        initial_prompt = (
            tier1_summary_prompt(graph_content, api_signature)
            if self.config.ablation == "no-verification"
            else tier1_prompt(graph_content, api_signature)
        )
        fingerprint = {
            "relative_path": relative_path,
            "api_signature": api_signature,
            "model": self.client.model,
            "prompt_version": "five-relations-v3-nary-parallel",
            "ablation": self.config.ablation,
            "drc_threshold": self.config.drc_threshold,
            "initial_prompt": initial_prompt,
            "revision_template": revision_prompt("", "", "", ()),
            "relations": (
                relation_path.read_text(encoding="utf-8") if relation_path.is_file() else None
            ),
        }
        digest = hashlib.sha256(
            json.dumps(fingerprint, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        return self.config.output_dir / ".cache" / self._sha256 / "tier1" / f"{digest}.json"

    async def _analyze_slice_uncached(self, path: Path, api_signature: str) -> dict[str, Any]:
        """Analyze one function after cache lookup has been resolved."""

        cfg_content = read_graph(path)
        if self.config.ablation == "no-verification":
            summary = await self.client.complete(tier1_summary_prompt(cfg_content, api_signature))
            return {
                "name": path.name,
                "path": str(path),
                "summary": summary.strip(),
                "selected_relations": [],
                "verification": {"status": "disabled"},
            }

        relation_path = relation_path_for_slice(path)
        expected = (
            parse_relation_text(relation_path.read_text(encoding="utf-8"))
            if relation_path.is_file()
            else None
        )
        prompt = tier1_prompt(cfg_content, api_signature)
        raw_response = await self.client.complete(prompt, json_mode=True)
        try:
            payload = parse_json_object(raw_response)
        except json.JSONDecodeError:
            # Large slices can make a model exhaust its output-token budget
            # while enumerating relationships, leaving an otherwise useful
            # response as truncated JSON.  Fall back to the bounded original
            # summary prompt and route the result through the same static
            # relation-guided revision used for a low DRC score.
            LOGGER.warning("Truncated Tier-1 JSON for %s; using revision fallback", path)
            summary = (
                await self.client.complete(tier1_summary_prompt(cfg_content, api_signature))
            ).strip()
            invalid = ["truncated_model_json"]
            result: dict[str, Any] = {
                "name": path.name,
                "path": str(path),
                "summary": summary,
                "selected_relations": [],
                "invalid_model_relations": invalid,
            }
            if expected is None:
                result["verification"] = {
                    "status": "unavailable",
                    "relation_path": str(relation_path),
                    "invalid_model_relations": invalid,
                }
                return result

            metrics = compare_relations(set(), expected)
            result["summary"] = (
                await self.client.complete(
                    revision_prompt(cfg_content, api_signature, summary, expected)
                )
            ).strip()
            result["verification"] = {
                "status": "revised",
                "relation_path": str(relation_path),
                "threshold": self.config.drc_threshold,
                "metrics": metrics.to_dict(),
                "expected_relations": [item.to_dict() for item in sorted(expected)],
                "invalid_model_relations": invalid,
            }
            return result
        summary = _function_summary(payload)
        relationship_payload = payload.get("relationships", [])
        if not isinstance(relationship_payload, list):
            relationship_payload = [relationship_payload]
        selected, invalid = parse_llm_relations_tolerant(relationship_payload)
        selected_payload = [item.to_dict() for item in sorted(selected)]

        result: dict[str, Any] = {
            "name": path.name,
            "path": str(path),
            "summary": summary,
            "selected_relations": selected_payload,
            "invalid_model_relations": invalid,
            "verification": {"status": "disabled"},
        }

        if expected is None:
            result["verification"] = {
                "status": "unavailable",
                "relation_path": str(relation_path),
                "invalid_model_relations": invalid,
            }
            return result

        metrics = compare_relations(selected, expected)
        if not invalid and metrics.drc >= self.config.drc_threshold:
            result["verification"] = {
                "status": "passed",
                "relation_path": str(relation_path),
                "threshold": self.config.drc_threshold,
                "metrics": metrics.to_dict(),
                "expected_relations": [item.to_dict() for item in sorted(expected)],
                "invalid_model_relations": invalid,
            }
            return result

        # A low-DRC or malformed relationship result is corrected once using
        # the statically extracted relationships.
        verification: dict[str, Any] = {
            "status": "revised",
            "relation_path": str(relation_path),
            "threshold": self.config.drc_threshold,
            "metrics": metrics.to_dict(),
            "expected_relations": [item.to_dict() for item in sorted(expected)],
            "invalid_model_relations": invalid,
        }
        summary = await self.client.complete(
            revision_prompt(cfg_content, api_signature, summary, expected)
        )
        result["summary"] = summary.strip()
        result["verification"] = verification
        return result

    async def _analyze_slice(self, path: Path, api_signature: str) -> dict[str, Any]:
        cache_path = self._slice_cache_path(path, api_signature)
        if cache_path.is_file() and not self.config.overwrite:
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                if isinstance(cached, dict):
                    cached["name"] = path.name
                    cached["path"] = str(path)
                    self._cache_hits += 1
                    return cached
            except (OSError, json.JSONDecodeError):
                pass

        result = await self._analyze_slice_uncached(path, api_signature)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = cache_path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.replace(cache_path)
        return result

    def _slice_task(self, path: Path, api_signature: str) -> asyncio.Task[dict[str, Any]]:
        key = (path.resolve(), api_signature)
        task = self._slice_tasks.get(key)
        if task is None:
            task = asyncio.create_task(self._analyze_slice(path, api_signature))
            self._slice_tasks[key] = task
        return task

    @staticmethod
    def _split_tier2_contexts(
        contexts: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Split an oversized API prompt while retaining every function analysis."""

        function_count = sum(len(context["functions"]) for context in contexts)
        if function_count < 2:
            raise PromptTooLongError(
                "A single API function context exceeds the configured prompt limit"
            )

        left: list[dict[str, Any]] = []
        right: list[dict[str, Any]] = []
        left_target = (function_count + 1) // 2
        left_count = 0
        for context in contexts:
            functions = list(context["functions"])
            take = min(len(functions), max(0, left_target - left_count))
            if take:
                left.append({"call_graph": context["call_graph"], "functions": functions[:take]})
                left_count += take
            if take < len(functions):
                right.append({"call_graph": context["call_graph"], "functions": functions[take:]})
        return left, right

    async def _complete_tier2(self, api: ApiInfo, contexts: list[dict[str, Any]]) -> list[str]:
        """Analyze an API, recursively batching only when its full prompt is too large."""

        try:
            return [(await self.client.complete(tier2_prompt(api, contexts))).strip()]
        except PromptTooLongError:
            left, right = self._split_tier2_contexts(contexts)
            LOGGER.warning(
                "Tier-2 context for API %s exceeds the input budget; splitting %d functions",
                api.index,
                sum(len(context["functions"]) for context in contexts),
            )
            batches = await asyncio.gather(
                self._complete_tier2(api, left),
                self._complete_tier2(api, right),
            )
            return [analysis for batch in batches for analysis in batch]

    async def _analyze_api(self, context: ApiContext) -> dict[str, Any]:
        tier2_contexts: list[dict[str, Any]] = []
        function_results: list[dict[str, Any]] = []
        for instance in context.instances:
            functions = await asyncio.gather(
                *[self._slice_task(path, context.api.signature) for path in instance.slice_graphs]
            )
            function_results.extend(functions)
            tier2_contexts.append(
                {
                    "call_graph": read_graph(instance.call_graph),
                    "functions": functions,
                }
            )

        analyses = await self._complete_tier2(context.api, tier2_contexts)
        analysis = "\n\n".join(
            f"=== API Analysis Batch #{index} ===\n{text}"
            for index, text in enumerate(analyses, start=1)
        )
        return {
            "api": context.api.signature,
            "api_index": context.api.index,
            "permissions": list(context.api.permissions),
            "contexts": len(context.instances),
            "analysis_batches": len(analyses),
            "functions": function_results,
            "analysis": analysis.strip(),
        }

    def _flat_contexts(self, contexts: tuple[ApiContext, ...]) -> list[dict[str, Any]]:
        rendered: list[dict[str, Any]] = []
        for context in contexts:
            rendered.append(
                {
                    "api": context.api.signature,
                    "permissions": list(context.api.permissions),
                    "instances": [
                        {
                            "call_graph": read_graph(instance.call_graph),
                            "slices": [read_graph(path) for path in instance.slice_graphs],
                        }
                        for instance in context.instances
                    ],
                }
            )
        return rendered

    async def analyze_apk(self, apk_dir: str | Path) -> dict[str, Any]:
        """Analyze one processed APK directory and persist a structured result."""

        apk_path = Path(apk_dir)
        sha256 = apk_path.name.upper()
        if not SHA256_RE.fullmatch(sha256):
            raise ValueError(f"Processed APK directory must be named with a SHA256: {apk_path}")
        output_path = self.config.output_dir / f"{sha256}.json"
        if output_path.is_file() and not self.config.overwrite:
            with output_path.open(encoding="utf-8") as handle:
                existing = json.load(handle)
            if not isinstance(existing, dict):
                raise ValueError(f"Existing result is not a JSON object: {output_path}")
            expected_configuration = {
                "model": self.client.model,
                "ablation": self.config.ablation,
                "drc_threshold": self.config.drc_threshold,
                "prompt_version": "five-relations-v3-nary-parallel",
            }
            actual_configuration = {key: existing.get(key) for key in expected_configuration}
            legacy_attempts = existing.get("tier1_max_attempts", 1)
            if actual_configuration != expected_configuration or legacy_attempts != 1:
                raise ValueError(
                    f"Existing result has a different configuration: {output_path}. "
                    "Use a separate --output-dir or pass --overwrite."
                )
            return existing

        contexts = discover_api_contexts(apk_path, self.api_catalog)
        if not contexts:
            raise NoGraphError(f"No analyzable graph contexts found under {apk_path}")

        self._slice_tasks = {}
        self._apk_path = apk_path
        self._sha256 = sha256
        self._cache_hits = 0
        started_at = datetime.now(timezone.utc)
        start = time.monotonic()
        if self.config.ablation == "flat":
            raw_final = await self.client.complete(
                flat_prompt(self._flat_contexts(contexts)), json_mode=True
            )
            api_analyses: list[dict[str, Any]] = []
        else:
            api_analyses = list(
                await asyncio.gather(*[self._analyze_api(context) for context in contexts])
            )
            raw_final = await self.client.complete(tier3_prompt(api_analyses), json_mode=True)

        final = _validate_final(parse_json_object(raw_final))
        verification_counts = {"passed": 0, "revised": 0, "unavailable": 0, "disabled": 0}
        for api_analysis in api_analyses:
            for function in api_analysis["functions"]:
                status = function["verification"]["status"]
                verification_counts[status] = verification_counts.get(status, 0) + 1

        result: dict[str, Any] = {
            "schema_version": 1,
            "sha256": sha256,
            "model": self.client.model,
            "ablation": self.config.ablation,
            "drc_threshold": self.config.drc_threshold,
            "prompt_version": "five-relations-v3-nary-parallel",
            "started_at": started_at.isoformat(),
            "duration_seconds": round(time.monotonic() - start, 3),
            "true_label": self.labels.get(sha256),
            **final,
            "verification_counts": verification_counts,
            "tier1_cache_hits": self._cache_hits,
            "api_analyses": api_analyses,
            "token_usage": self.client.usage(),
        }
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        temporary = output_path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.replace(output_path)
        return result
