"""Safe, reproducible wrapper around the Java APK slicer."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class SlicerConfig:
    """Arguments accepted by the slicer's ``Instrumenter.main`` entry point.

    ``k`` is the number of caller-context hops added after all variables that
    reach a function entry have been resolved interprocedurally.
    """

    jar_path: Path
    output_dir: Path
    android_platforms: Path
    sensitive_api_list: Path
    k: int = 1
    msdroid: bool = False
    debug: bool = False
    timeout_seconds: int = 900
    java_command: str = "java"
    overwrite: bool = False

    def validate(self) -> None:
        for description, path in (
            ("slicer JAR", self.jar_path),
            ("Android SDK platforms directory", self.android_platforms),
            ("sensitive API list", self.sensitive_api_list),
        ):
            if not path.exists():
                raise FileNotFoundError(f"{description} not found: {path}")
        if not self.jar_path.is_file():
            raise ValueError(f"Slicer JAR is not a file: {self.jar_path}")
        if not self.android_platforms.is_dir():
            raise ValueError(
                f"Android SDK platforms path is not a directory: {self.android_platforms}"
            )
        if not self.sensitive_api_list.is_file():
            raise ValueError(f"Sensitive API list is not a file: {self.sensitive_api_list}")
        if self.k < 0:
            raise ValueError("k must be non-negative")
        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")

    def command_for(self, apk_path: Path) -> list[str]:
        return [
            self.java_command,
            "-jar",
            str(self.jar_path),
            str(apk_path),
            str(self.output_dir),
            str(self.android_platforms),
            str(self.sensitive_api_list),
            str(self.k),
            str(self.msdroid).lower(),
            str(self.debug).lower(),
        ]


@dataclass(frozen=True)
class SlicingResult:
    apk: str
    status: str
    slice_count: int | None
    duration_seconds: float
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _last_integer(stdout: str) -> int:
    for line in reversed(stdout.splitlines()):
        try:
            return int(line.strip())
        except ValueError:
            continue
    raise ValueError(f"Slicer did not print a slice count. Output: {stdout[-500:]!r}")


def slice_apk(apk_path: str | Path, config: SlicerConfig) -> SlicingResult:
    """Slice one APK, validating the process exit code and numeric output."""

    path = Path(apk_path)
    started = time.monotonic()
    if not path.is_file():
        return SlicingResult(path.name, "error", None, 0.0, "APK file does not exist")

    output_path = config.output_dir / path.stem
    if output_path.exists() and not config.overwrite:
        return SlicingResult(path.name, "skipped", None, 0.0, "output already exists")
    if output_path.exists() and config.overwrite:
        if output_path.is_dir():
            shutil.rmtree(output_path)
        else:
            output_path.unlink()

    try:
        completed = subprocess.run(
            config.command_for(path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=config.timeout_seconds,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"Java exited with {completed.returncode}: "
                f"{(completed.stderr or completed.stdout)[-2000:].strip()}"
            )
        slice_count = _last_integer(completed.stdout)
        status = "zero-slice" if slice_count == 0 else "ok"
        return SlicingResult(
            path.name,
            status,
            slice_count,
            round(time.monotonic() - started, 3),
        )
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as exc:
        if output_path.exists():
            if output_path.is_dir():
                shutil.rmtree(output_path)
            else:
                output_path.unlink()
        return SlicingResult(
            path.name,
            "error",
            None,
            round(time.monotonic() - started, 3),
            str(exc),
        )


def slice_many(
    apk_paths: Iterable[str | Path],
    config: SlicerConfig,
    workers: int = 1,
) -> list[SlicingResult]:
    """Slice APKs concurrently and write a deterministic JSONL report."""

    config.validate()
    if workers < 1:
        raise ValueError("workers must be at least 1")
    config.output_dir.mkdir(parents=True, exist_ok=True)
    paths = sorted((Path(path) for path in apk_paths), key=lambda item: item.name)
    results: list[SlicingResult] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(slice_apk, path, config): path for path in paths}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            LOGGER.info("%s: %s", result.apk, result.status)

    results.sort(key=lambda result: result.apk)
    report_path = config.output_dir / "slicing-report.jsonl"
    report_path.write_text(
        "".join(json.dumps(result.to_dict(), sort_keys=True) + "\n" for result in results),
        encoding="utf-8",
    )
    return results
