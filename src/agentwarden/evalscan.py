"""Scanner eval (spec 013): `make eval-scan` on the content set (`eval/content/*.jsonl`)."""

from __future__ import annotations

import datetime as dt
import json
import math
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from agentwarden import scanner
from agentwarden.providers import get_provider
from agentwarden.providers.cache import CachedProvider

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTENT = str(REPO_ROOT / "eval" / "content" / "*.jsonl")
HOLDOUT_NAME = "holdout.jsonl"
SCANNER_ENV = {"local": "WARDEN_LOCAL_BASE", "meta_api": "META_API_KEY"}


class ContentCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    source_type: Literal["readme", "code_comment", "issue", "web_page", "config", "docs"]
    path: str
    content: str
    label: Literal["injection", "clean"]
    note: str | None = None
    source: str | None = None


class ScanCaseResult(BaseModel):
    id: str
    source_type: str
    label: str
    flagged: bool
    error: str | None
    latency_ms: int
    holdout: bool = False


def load_content(paths: list[Path]) -> tuple[list[ContentCase], list[ContentCase]]:
    """(main, holdout); raises ValueError on any bad line or duplicate id."""
    main: list[ContentCase] = []
    holdout: list[ContentCase] = []
    seen: set[str] = set()
    for path in paths:
        target = holdout if Path(path).name == HOLDOUT_NAME else main
        for lineno, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                case = ContentCase.model_validate(json.loads(line))
            except (json.JSONDecodeError, ValidationError) as exc:
                raise ValueError(f"{path}:{lineno}: invalid content case: {exc}") from exc
            if case.id in seen:
                raise ValueError(f"{path}:{lineno}: duplicate id {case.id!r}")
            seen.add(case.id)
            target.append(case)
    return main, holdout


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def _rank(values: list[int], pct: float) -> int | None:
    """Nearest-rank percentile."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(pct * len(ordered)) - 1)]


def content_metrics(results: list[ScanCaseResult]) -> dict:
    injected = [r for r in results if r.label == "injection"]
    clean = [r for r in results if r.label == "clean"]
    tp = sum(r.flagged for r in injected)
    fp = sum(r.flagged for r in clean)
    latencies = [r.latency_ms for r in results]
    return {
        "n": len(results),
        "recall": _ratio(tp, len(injected)),
        "precision": _ratio(tp, tp + fp),
        "fpr": _ratio(fp, len(clean)),
        "errors": sum(r.error is not None for r in results),
        "parse_failures": sum(r.error == "unparsable" for r in results),
        "latency_ms": {"p50": _rank(latencies, 0.50), "p95": _rank(latencies, 0.95)},
    }


def run_cases(cases: list[ContentCase], provider, *, holdout: bool = False) -> list[ScanCaseResult]:
    out = []
    for case in cases:
        result = scanner.scan(case.content, case.path, provider)
        out.append(
            ScanCaseResult(
                id=case.id,
                source_type=case.source_type,
                label=case.label,
                flagged=result.flagged,
                error=result.error,
                latency_ms=result.latency_ms,
                holdout=holdout,
            )
        )
    return out


def _fmt(value: float | None) -> str:
    return "-" if value is None else f"{value:.3f}"


def _row(name: str, m: dict) -> str:
    return (
        f"{name:<15} {m['n']:<4} {_fmt(m['recall']):<7} {_fmt(m['precision']):<7} "
        f"{_fmt(m['fpr']):<6} {m['errors']:<4} {m['latency_ms']['p50']!s:<6} "
        f"{m['latency_ms']['p95']!s}"
    )


HEADER = f"{'set':<15} {'n':<4} {'recall':<7} {'prec':<7} {'fpr':<6} {'err':<4} {'p50ms':<6} p95ms"


def run_content_eval(
    case_files: list[Path], results_dir: Path, write: bool, commit: str, rel
) -> int:
    name = (os.environ.get("WARDEN_SCANNER") or "local").strip().lower()
    provider = get_provider(name)
    if provider is None:
        print(f"scan: not available ({SCANNER_ENV.get(name, 'WARDEN_SCANNER')} not set)")
        return 2
    if scanner.load_prompt(scanner.prompt_path()) is None:
        print("scan: not available (prompts/scanner.md not written)")
        return 2
    try:
        main, holdout = load_content(case_files)
    except (OSError, ValueError) as exc:
        print(f"bad content file: {exc}")
        return 2
    if not main and not holdout:
        print("no cases found")
        return 2
    cached = CachedProvider(
        provider,
        cacheable=lambda text: scanner.parse_output(text) is not None,
        namespace=f"scanner:{name}",
    )
    results = run_cases(main, cached) + run_cases(holdout, cached, holdout=True)
    main_m = content_metrics([r for r in results if not r.holdout])
    holdout_m = content_metrics([r for r in results if r.holdout]) if holdout else None
    print(HEADER)
    print(_row("scan", main_m))
    if holdout_m is not None:
        print(_row("scan (holdout)", holdout_m))
    misses = [r for r in results if r.flagged != (r.label == "injection")]
    print("mismatches:" if misses else "mismatches: none")
    for r in misses:
        print(f"  {r.id}  {r.label} -> {'flagged' if r.flagged else 'clean'}  ({r.error or 'ok'})")
    if write:
        date = dt.date.today().isoformat()
        out_path = Path(results_dir) / f"{date}-{commit}-content-scan.json"
        payload = {
            "set": "content",
            "mode": "scan",
            "scanner": name,
            "date": date,
            "commit": commit,
            "case_files": [rel(p) for p in case_files],
            "metrics": {"main": main_m, "holdout": holdout_m},
            "cases": [r.model_dump() for r in results],
        }
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), "utf-8")
        except OSError as exc:
            print(f"cannot write results: {exc}")
            return 2
        print(f"wrote {out_path}")
    return 0
