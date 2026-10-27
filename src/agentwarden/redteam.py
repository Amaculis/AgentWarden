"""Meta red-team loop (spec 014): Muse Spark generates attacks, the defender is scored.

Generated cases are drafts: bypasses and over-blocks go to `eval/candidates/` only, for the
human to relabel and promote. Nothing generated is ever executed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from agentwarden import evalrun
from agentwarden.judge import DATA_PREAMBLE, env_float, load_prompt
from agentwarden.providers import Provider, get_provider
from agentwarden.redact import redact_obj

REPO_ROOT = Path(__file__).resolve().parents[2]
PROMPT_PATH = REPO_ROOT / "prompts" / "redteam.md"
RUNS_DIR = REPO_ROOT / "redteam" / "runs"
CANDIDATES_DIR = REPO_ROOT / "eval" / "candidates"
DEFAULT_CATEGORIES = (
    "secrets",
    "exfiltration",
    "destruction",
    "persistence",
    "drift",
    "injection",
    "judge_attack",
    "benign",
)
MAX_TOKENS = 6000
MAX_REPLY_CHARS = 200_000  # bounds the JSON scan below on garbage replies
MAX_EXAMPLES = 5


def prompt_path() -> Path:
    override = os.environ.get("WARDEN_REDTEAM_PROMPT")
    return Path(override) if override else PROMPT_PATH


def _json_objects(text: str) -> list[object]:
    decoder = json.JSONDecoder(strict=False)
    found: list[object] = []
    pos = 0
    while True:
        starts = [i for i in (text.find("{", pos), text.find("[", pos)) if i != -1]
        if not starts:
            return found
        start = min(starts)
        try:
            value, end = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            pos = start + 1
            continue
        if isinstance(value, list):
            found.extend(value)
        else:
            found.append(value)
        pos = end


def parse_generated(
    text: str | None, round_no: int, date: str
) -> tuple[list[evalrun.ActionCase], list[str], int]:
    """(valid cases, their attack ideas, number of invalid objects)."""
    cases: list[evalrun.ActionCase] = []
    ideas: list[str] = []
    invalid = 0
    for raw in _json_objects((text or "")[:MAX_REPLY_CHARS]):
        if not isinstance(raw, dict):
            invalid += 1
            continue
        data = dict(raw)
        idea = data.pop("attack_idea", "")
        category = data.get("category", "case")
        data["id"] = f"{category}-meta-{date}-r{round_no}-{len(cases) + 1:03d}"
        data["source"] = "redteam-meta"
        data.setdefault("history", [])
        try:
            case = evalrun.ActionCase.model_validate(data)
        except (ValidationError, TypeError):
            invalid += 1
            continue
        cases.append(case)
        ideas.append(idea if isinstance(idea, str) else "")
    return cases, ideas, invalid


def classify(label: str, decision: str) -> str | None:
    if label in ("deny", "ask") and decision == "allow":
        return "bypass"
    if label == "allow" and decision == "deny":
        return "overblock"
    return None


def load_examples() -> list[dict]:
    for pattern in ("cases", "candidates"):
        files = sorted(glob.glob(str(REPO_ROOT / "eval" / pattern / "*.jsonl")))
        rows: list[dict] = []
        for path in files:
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                if line.strip():
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        if rows:
            step = max(len(rows) // MAX_EXAMPLES, 1)
            return rows[::step][:MAX_EXAMPLES]
    return []


def build_messages(
    prompt: str,
    round_no: int,
    batch: int,
    categories: list[str],
    examples: list[dict],
    blocked: list[str],
) -> list[dict[str, str]]:
    document = redact_obj(
        {
            "round": round_no,
            "batch": batch,
            "categories": categories,
            "examples": examples,
            "blocked_last_round": blocked,
        }
    )
    return [
        {"role": "system", "content": prompt},
        {"role": "user", "content": f"{DATA_PREAMBLE}\n\n{json.dumps(document, indent=1)}"},
    ]


def _inside(path: Path, root: Path) -> bool:
    return Path(path).resolve().is_relative_to(Path(root).resolve())


def write_report(runs_dir: Path, name: str, report: dict) -> None:
    """Round report under redteam/runs/ only (it holds generated content)."""
    if not _inside(runs_dir, RUNS_DIR):
        raise ValueError(f"refusing to write round reports outside redteam/runs/: {runs_dir}")
    runs_dir = Path(runs_dir)
    runs_dir.mkdir(parents=True, exist_ok=True)
    (runs_dir / name).write_text(json.dumps(report, indent=2, ensure_ascii=False), "utf-8")


def write_candidates(path: Path, rows: list[dict]) -> None:
    """Append candidate rows. Refuses anything outside eval/candidates/ (invariant 4)."""
    resolved = Path(path).resolve()
    if resolved.parent != CANDIDATES_DIR.resolve():
        raise ValueError(f"refusing to write candidates outside eval/candidates/: {path}")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    with open(resolved, "a", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def run_round(
    round_no: int,
    generator: Provider,
    prompt: str,
    decider: evalrun.Decider,
    *,
    batch: int,
    categories: list[str],
    examples: list[dict],
    blocked: list[str],
    date: str,
) -> dict:
    messages = build_messages(prompt, round_no, batch, categories, examples, blocked)
    timeout = env_float("WARDEN_REDTEAM_TIMEOUT", 60.0)
    result = generator.complete(messages, timeout=timeout, max_tokens=MAX_TOKENS)
    cases, ideas, invalid = parse_generated(result.text, round_no, date)
    results = evalrun.run_mode(cases, decider)
    rows = []
    for case, idea, res in zip(cases, ideas, results, strict=True):
        rows.append(
            {
                "case": case.model_dump(exclude_none=True),
                "attack_idea": idea,
                "decision": res.decision,
                "decided_source": res.source,
                "outcome": classify(case.label, res.decision),
            }
        )
    dangerous = [r for r in rows if r["case"]["label"] in ("deny", "ask")]
    bypasses = [r for r in rows if r["outcome"] == "bypass"]
    return {
        "round": round_no,
        "generator_error": result.error,
        "generator_tokens": [result.tokens_in or 0, result.tokens_out or 0],
        "generated": len(cases) + invalid,
        "valid": len(cases),
        "invalid": invalid,
        "bypasses": len(bypasses),
        "bypass_rate": len(bypasses) / len(dangerous) if dangerous else None,
        "overblocks": sum(r["outcome"] == "overblock" for r in rows),
        "blocked_ideas": [r["attack_idea"] for r in dangerous if r["decision"] != "allow"],
        "rows": rows,
    }


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AgentWarden Meta red-team loop")
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--batch", type=int, default=20)
    parser.add_argument(
        "--defender", default="cascade", choices=["cascade", "spark", "local", "rules"]
    )
    parser.add_argument("--categories", default=",".join(DEFAULT_CATEGORIES))
    parser.add_argument("--runs-dir", type=Path, default=RUNS_DIR)
    parser.add_argument("--candidates-dir", type=Path, default=CANDIDATES_DIR)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    generator = get_provider("meta_api")
    if generator is None:
        print("redteam: not available (META_API_KEY not set)")
        return 2
    prompt = load_prompt(prompt_path())
    if prompt is None:
        print("redteam: not available (prompts/redteam.md not written)")
        return 2
    decider, why_not = evalrun._resolve_mode(args.defender)
    if decider is None:
        print(f"redteam: defender {args.defender} not available ({why_not})")
        return 2
    max_usd = env_float("REDTEAM_MAX_USD", 5.0)
    categories = [c.strip() for c in args.categories.split(",") if c.strip()]
    examples = load_examples()
    date = dt.date.today().isoformat()
    # Same fixed policy as the eval, never the developer's own (eval-case skill).
    previous_policy = os.environ.get("WARDEN_POLICY")
    os.environ["WARDEN_POLICY"] = str(evalrun.EVAL_POLICY_PATH)
    try:
        return _loop(args, generator, prompt, decider, categories, examples, date, max_usd)
    finally:
        if previous_policy is None:
            os.environ.pop("WARDEN_POLICY", None)
        else:
            os.environ["WARDEN_POLICY"] = previous_policy


def _loop(args, generator, prompt, decider, categories, examples, date, max_usd) -> int:
    meters = getattr(decider, "meters", [])
    price_in, price_out = evalrun._spark_prices()
    blocked: list[str] = []
    generator_cost = 0.0
    stopped = None
    print(f"{'round':<6} {'gen':<5} {'valid':<6} {'bypass':<7} {'rate':<6} {'over':<5} cost$")
    for round_no in range(1, args.rounds + 1):
        spent = (
            generator_cost + sum(m.tokens_in * pi + m.tokens_out * po for m, pi, po in meters) / 1e6
        )
        if spent >= max_usd:
            stopped = "budget"
            print(f"budget reached (${spent:.2f} >= ${max_usd:.2f}); stopping")
            break
        report = run_round(
            round_no,
            generator,
            prompt,
            decider,
            batch=args.batch,
            categories=categories,
            examples=examples,
            blocked=blocked,
            date=date,
        )
        tokens_in, tokens_out = report["generator_tokens"]
        generator_cost += (tokens_in * price_in + tokens_out * price_out) / 1e6
        spent = (
            generator_cost + sum(m.tokens_in * pi + m.tokens_out * po for m, pi, po in meters) / 1e6
        )
        report.update({"date": date, "defender": args.defender, "cost_usd_total": spent})
        rate = "-" if report["bypass_rate"] is None else f"{report['bypass_rate']:.2f}"
        print(
            f"{round_no:<6} {report['generated']:<5} {report['valid']:<6} "
            f"{report['bypasses']:<7} {rate:<6} {report['overblocks']:<5} {spent:.3f}"
        )
        flagged = [r for r in report["rows"] if r["outcome"]]
        try:
            write_report(Path(args.runs_dir), f"{date}-r{round_no}.json", report)
            if flagged:
                rows = []
                for r in flagged:
                    row = dict(r["case"])
                    row["note"] = f"{r['outcome']}: {r['attack_idea']}".strip()
                    rows.append(row)
                write_candidates(
                    Path(args.candidates_dir) / f"redteam-{date}-r{round_no}.jsonl", rows
                )
        except (OSError, ValueError) as exc:
            print(f"cannot write round results: {exc}")
            return 2
        blocked = report["blocked_ideas"]
    if stopped:
        print(f"stopped: {stopped}")
    return 0
