#!/usr/bin/env python3
"""Merge per-scanner SARIF files into one SARIF, preserving provenance.

 SARIF v2.1.0 is the one format every tool emits and every viewer
 ingests (GitHub, VS Code, AWS Audit Manager). No custom intermediate format —
 translating to a bespoke JSON loses the tool metadata the triage LLM needs to
 judge FP likelihood. We concatenate runs only; no cross-run dedup here (that's
 the LLM's job, it needs to see the raw overlap to dedupe with reasoning).

Usage: merge_sarif.py <input_dir_of_sarif> <output.sarif>

Each input becomes one entry in runs[]. run.tool.driver.name is kept as-is so
the downstream triage knows *who* flagged each finding.
"""
# one runnable self-check at the bottom (assert the merge invariant).

from __future__ import annotations
import json
import sys
from pathlib import Path


def _load(p: Path) -> dict | None:
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"[merge] skip {p.name}: {e}", file=sys.stderr)
        return None
    # Some scanners emit {} or a bare array on zero findings. Normalize.
    if isinstance(data, list):
        data = {"runs": []}
    if not isinstance(data, dict):
        return None
    runs = data.get("runs") or []
    if not runs:
        # Scanner found nothing — still useful to record that it ran.
        runs = [{
            "tool": {"driver": {"name": p.stem, "version": "unknown"}},
            "results": [],
            "invocations": [{"executionSuccessful": True}],
        }]
    # repo = the per-repo subdir name (run_scanners writes sarif/<repo>/<tool>.sarif).
    # This is the ONLY unambiguous source of repo attribution — scanners emit
    # repo-relative paths, so the path alone can't tell you which repo.
    repo = p.parent.name if p.parent.name and p.parent.name != p.parent.parent.name else p.stem
    for run in runs:
        run["automationDetails"] = {"id": repo}
        run.setdefault("properties", {})["_repo"] = repo
        for r in run.get("results", []):
            r.setdefault("properties", {})["_repo"] = repo
            r.setdefault("properties", {})["_source_file"] = p.name
    return {"runs": runs}


def merge(input_dir: Path, output: Path) -> int:
    # Recursive: sarif/<repo>/<tool>.sarif. Parent dir = repo.
    files = sorted(input_dir.rglob("*.sarif")) + sorted(input_dir.rglob("*.sarif.json"))
    if not files:
        print("[merge] no input SARIF files found", file=sys.stderr)
    merged_runs = []
    total_results = 0
    for f in files:
        doc = _load(f)
        if not doc:
            continue
        for run in doc["runs"]:
            merged_runs.append(run)
            total_results += len(run.get("results", []))

    out = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": merged_runs,
        "properties": {
            "merged_run_count": len(merged_runs),
            "merged_result_count": total_results,
        },
    }
    output.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"[merge] {len(merged_runs)} runs, {total_results} results -> {output}")
    return total_results


def _demo() -> None:
    # self-check — mirrors the real layout sarif/<repo>/<tool>.sarif.
    # Asserts the merge counts AND that repo attribution (parent dir) lands on
    # each result's properties._repo and the run's automationDetails.id.
    d = Path("/tmp/_sarif_demo")
    if d.exists():
        import shutil
        shutil.rmtree(d)
    repo_a = d / "repo-a"; repo_a.mkdir(parents=True)
    repo_b = d / "repo-b"; repo_b.mkdir(parents=True)
    (repo_a / "gitleaks.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [
        {"tool": {"driver": {"name": "gitleaks"}},
         "results": [{"ruleId": "X", "level": "error"}]}]}))
    (repo_b / "bandit.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [
        {"tool": {"driver": {"name": "bandit"}},
         "results": [{"ruleId": "Y", "level": "warning"}]}]}))
    out = d / "merged.sarif"
    n = merge(d, out)
    m = json.loads(out.read_text())
    assert len(m["runs"]) == 2, f"expected 2 runs, got {len(m['runs'])}"
    assert n == 2, f"expected 2 results, got {n}"
    repos = {r["automationDetails"]["id"] for r in m["runs"]}
    assert repos == {"repo-a", "repo-b"}, f"repo attribution wrong: {repos}"
    for r in m["runs"]:
        for res in r["results"]:
            assert res["properties"]["_repo"] == r["automationDetails"]["id"], "result _repo mismatch"
    print("[merge] demo ok (repo attribution verified)")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _demo(); sys.exit(0)
    if len(sys.argv) != 3:
        print("usage: merge_sarif.py <input_dir> <output.sarif>", file=sys.stderr); sys.exit(2)
    merge(Path(sys.argv[1]), Path(sys.argv[2]))
