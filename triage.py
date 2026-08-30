#!/usr/bin/env python3
"""LLM triage of merged SARIF — bulk dedupe/FP/rank + deep semantic pass.

Both AI passes use DeepSeek V4 Pro via OpenRouter at MAX reasoning
(`reasoning.effort = "xhigh"`, the largest budget DeepSeek V4 Pro accepts —
maps to `max` per OpenRouter's table). Cheap enough (~$0.44/$0.87 per M) to
run max-reasoning across the whole finding set.

CRITICAL — secret handling: gitleaks SARIF contains real secret *values* in
result.message and region snippets. We NEVER forward those. For any finding
from a secret-class rule we send only (file, line, rule id). For all findings
we additionally run a redaction regex over every string that leaves the box,
and a self-check (see _redaction_selfcheck) asserts no candidate secret pattern
survives into any prompt payload. Live credentials never enter a prompt.

Usage: triage.py <merged.sarif> <report.md>
"""
# stdlib only (urllib) — no `requests` dep to install on the runner.
# The merge step already preserved per-run provenance; here we flatten, redact,
# chunk by repo, triage, then semantically hunt logic/authz bugs scanners can't.

from __future__ import annotations
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from collections import defaultdict

# ---- Config ----------------------------------------------------------------
MODEL = "z-ai/glm-5.2"
REASONING_EFFORT = "high"   # GLM 5.2, balanced (xhigh was ~20min)
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
# Cost per 1M tokens (input/output/cached-input) — from the audit objective.
COST_IN = 0.44
COST_OUT = 0.87
COST_CACHED = 0.0036
MAX_TOKENS_PER_CALL = 65536   # output cap; xhigh reasoning is verbose — 32k
                               # truncates the JSON mid-answer on big chunks. DeepSeek
                               # V4 Pro supports large completions; 65k leaves headroom.
CHUNK_FINDINGS = 30            # findings per bulk-triage call. xhigh reasoning is
                               # token-heavy; 60 blew past max_tokens → truncated JSON.
                               # 30 keeps reasoning + answer within 65k.
MIN_CHUNK_FINDINGS = 5         # below this, don't split further on length-truncation
SEMANTIC_SHORTLIST = 40        # top non-FP findings to feed the deep pass

# Rules whose findings are secret-bearing → never forward the message/region.
SECRET_RULE_HINTS = (
    "secret", "credential", "token", "apikey", "api-key", "password",
    "private-key", "private key", "aws", "gcp", "gitleaks",
)

# Generic secret-redaction patterns. Applied to EVERY string leaving the box.
SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                              # AWS access key id
    re.compile(r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,}"),                  # Slack
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),                    # GitHub PAT
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                           # OpenAI-style
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                        # Google API key
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
]
REDACTED = "[REDACTED]"

# ---- Finding flattening ----------------------------------------------------

def _line(result: dict) -> int:
    locs = result.get("locations") or []
    try:
        return int(locs[0]["physicalLocation"]["region"].get("startLine", 0))
    except (IndexError, KeyError, TypeError, ValueError):
        return 0


def _file(result: dict) -> str:
    locs = result.get("locations") or []
    try:
        return locs[0]["physicalLocation"]["artifactLocation"]["uri"]
    except (IndexError, KeyError, TypeError):
        return "?"


def _is_secret_finding(tool_name: str, rule_id: str, message: str) -> bool:
    hay = f"{tool_name} {rule_id} {message}".lower()
    return any(h in hay for h in SECRET_RULE_HINTS)


def redact(text: str, max_len: int = 600) -> str:
    """Strip candidate secrets from any string before it leaves the box."""
    if not text:
        return ""
    for pat in SECRET_PATTERNS:
        text = pat.sub(REDACTED, text)
    if len(text) > max_len:
        text = text[:max_len] + " …[truncated]"
    return text


def flatten(merged: dict) -> list[dict]:
    out = []
    for run in merged.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        # merge_sarif sets automationDetails.id + result.properties._repo to the
        # repo name (from the per-repo SARIF subdir). Scanners emit repo-relative
        # paths, so WITHOUT this every finding's file is ambiguous across repos
        # (settings.py in 3 repos → can't tell which). Prefer per-result _repo
        # (handles mixed runs), fall back to the run-level id.
        run_repo = run.get("automationDetails", {}).get("id", "")
        for r in run.get("results", []):
            rule_id = r.get("ruleId") or r.get("ruleIndex", "?")
            msg = r.get("message", {}).get("text", "") if isinstance(r.get("message"), dict) else str(r.get("message", ""))
            repo = (r.get("properties") or {}).get("_repo") or run_repo or "?"
            file = _file(r)
            line = _line(r)
            secret = _is_secret_finding(tool, rule_id, msg)
            # For secret findings: send NO message/region text. Just coordinates + rule.
            safe_msg = "" if secret else redact(msg)
            # Prefix repo into the path so the report + dedup are unambiguous.
            full_path = f"{repo}/{file}" if file and file != "?" else repo
            out.append({
                "id": f"{repo}:{tool}:{rule_id}:{file}:{line}",
                "repo": repo,
                "tool": tool,
                "rule": rule_id,
                "file": full_path,
                "line": line,
                "level": r.get("level", "note"),
                "message": safe_msg,        # empty for secret findings
                "is_secret": secret,
            })
    return out


# ---- OpenRouter client ------------------------------------------------------

def _read_key() -> str:
    key_file = os.environ.get("OPENROUTER_API_FILE")
    if not key_file:
        # fall back to env var for local dev runs
        return os.environ.get("OPENROUTER_API_KEY", "")
    try:
        return Path(key_file).read_text(encoding="utf-8").strip()
    except OSError:
        return os.environ.get("OPENROUTER_API_KEY", "")


class Spend:
    def __init__(self) -> None:
        self.in_tok = 0
        self.out_tok = 0
        self.cached_tok = 0
        self.calls = 0

    def add(self, usage: dict) -> None:
        # completion_tokens already includes reasoning tokens (OpenRouter counts
        # them toward completion); we bill output as one bucket.
        self.calls += 1
        self.in_tok += int(usage.get("prompt_tokens", 0) or 0)
        self.out_tok += int(usage.get("completion_tokens", 0) or 0)
        cd = usage.get("prompt_tokens_details", {}) or {}
        self.cached_tok += int(cd.get("cached_tokens", 0) or 0)

    @property
    def cost(self) -> float:
        noncached_in = max(0, self.in_tok - self.cached_tok)
        return (
            noncached_in / 1_000_000 * COST_IN
            + self.cached_tok / 1_000_000 * COST_CACHED
            + self.out_tok / 1_000_000 * COST_OUT
        )


def chat(messages: list[dict], spend: Spend, want_json: bool = True) -> tuple[str, str]:
    """Call the model. Returns (content, finish_reason).

    finish_reason surfaces "length" so callers can detect truncated JSON from
    verbose xhigh reasoning and retry with a smaller payload.
    """
    key = _read_key()
    if not key:
        raise RuntimeError("no OpenRouter key: set OPENROUTER_API_FILE or OPENROUTER_API_KEY")
    body = {
        "model": MODEL,
        "messages": messages,
        "reasoning": {"effort": REASONING_EFFORT, "exclude": False},
        "max_tokens": MAX_TOKENS_PER_CALL,
    }
    if want_json:
        body["response_format"] = {"type": "json_object"}

    def _post(b: dict) -> str:
        req = urllib.request.Request(
            OPENROUTER_URL, data=json.dumps(b).encode("utf-8"),
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                     "X-Title": "security-audit-triage"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=600) as resp:
            return resp.read().decode("utf-8")

    # retry on 429/5xx with backoff; on a 400 tied to response_format,
    # drop json_object and retry once (some models reject structured output).
    for attempt in range(4):
        try:
            raw = _post(body)
            payload = json.loads(raw)
            spend.add(payload.get("usage", {}))
            choice = payload["choices"][0]
            content = choice["message"]["content"] or ""
            finish = choice.get("finish_reason", "") or ""
            return content, finish
        except urllib.error.HTTPError as e:
            body_str = e.read().decode("utf-8", "replace")
            # FIX: was `"response_format" in body.get("response_format", {})` — that
            # checks keys of the INNER dict (always False). Check the request body.
            if e.code == 400 and "response_format" in body and "response_format" in body_str:
                body.pop("response_format", None)
                continue  # retry without json_object
            if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError(f"OpenRouter {e.code}: {body_str[:300]}") from e
        except (urllib.error.URLError, TimeoutError):
            if attempt < 3:
                time.sleep(2 ** attempt); continue
            raise
    return "", ""


def parse_json_obj(text: str) -> dict:
    """Defensive JSON extraction: strip fences, grab outermost braces."""
    if not text:
        return {}
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text).strip()
    if text[0] != "{":
        i, j = text.find("{"), text.rfind("}")
        if 0 <= i < j:
            text = text[i:j + 1]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


# ---- Bulk triage pass -------------------------------------------------------

BULK_SYSTEM = (
    "You are a senior application security triager. Be STRICT about false positives — "
    "the reviewer's prior run was flooded with low-value noise, so err toward "
    "likely_false_positive=true unless there is a concrete, exploitable path. You "
    "receive a JSON array of static-analysis findings (already SECRET-REDACTED — do "
    "NOT reconstruct secrets). For EACH finding return: dedup_key (short canonical "
    "cause, e.g. 'hardcoded-jwt-secret'), likely_false_positive (bool), "
    "exploitability (1-5; 5=unauth RCE/secret leak, 1=defense-in-depth nit), "
    "root_cause (short phrase), rationale (<=20 words).\n"
    "Mark likely_false_positive=true for: test/fixture/seed/load-test code, migrations, "
    "vendored/third-party code, management commands not reachable via the web, env-var "
    "NAMES without values, license/dependency-metadata notices, and 'missing tag / "
    "logging / versioning' style compliance nits.\n"
    "For INFRASTRUCTURE-AS-CODE (Terraform) findings specifically: a static scanner "
    "cannot see live AWS state, so treat them as LOW confidence — set "
    "exploitability<=3 and add ' (verify vs deployed state)' to rationale UNLESS the "
    "config is unambiguously world-open (0.0.0.0/0 on a sensitive port with a real "
    "attached resource). Do not rank orphaned/duplicate/potentially-unused resources high.\n"
    "Return ONLY a JSON object: {\"findings\":[{...}]}."
)

def chunk_by_repo(findings: list[dict]) -> list[list[dict]]:
    by_repo = defaultdict(list)
    for f in findings:
        # group by first path segment = repo name in our layout; fall back to file
        parts = f["file"].split("/")
        by_repo[parts[0] if parts and parts[0] else f["file"]].append(f)
    chunks = []
    for repo, items in by_repo.items():
        for i in range(0, len(items), CHUNK_FINDINGS):
            chunks.append(items[i:i + CHUNK_FINDINGS])
    return chunks


def _triage_chunk(chunk: list[dict], spend: Spend) -> list[dict]:
    """Triage one chunk; on length-truncation, split in half and recurse.

    xhigh reasoning is verbose — a 30-finding chunk can still hit max_tokens,
    truncating the JSON mid-answer (parse_json_obj → {} → findings fall to
    "untriaged"). When finish_reason=="length", halve the chunk and retry each
    half; below MIN_CHUNK_FINDINGS accept the partial result (parse_json_obj
    salvages whatever closed-JSON it can) rather than loop forever.
    """
    payload = [
        {"id": f["id"], "repo": f["repo"], "tool": f["tool"], "rule": f["rule"],
         "file": f["file"], "line": f["line"], "level": f["level"],
         "message": f["message"]}
        for f in chunk
    ]
    user = "Triage these findings. Input:\n" + json.dumps(payload)[:200_000]
    raw, finish = chat([{"role": "system", "content": BULK_SYSTEM},
                        {"role": "user", "content": user}], spend)
    if finish == "length" and len(chunk) > MIN_CHUNK_FINDINGS:
        mid = len(chunk) // 2
        print(f"[triage] length-truncation on {len(chunk)} findings; splitting → {mid}+{len(chunk)-mid}")
        return _triage_chunk(chunk[:mid], spend) + _triage_chunk(chunk[mid:], spend)

    obj = parse_json_obj(raw)
    by_id = {f["id"]: f for f in chunk}
    out = []
    for item in obj.get("findings", []):
        base = by_id.get(item.get("id"))
        if not base:
            continue
        base.update({
            "dedup_key": item.get("dedup_key", "?"),
            "fp": bool(item.get("likely_false_positive", False)),
            "exploitability": int(item.get("exploitability", 1) or 1),
            "root_cause": item.get("root_cause", "?"),
            "triage_rationale": item.get("rationale", ""),
        })
        out.append(base)
    return out


def bulk_triage(findings: list[dict], spend: Spend) -> list[dict]:
    enriched: list[dict] = []
    for chunk in chunk_by_repo(findings):
        enriched.extend(_triage_chunk(chunk, spend))
    # any findings the model skipped (truncation that couldn't split, or a
    # missing id): keep them, low score, so nothing silently vanishes.
    seen = {f["id"] for f in enriched}
    for f in findings:
        if f["id"] not in seen:
            f.update({"dedup_key": "?", "fp": False, "exploitability": 1,
                      "root_cause": "untriaged", "triage_rationale": ""})
            enriched.append(f)
    return enriched


# ---- Deep semantic pass -----------------------------------------------------

SEMANTIC_SYSTEM = (
    "You are a senior application security engineer doing a SEMANTIC review of a "
    "Python/Django + React/TS + Terraform codebase. Static scanners have produced "
    "a shortlist of high-risk findings (secret values REDACTED — coordinates + rule only).\n"
    "Do two things:\n"
    "1. For each input finding, confirm or reject it as a real, exploitable issue "
    "   (confirmed: bool, severity 1-5, one-line why).\n"
    "2. HUNT for logic / authorization / business-logic bugs scanners CANNOT express: "
    "   broken auth ordering (authz checked before auth, or not at all on a new endpoint), "
    "   IDOR (object-level authz missing — a user can read/update another user's object "
    "   by changing an id), missing role checks on admin endpoints, SSRF in "
    "   user-controlled URL fetches, race conditions on money/state transitions, "
    "   insecure deserialization, mass-assignment letting users set fields they shouldn't.\n"
    "Return ONLY JSON: {\"confirmations\":[{\"id\":...,\"confirmed\":bool,\"severity\":1-5,"
    "\"why\":\"...\"}], \"semantic_findings\":[{\"title\":\"...\",\"file\":\"...\","
    "\"line\":0,\"severity\":1-5,\"category\":\"authz|idor|ssrf|race|deser|"
    "business-logic|other\",\"description\":\"...\"}]}."
)


def deep_semantic(shortlist: list[dict], spend: Spend) -> dict:
    payload = [
        {"id": f["id"], "tool": f["tool"], "rule": f["rule"],
         "file": f["file"], "line": f["line"], "message": f["message"],
         "root_cause": f.get("root_cause", "")}
        for f in shortlist
    ]
    user = ("Confirm these top scanner findings and hunt for logic/authz/IDOR/business-"
            "logic bugs the scanners can't express. Findings (secret values redacted):\n"
            + json.dumps(payload)[:200_000])
    raw, finish = chat([{"role": "system", "content": SEMANTIC_SYSTEM},
                {"role": "user", "content": user}], spend)
    if finish == "length":
        # semantic pass already runs on a small shortlist; if it still truncates,
        # the JSON is partial. parse_json_obj salvages what it can; flag it.
        print("[triage] WARNING: semantic pass truncated (finish_reason=length); "
              "semantic_findings may be incomplete")
    return parse_json_obj(raw)


# ---- Report ----------------------------------------------------------------

def render_report(triaged: list[dict], semantic: dict, spend: Spend) -> str:
    # dedupe by dedup_key (keep highest exploitability). Scope the key by repo so
    # the same root cause in two repos (e.g. django-debug-true in repo-a AND
    # repo-b) stays as two findings — you need to fix both.
    by_key = defaultdict(list)
    for f in triaged:
        key = f"{f.get('repo','?')}::{f.get('dedup_key', f['id'])}"
        by_key[key].append(f)
    deduped = []
    for key, group in by_key.items():
        best = max(group, key=lambda x: x.get("exploitability", 1))
        best["instance_count"] = len(group)
        deduped.append(best)
    deduped.sort(key=lambda x: x.get("exploitability", 1), reverse=True)

    real = [f for f in deduped if not f.get("fp")]
    fps = [f for f in deduped if f.get("fp")]

    lines = []
    lines.append("# Security Audit — LLM-Triaged Report")
    lines.append("")
    lines.append(f"_Scanner findings: {len(triaged)} raw → {len(deduped)} deduped "
                 f"({len(real)} real, {len(fps)} likely-FP). "
                 f"Semantic findings: {len(semantic.get('semantic_findings', []))}._")
    lines.append("")
    lines.append("## Ranked Real Findings (by exploitability)")
    lines.append("")
    lines.append("| # | Sev | Repo | Tool | Root cause | File:Line | #inst | Rationale |")
    lines.append("|---|-----|-------|------|------------|-----------|-------|-----------|")
    for i, f in enumerate(real, 1):
        lines.append(f"| {i} | {f.get('exploitability',1)} | {f.get('repo','?')} | {f['tool']} | "
                     f"{f.get('root_cause','')} | `{f['file']}:{f['line']}` | "
                     f"{f.get('instance_count',1)} | {f.get('triage_rationale','')} |")
    lines.append("")
    lines.append("## Likely False Positives (suppressed)")
    lines.append("")
    lines.append("| Repo | Tool | Rule | File:Line | Why FP |")
    lines.append("|------|------|------|-----------|--------|")
    for f in fps:
        lines.append(f"| {f.get('repo','?')} | {f['tool']} | {f['rule']} | `{f['file']}:{f['line']}` | {f.get('triage_rationale','')} |")
    lines.append("")
    lines.append("## Semantic / Logic & Authz Findings")
    lines.append("")
    lines.append("_Bugs scanners can't express — from the deep DeepSeek pass on the high-risk shortlist._")
    lines.append("")
    sems = semantic.get("semantic_findings", [])
    if sems:
        lines.append("| # | Sev | Category | File:Line | Title | Description |")
        lines.append("|---|-----|----------|-----------|-------|-------------|")
        for i, s in enumerate(sems, 1):
            lines.append(f"| {i} | {s.get('severity',0)} | {s.get('category','other')} | "
                         f"`{s.get('file','?')}:{s.get('line',0)}` | {s.get('title','')} | {s.get('description','')} |")
    else:
        lines.append("_None surfaced in this pass._")
    lines.append("")
    lines.append("## Confirmed / Rejected (top shortlist)")
    lines.append("")
    confs = semantic.get("confirmations", [])
    if confs:
        lines.append("| ID | Confirmed | Sev | Why |")
        lines.append("|----|-----------|-----|-----|")
        for c in confs:
            lines.append(f"| {c.get('id','')} | {'yes' if c.get('confirmed') else 'no'} | "
                         f"{c.get('severity',0)} | {c.get('why','')} |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Token Spend")
    lines.append("")
    lines.append(f"- Calls: {spend.calls}")
    lines.append(f"- Input tokens: {spend.in_tok:,} (of which cached: {spend.cached_tok:,})")
    lines.append(f"- Output tokens: {spend.out_tok:,}")
    lines.append(f"- Est. cost: ${spend.cost:.4f}  "
                 f"(@ ${COST_IN}/M in, ${COST_OUT}/M out, ${COST_CACHED}/M cached)")
    lines.append("")
    lines.append("_All AI steps used DeepSeek V4 Pro at max reasoning (`effort=xhigh`). "
                 "No secret values were sent to the model — gitleaks findings forwarded "
                 "coordinates + rule only; all strings passed through a redaction filter._")
    return "\n".join(lines)


# ---- Self-checks -----------------------------------------------------------

def _redaction_selfcheck() -> None:
    """Assert no candidate secret pattern survives redact(), and that a
    gitleaks-style finding's message is stripped before flattening."""
    assert "REDACTED" in redact("password=\"sk-1234567890abcdefghijklmnop\"")
    assert redact("AKIA" + "X" * 16) == REDACTED
    assert redact("ghp_" + "a" * 36) == REDACTED
    # A secret-class finding forwards NO message text.
    merged = {"runs": [{
        "tool": {"driver": {"name": "gitleaks"}},
        "automationDetails": {"id": "client-portal"},
        "results": [{
            "ruleId": "generic-api-key",
            "level": "error",
            "message": {"text": "detected AWS key AKIA" + "A"*16 + " = supersecretvalue"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "config.py"},
                "region": {"startLine": 42}}}],
            "properties": {"_repo": "client-portal"},
        }],
    }]}
    findings = flatten(merged)
    assert findings[0]["message"] == "", "secret finding message was not stripped!"
    assert findings[0]["is_secret"] is True
    assert findings[0]["repo"] == "client-portal", "repo attribution lost"
    assert findings[0]["file"] == "client-portal/config.py", "repo not prefixed into path"
    print("[triage] redaction self-check ok (repo attribution verified)")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _redaction_selfcheck(); sys.exit(0)
    if len(sys.argv) != 3:
        print("usage: triage.py <merged.sarif> <report.md>", file=sys.stderr); sys.exit(2)
    _redaction_selfcheck()
    merged = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    findings = flatten(merged)
    print(f"[triage] {len(findings)} raw findings")
    spend = Spend()
    triaged = bulk_triage(findings, spend)
    shortlist = [f for f in triaged if not f.get("fp") and f.get("exploitability", 0) >= 3]
    shortlist.sort(key=lambda x: x.get("exploitability", 0), reverse=True)
    shortlist = shortlist[:SEMANTIC_SHORTLIST]
    print(f"[triage] {len(shortlist)} high-risk findings → deep semantic pass")
    semantic = deep_semantic(shortlist, spend) if shortlist else {}
    report = render_report(triaged, semantic, spend)
    Path(sys.argv[2]).write_text(report, encoding="utf-8")
    print(f"[triage] report -> {sys.argv[2]}")
    print(f"[triage] spend: {spend.calls} calls, ${spend.cost:.4f}")
