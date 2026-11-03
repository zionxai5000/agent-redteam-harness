"""Markdown and JSON report writers."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .defenses.config import PRESETS
from .mappings import ATLAS_TECHNIQUES, CATEGORY_RMF, LAYER_MITIGATIONS, OWASP
from .suite import CASES

CATEGORY_ORDER = ["direct_injection", "indirect_injection", "exfiltration", "privilege_escalation", "jailbreak", "integrity"]


def results_table(run: dict[str, Any]) -> str:
    s = run["summary"]
    lines = ["| Defense config | Attacks succeeded | ASR | Benign tasks completed | Approvals requested (benign / total) |",
             "|---|---|---|---|---|"]
    for cfg in run["configs"]:
        r = s[cfg]
        lines.append(f"| `{cfg}` | {r['attack_success']}/{r['attacks']} | {r['asr']:.0%} | "
                     f"{r['benign_completed']}/{r['benign']} | {r['approvals_on_benign']} / {r['approvals_requested']} |")
    return "\n".join(lines)


def category_table(run: dict[str, Any]) -> str:
    s, cfgs = run["summary"], run["configs"]
    lines = ["| Category | " + " | ".join(f"`{c}`" for c in cfgs) + " |", "|---|" + "---|" * len(cfgs)]
    for cat in CATEGORY_ORDER:
        cells = []
        for c in cfgs:
            v = s[c]["by_category"].get(cat)
            cells.append(f"{v['succeeded']}/{v['total']}" if v else "-")
        lines.append(f"| {cat} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def case_matrix(run: dict[str, Any]) -> str:
    cfgs = run["configs"]
    idx = {(r.case_id, r.config): r for r in run["results"]}
    lines = ["| Case | Kind | " + " | ".join(f"`{c}`" for c in cfgs) + " |", "|---|---|" + "---|" * len(cfgs)]
    for case in CASES:
        cells = []
        for c in cfgs:
            r = idx[(case.id, c)]
            if case.kind == "attack":
                cells.append("**HIT**" if r.success else ("blocked: " + "+".join(r.blocking_layers) if r.blocking_layers else "failed (model refused)"))
            else:
                cells.append("ok" if r.success else ("FAIL: " + "+".join(r.blocking_layers) if r.blocking_layers else "FAIL"))
        lines.append(f"| {case.id} {case.title} | {case.kind} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def write_reports(run: dict[str, Any], outdir: Path) -> tuple[Path, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    json_path, md_path = outdir / "results.json", outdir / "report.md"
    payload = {
        "model": run["model"],
        "note": "Generated with the deterministic mock model. Rates describe this hand-built suite, not real-model robustness.",
        "configs": {c: asdict(PRESETS[c]) for c in run["configs"]},
        "summary": run["summary"],
        "cases": [{"id": c.id, "kind": c.kind, "category": c.category, "title": c.title, "vector": c.vector,
                   "prompt": c.prompt, "scope": c.scope, "success_criterion": c.success.describe,
                   "atlas": c.atlas, "owasp": c.owasp, "nist_ai_rmf": CATEGORY_RMF[c.category]} for c in CASES],
        "results": [asdict(r) for r in run["results"]],
    }
    json_path.write_text(json.dumps(payload, indent=2))

    full = run["summary"].get("full", {})
    residual = [c for c in CASES if c.id in set(full.get("succeeded_attacks", []))]
    md = [
        "# Agent red-team report",
        "",
        f"Model adapter: `{run['model']}`. ",
        "**These results come from the deterministic mock model**, a worst-case, instruction-following stand-in. "
        "They show which defense layer stops which attack pattern in this hand-built suite. They are not a "
        "measurement of any real model's robustness.",
        "",
        "## Summary by defense configuration", "", results_table(run), "",
        "## Attack success by category", "", category_table(run), "",
        "## Case-by-case matrix", "",
        "`HIT` = attack succeeded. `blocked: x` = attack failed and layer x intervened. "
        "For benign tasks, `ok` = task completed.", "", case_matrix(run), "",
        "## Residual risk with all layers on (`full`)", "",
    ]
    if residual:
        for c in residual:
            md.append(f"- **{c.id} {c.title}** ({c.category}; {', '.join(c.atlas)}): {c.success.describe}.")
    else:
        md.append("- None in this suite.")
    md += ["", "## Framework mapping", "", "| Case | ATLAS techniques | OWASP LLM | NIST AI RMF |", "|---|---|---|---|"]
    for c in CASES:
        if c.kind != "attack":
            continue
        atlas = "; ".join(f"{t} {ATLAS_TECHNIQUES[t]}" for t in c.atlas)
        owasp = "; ".join(f"{o} {OWASP[o]}" for o in c.owasp)
        md.append(f"| {c.id} | {atlas} | {owasp} | {'; '.join(CATEGORY_RMF[c.category])} |")
    md += ["", "## Defense layers and ATLAS mitigations", ""]
    for layer, mits in LAYER_MITIGATIONS.items():
        md.append(f"- `{layer}`: {', '.join(mits)}")
    md_path.write_text("\n".join(md) + "\n")
    return json_path, md_path
