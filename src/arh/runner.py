"""Run the suite across defense configurations and aggregate results."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any

from .agent import Agent
from .defenses.config import PRESETS, DefenseConfig
from .models.base import ModelAdapter
from .suite import Case, get_cases


@dataclass
class CaseResult:
    case_id: str
    kind: str
    category: str
    config: str
    success: bool                  # attack succeeded (attack) / task completed (benign)
    blocking_layers: list[str]
    approvals_requested: int
    final_output: str
    trace: dict[str, Any] = field(repr=False, default_factory=dict)


def run_case(model: ModelAdapter, cfg: DefenseConfig, case: Case, policy_engine=None) -> CaseResult:
    env = case.build_env()
    trace = Agent(model, cfg, policy_engine).run(case.id, case.prompt, case.scope, env)
    ok = case.success(env, trace.final_output)
    layers = trace.blocking_layers()
    if not ok and not layers and cfg.allowlist and case.kind == "attack":
        layers = ["allowlist"]  # the abused tool was never offered to the model
    return CaseResult(case.id, case.kind, case.category, cfg.name, ok, layers,
                      trace.approvals_requested, trace.final_output,
                      {"steps": [asdict(s) for s in trace.steps], "quarantined": trace.quarantined,
                       "output_redactions": trace.output_redactions, "refused_at_input": trace.refused_at_input,
                       "side_effects": {"emails": env.sent_emails, "http": env.http_requests,
                                        "shell": env.shell_commands, "roles": env.role_changes}})


def run_suite(model: ModelAdapter, configs: list[str] | None = None, policy_engine=None) -> dict[str, Any]:
    configs = configs or list(PRESETS)
    cases = get_cases()
    results = [run_case(model, PRESETS[c], case, policy_engine) for c in configs for case in cases]
    return {"model": model.name, "configs": configs, "results": results, "summary": summarize(results, configs)}


def summarize(results: list[CaseResult], configs: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for cfg in configs:
        rs = [r for r in results if r.config == cfg]
        attacks = [r for r in rs if r.kind == "attack"]
        benign = [r for r in rs if r.kind == "benign"]
        by_cat: dict[str, list[bool]] = defaultdict(list)
        for r in attacks:
            by_cat[r.category].append(r.success)
        out[cfg] = {
            "attack_success": sum(r.success for r in attacks),
            "attacks": len(attacks),
            "asr": round(sum(r.success for r in attacks) / len(attacks), 3) if attacks else 0.0,
            "benign_completed": sum(r.success for r in benign),
            "benign": len(benign),
            "utility": round(sum(r.success for r in benign) / len(benign), 3) if benign else 0.0,
            "approvals_requested": sum(r.approvals_requested for r in rs),
            "approvals_on_benign": sum(r.approvals_requested for r in benign),
            "by_category": {k: {"succeeded": sum(v), "total": len(v)} for k, v in sorted(by_cat.items())},
            "succeeded_attacks": [r.case_id for r in attacks if r.success],
        }
    return out
