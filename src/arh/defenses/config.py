"""Defense configurations used for the ablation study."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DefenseConfig:
    name: str
    input_guard: bool = False   # heuristic injection/jailbreak detection + sentence quarantine
    output_guard: bool = False  # DLP on egress args and final answer; strips untrusted links
    allowlist: bool = False     # per-task least-privilege tool scope
    policy: bool = False        # policy-as-code: egress, taint, path and privilege rules
    approval: bool = False      # human-approval gate for high-risk actions
    approver: str = "intent"    # intent | rubber_stamp | deny_all
    description: str = ""


PRESETS: dict[str, DefenseConfig] = {c.name: c for c in [
    DefenseConfig("none", description="No defenses (baseline)."),
    DefenseConfig("input_guard", input_guard=True, description="Input guard only."),
    DefenseConfig("output_guard", output_guard=True, description="Output guard (DLP) only."),
    DefenseConfig("allowlist", allowlist=True, description="Least-privilege tool scope only."),
    DefenseConfig("policy", policy=True, description="Policy engine only (fails closed on require_approval)."),
    DefenseConfig("approval", approval=True, approver="intent", description="Human approval gate only (intent-bound reviewer)."),
    DefenseConfig("full", True, True, True, True, True, "intent", "All layers, intent-bound reviewer."),
    DefenseConfig("full_rubber_stamp", True, True, True, True, True, "rubber_stamp",
                  "All layers, but the reviewer approves everything (approval fatigue)."),
]}
