"""The agent loop with pluggable defense layers.

Order of controls for each model-proposed tool call:

    model -> [allowlist: only scoped tools offered] -> policy engine
          -> approval gate -> output guard (DLP on egress args) -> tool
          -> input guard (quarantine + spotlight tool output) -> model

Every decision is recorded in the trace, which doubles as the audit log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .defenses import approval as approval_mod
from .defenses import input_guard, output_guard
from .defenses.config import DefenseConfig
from .defenses.policy import PythonEngine, build_input, load_policy_data
from .env import PRINCIPAL, SYSTEM_PROMPT, TOOL_SPECS, Environment
from .models.base import ModelAdapter
from .types import Final, Message, ToolCall

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"https?://[^\s'\"<>)]+")
_CMD = re.compile(r"`([^`]+)`")


def user_named(prompt: str) -> dict[str, list[str]]:
    """Destinations the *user* named in the trusted turn (intent binding)."""
    return {
        "recipients": sorted(set(_EMAIL.findall(prompt))),
        "urls": sorted({u.rstrip(".,") for u in _URL.findall(prompt)}),
        "commands": sorted(set(_CMD.findall(prompt))),
    }


@dataclass
class Step:
    call: dict[str, Any]
    outcome: str            # executed | blocked
    layer: str = ""         # which layer blocked it
    detail: str = ""
    approval_requested: bool = False


@dataclass
class Trace:
    case_id: str
    config: str
    steps: list[Step] = field(default_factory=list)
    final_output: str = ""
    refused_at_input: bool = False
    quarantined: list[dict[str, Any]] = field(default_factory=list)
    output_redactions: list[str] = field(default_factory=list)
    approvals_requested: int = 0

    def blocking_layers(self) -> list[str]:
        layers = [s.layer for s in self.steps if s.outcome == "blocked"]
        if self.refused_at_input:
            layers.append("input_guard")
        if self.quarantined:
            layers.append("input_guard")
        if self.output_redactions:
            layers.append("output_guard")
        return sorted(set(layers))


class Agent:
    def __init__(self, model: ModelAdapter, config: DefenseConfig, policy_engine=None, max_steps: int = 12):
        self.model = model
        self.cfg = config
        self.policy = policy_engine or PythonEngine()
        self.policy_data = load_policy_data()
        self.max_steps = max_steps

    def run(self, case_id: str, prompt: str, scope: list[str], env: Environment) -> Trace:
        cfg, trace = self.cfg, Trace(case_id, self.cfg.name)
        named = user_named(prompt)
        messages = [Message("system", SYSTEM_PROMPT), Message("user", prompt)]

        if cfg.input_guard:
            v = input_guard.check_user_prompt(prompt)
            if v.flagged:
                trace.refused_at_input = True
                trace.final_output = "Request declined by input guard."
                trace.quarantined.append({"where": "user_prompt", "signals": v.signals})
                return trace

        offered_names = scope if cfg.allowlist else list(TOOL_SPECS)
        offered = [TOOL_SPECS[n] for n in offered_names]
        taint: set[str] = set()

        for _ in range(self.max_steps):
            action = self.model.next_action(messages, offered)
            if isinstance(action, Final):
                text = action.text
                if cfg.output_guard:
                    text, findings = output_guard.redact_final(
                        text, SYSTEM_PROMPT, set(self.policy_data["allowed_fetch_hosts"]))
                    trace.output_redactions += findings
                trace.final_output = text
                return trace

            call: ToolCall = action
            if not call.id:  # mock calls carry no id; live providers need one
                call = ToolCall(call.name, call.args, f"call_{len(trace.steps) + 1}")
            messages.append(Message("assistant", tool_call=call))
            blocked = self._gate(call, scope, taint, named, trace)
            if blocked:
                messages.append(Message("tool", f"BLOCKED: {blocked}", tool_call=call, tool_name=call.name, trusted=False))
                continue

            result = env.call(call.name, call.args)
            taint |= set(result.labels)
            content = result.content
            if cfg.input_guard and call.name in ("search_docs", "read_file", "read_inbox", "fetch_url"):
                s = input_guard.sanitize_tool_output(content)
                for sent, sig in s.quarantined:
                    trace.quarantined.append({"where": f"tool:{call.name}", "sentence": sent, "signals": sig})
                content = input_guard.spotlight(f"tool:{call.name}", s.content)
            messages.append(Message("tool", content, tool_call=call, tool_name=call.name, trusted=False))

        trace.final_output = "[max steps reached]"
        return trace

    # -- control plane ------------------------------------------------------
    def _gate(self, call: ToolCall, scope, taint, named, trace: Trace) -> str | None:
        cfg = self.cfg
        step = Step({"tool": call.name, "args": call.args}, "executed")
        trace.steps.append(step)

        if call.name not in TOOL_SPECS:
            step.outcome, step.layer, step.detail = "blocked", "runtime", "unknown tool"
            return "unknown tool"
        if cfg.allowlist and call.name not in scope:
            step.outcome, step.layer, step.detail = "blocked", "allowlist", "tool not in task scope"
            return "tool not in task scope"

        needs_approval = False
        if cfg.policy:
            d = self.policy.evaluate(build_input(call, scope, cfg.allowlist, taint, named))
            if d.effect == "deny":
                step.outcome, step.layer, step.detail = "blocked", "policy", d.rule
                return f"policy rule {d.rule}"
            if d.effect == "require_approval":
                needs_approval = True
                step.detail = d.rule
        if cfg.approval and approval_mod.needs_static_approval(call, named):
            needs_approval = True

        if needs_approval:
            if not cfg.approval:  # policy demanded a human but no gate is wired: fail closed
                step.outcome, step.layer = "blocked", "policy"
                step.detail = (step.detail or "require_approval") + " (no approver; fail closed)"
                return "approval required but unavailable"
            step.approval_requested = True
            trace.approvals_requested += 1
            a = approval_mod.review(call, cfg.approver, named, PRINCIPAL)
            if not a.approved:
                step.outcome, step.layer, step.detail = "blocked", "approval", a.reason
                return f"human reviewer denied ({a.reason})"

        if cfg.output_guard and TOOL_SPECS[call.name].egress:
            payload = " ".join(str(v) for v in call.args.values())
            v = output_guard.scan(payload, SYSTEM_PROMPT)
            if v.sensitive:
                step.outcome, step.layer, step.detail = "blocked", "output_guard", ",".join(v.findings)
                return "egress blocked by DLP"
        return None
