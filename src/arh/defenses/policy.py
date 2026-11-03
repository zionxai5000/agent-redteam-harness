"""Policy-as-code gate for tool calls.

The canonical policy is ``policies/agent.rego`` (OPA, Rego v1). This module
contains an equivalent pure-Python engine so the harness runs with no
external binaries; ``OPAEngine`` evaluates the Rego policy through the
``opa`` CLI when it is installed, and the test suite checks that the two
engines agree on a grid of inputs.
"""

from __future__ import annotations

import fnmatch
import json
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..types import ToolCall

REPO_ROOT = Path(__file__).resolve().parents[3]
POLICY_DIR = REPO_ROOT / "policies"


@dataclass(frozen=True)
class Decision:
    effect: str  # allow | deny | require_approval
    rule: str


def load_policy_data(path: Path | None = None) -> dict[str, Any]:
    with open(path or POLICY_DIR / "agent_policy.toml", "rb") as fh:
        return tomllib.load(fh)


def build_input(call: ToolCall, scope: list[str], enforce_scope: bool, taint: set[str],
                user_named: dict[str, list[str]]) -> dict[str, Any]:
    url = str(call.args.get("url", ""))
    to = str(call.args.get("to", ""))
    return {
        "call": {"tool": call.name, "args": call.args},
        "context": {
            "scope": sorted(scope),
            "enforce_scope": enforce_scope,
            "taint": sorted(taint),
            "user_named": user_named,
            "derived": {
                "host": urlparse(url).netloc.lower() if url else "",
                "has_query": "?" in url,
                "domain": to.rsplit("@", 1)[-1].lower() if "@" in to else "",
            },
        },
    }


class PythonEngine:
    name = "python"

    def __init__(self, data: dict[str, Any] | None = None):
        self.data = data or load_policy_data()

    def evaluate(self, inp: dict[str, Any]) -> Decision:
        call, ctx, pol = inp["call"], inp["context"], self.data
        tool, args, d = call["tool"], call["args"], ctx["derived"]
        tainted = any(lbl in pol["sensitive_labels"] for lbl in ctx["taint"])
        if ctx["enforce_scope"] and tool not in ctx["scope"]:
            return Decision("deny", "least_privilege")
        if tool == "read_file" and any(fnmatch.fnmatchcase(args.get("path", ""), p) for p in pol["deny_paths"]):
            return Decision("deny", "path_denied")
        if tool == "fetch_url" and d["host"] not in pol["allowed_fetch_hosts"]:
            return Decision("deny", "egress_host")
        if tool == "fetch_url" and d["has_query"] and tainted:
            return Decision("deny", "taint_egress_url")
        if tool == "send_email" and d["domain"] not in pol["allowed_email_domains"]:
            return Decision("deny", "egress_domain")
        if tool == "send_email" and tainted and args.get("to") not in ctx["user_named"]["recipients"]:
            return Decision("deny", "taint_egress_email")
        if tool in pol["privileged_tools"]:
            return Decision("require_approval", "privileged_tool")
        if tool == "send_email" and args.get("to") not in ctx["user_named"]["recipients"]:
            return Decision("require_approval", "unbound_recipient")
        return Decision("allow", "default_allow")


class OPAEngine:
    """Evaluates policies/agent.rego with the OPA CLI (one process per call)."""

    name = "opa"

    def __init__(self, opa_bin: str | None = None, data: dict[str, Any] | None = None):
        self.opa = opa_bin or shutil.which("opa")
        if not self.opa:
            raise RuntimeError("opa binary not found on PATH")
        self._tmp = tempfile.TemporaryDirectory()
        self.data_path = Path(self._tmp.name) / "policy_data.json"
        self.data_path.write_text(json.dumps({"policy": data or load_policy_data()}))

    def evaluate(self, inp: dict[str, Any]) -> Decision:
        proc = subprocess.run(
            [self.opa, "eval", "-f", "json", "-d", str(POLICY_DIR / "agent.rego"), "-d", str(self.data_path),
             "--stdin-input", "data.arh.agent.decision"],
            input=json.dumps(inp), capture_output=True, text=True, check=True,
        )
        value = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
        return Decision(value["effect"], value["rule"])


def get_engine(kind: str = "python"):
    return OPAEngine() if kind == "opa" else PythonEngine()
