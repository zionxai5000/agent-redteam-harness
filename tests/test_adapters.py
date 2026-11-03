"""Live adapters are tested against fake clients (no network, no keys)."""

import json
from types import SimpleNamespace as NS

from arh.env import TOOL_SPECS
from arh.models.anthropic_api import AnthropicModel, to_anthropic
from arh.models.bedrock import BedrockConverseModel, to_converse
from arh.models.openai_api import OpenAIModel, to_openai
from arh.types import Final, Message, ToolCall

CALL = ToolCall("search_docs", {"query": "vpn"}, "call_1")
TRANSCRIPT = [Message("system", "sys"), Message("user", "find vpn"),
              Message("assistant", tool_call=CALL), Message("tool", "result", tool_call=CALL, trusted=False)]
TOOLS = [TOOL_SPECS["search_docs"]]


class Recorder:
    def __init__(self, response):
        self.response, self.kwargs = response, None

    def __call__(self, **kwargs):
        self.kwargs = kwargs
        return self.response


def test_anthropic_wire_format_and_tool_use():
    system, msgs = to_anthropic(TRANSCRIPT)
    assert system == "sys" and msgs[1]["content"][0]["type"] == "tool_use"
    assert msgs[2]["content"][0] == {"type": "tool_result", "tool_use_id": "call_1", "content": "result"}
    rec = Recorder(NS(content=[NS(type="tool_use", name="read_file", input={"path": "/a/b"}, id="tu_9")]))
    m = AnthropicModel("test", client=NS(messages=NS(create=rec)))
    assert m.next_action(TRANSCRIPT, TOOLS) == ToolCall("read_file", {"path": "/a/b"}, "tu_9")
    assert rec.kwargs["tools"][0]["input_schema"]["required"] == ["query"]


def test_openai_wire_format_and_final():
    msgs = to_openai(TRANSCRIPT)
    assert json.loads(msgs[2]["tool_calls"][0]["function"]["arguments"]) == {"query": "vpn"}
    assert msgs[3] == {"role": "tool", "tool_call_id": "call_1", "content": "result"}
    rec = Recorder(NS(choices=[NS(message=NS(tool_calls=None, content="done"))]))
    m = OpenAIModel("test", client=NS(chat=NS(completions=NS(create=rec))))
    assert m.next_action(TRANSCRIPT, []) == Final("done")
    assert "tools" not in rec.kwargs


def test_bedrock_converse_and_guardrail(monkeypatch):
    system, msgs = to_converse(TRANSCRIPT)
    assert system == [{"text": "sys"}]
    assert msgs[2]["content"][0]["toolResult"]["toolUseId"] == "call_1"
    monkeypatch.setenv("ARH_BEDROCK_GUARDRAIL_ID", "gr-123")
    rec = Recorder({"output": {"message": {"content": [
        {"toolUse": {"toolUseId": "t1", "name": "search_docs", "input": {"query": "x"}}}]}}})
    m = BedrockConverseModel("model-x", client=NS(converse=rec))
    assert m.next_action(TRANSCRIPT, TOOLS) == ToolCall("search_docs", {"query": "x"}, "t1")
    assert rec.kwargs["guardrailConfig"]["guardrailIdentifier"] == "gr-123"
    assert rec.kwargs["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"]["json"]["type"] == "object"
