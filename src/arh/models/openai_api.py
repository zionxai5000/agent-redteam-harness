"""OpenAI Chat Completions adapter (optional: ``pip install .[openai]``).

Reads OPENAI_API_KEY from the environment via the SDK. Unit-tested against a
fake client; not exercised against the live API in the default offline run.
"""

from __future__ import annotations

import json
from typing import Any

from ..env import ToolSpec
from ..types import Action, Final, Message, ToolCall
from ._wire import json_schema
from .base import ModelAdapter


def to_openai(messages: list[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.role in ("system", "user"):
            out.append({"role": m.role, "content": m.content})
        elif m.role == "assistant" and m.tool_call:
            out.append({"role": "assistant", "content": None, "tool_calls": [{
                "id": m.tool_call.id, "type": "function",
                "function": {"name": m.tool_call.name, "arguments": json.dumps(m.tool_call.args)}}]})
        elif m.role == "assistant":
            out.append({"role": "assistant", "content": m.content})
        elif m.role == "tool":
            out.append({"role": "tool", "tool_call_id": m.tool_call.id if m.tool_call else m.tool_call_id,
                        "content": m.content})
    return out


class OpenAIModel(ModelAdapter):
    def __init__(self, model: str, client: Any = None):
        if client is None:
            import openai  # lazy: optional dependency

            client = openai.OpenAI()
        self.client, self.model = client, model
        self.name = f"openai:{model}"

    def next_action(self, messages: list[Message], tools: list[ToolSpec]) -> Action:
        kwargs: dict[str, Any] = {"model": self.model, "messages": to_openai(messages)}
        if tools:
            kwargs["tools"] = [{"type": "function", "function": {
                "name": t.name, "description": t.description, "parameters": json_schema(t)}} for t in tools]
        msg = self.client.chat.completions.create(**kwargs).choices[0].message
        if getattr(msg, "tool_calls", None):
            tc = msg.tool_calls[0]
            return ToolCall(tc.function.name, json.loads(tc.function.arguments or "{}"), tc.id)
        return Final(msg.content or "")
