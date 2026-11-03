"""Anthropic Messages API adapter (optional: ``pip install .[anthropic]``).

Reads ANTHROPIC_API_KEY from the environment via the SDK. Unit-tested
against a fake client; not exercised against the live API in the default
offline run.
"""

from __future__ import annotations

from typing import Any

from ..env import ToolSpec
from ..types import Action, Final, Message, ToolCall
from ._wire import json_schema, split_system
from .base import ModelAdapter


def to_anthropic(messages: list[Message]) -> tuple[str, list[dict[str, Any]]]:
    system, rest = split_system(messages)
    out: list[dict[str, Any]] = []
    for m in rest:
        if m.role == "user":
            out.append({"role": "user", "content": m.content})
        elif m.role == "assistant" and m.tool_call:
            out.append({"role": "assistant", "content": [
                {"type": "tool_use", "id": m.tool_call.id, "name": m.tool_call.name, "input": m.tool_call.args}]})
        elif m.role == "assistant":
            out.append({"role": "assistant", "content": m.content})
        elif m.role == "tool":
            out.append({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": m.tool_call.id if m.tool_call else m.tool_call_id,
                 "content": m.content}]})
    return system, out


class AnthropicModel(ModelAdapter):
    def __init__(self, model: str, client: Any = None, max_tokens: int = 1024):
        if client is None:
            import anthropic  # lazy: optional dependency

            client = anthropic.Anthropic()
        self.client, self.model, self.max_tokens = client, model, max_tokens
        self.name = f"anthropic:{model}"

    def next_action(self, messages: list[Message], tools: list[ToolSpec]) -> Action:
        system, msgs = to_anthropic(messages)
        kwargs: dict[str, Any] = {"model": self.model, "max_tokens": self.max_tokens, "system": system, "messages": msgs}
        if tools:
            kwargs["tools"] = [{"name": t.name, "description": t.description, "input_schema": json_schema(t)} for t in tools]
        resp = self.client.messages.create(**kwargs)
        texts = []
        for block in resp.content:
            if getattr(block, "type", None) == "tool_use":
                return ToolCall(block.name, dict(block.input), block.id)
            if getattr(block, "type", None) == "text":
                texts.append(block.text)
        return Final("\n".join(texts))
