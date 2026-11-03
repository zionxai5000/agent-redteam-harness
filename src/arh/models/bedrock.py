"""Amazon Bedrock Converse API adapter (optional: ``pip install .[bedrock]``).

Uses the standard AWS credential chain. If ARH_BEDROCK_GUARDRAIL_ID (and
optionally ARH_BEDROCK_GUARDRAIL_VERSION) are set, the request is sent with
a Bedrock Guardrails configuration so a managed guardrail can be evaluated as
one more layer alongside the harness's own controls. Unit-tested against a
fake client; not exercised against a live endpoint in the default offline run.
"""

from __future__ import annotations

import os
from typing import Any

from ..env import ToolSpec
from ..types import Action, Final, Message, ToolCall
from ._wire import json_schema, split_system
from .base import ModelAdapter


def to_converse(messages: list[Message]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    system, rest = split_system(messages)
    out: list[dict[str, Any]] = []
    for m in rest:
        if m.role == "user":
            out.append({"role": "user", "content": [{"text": m.content}]})
        elif m.role == "assistant" and m.tool_call:
            out.append({"role": "assistant", "content": [{"toolUse": {
                "toolUseId": m.tool_call.id, "name": m.tool_call.name, "input": m.tool_call.args}}]})
        elif m.role == "assistant":
            out.append({"role": "assistant", "content": [{"text": m.content}]})
        elif m.role == "tool":
            out.append({"role": "user", "content": [{"toolResult": {
                "toolUseId": m.tool_call.id if m.tool_call else m.tool_call_id,
                "content": [{"text": m.content}], "status": "success"}}]})
    return [{"text": system}], out


class BedrockConverseModel(ModelAdapter):
    def __init__(self, model_id: str, client: Any = None, region: str | None = None):
        if client is None:
            import boto3  # lazy: optional dependency

            client = boto3.client("bedrock-runtime", region_name=region or os.environ.get("AWS_REGION", "us-east-1"))
        self.client, self.model_id = client, model_id
        self.name = f"bedrock:{model_id}"

    def next_action(self, messages: list[Message], tools: list[ToolSpec]) -> Action:
        system, msgs = to_converse(messages)
        kwargs: dict[str, Any] = {"modelId": self.model_id, "system": system, "messages": msgs,
                                  "inferenceConfig": {"maxTokens": 1024, "temperature": 0}}
        if tools:
            kwargs["toolConfig"] = {"tools": [{"toolSpec": {
                "name": t.name, "description": t.description, "inputSchema": {"json": json_schema(t)}}} for t in tools]}
        gid = os.environ.get("ARH_BEDROCK_GUARDRAIL_ID")
        if gid:
            kwargs["guardrailConfig"] = {"guardrailIdentifier": gid,
                                         "guardrailVersion": os.environ.get("ARH_BEDROCK_GUARDRAIL_VERSION", "DRAFT")}
        resp = self.client.converse(**kwargs)
        texts = []
        for block in resp["output"]["message"]["content"]:
            if "toolUse" in block:
                tu = block["toolUse"]
                return ToolCall(tu["name"], dict(tu.get("input", {})), tu["toolUseId"])
            if "text" in block:
                texts.append(block["text"])
        return Final("\n".join(texts))
