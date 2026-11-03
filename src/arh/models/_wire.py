"""Shared helpers for live provider adapters."""

from __future__ import annotations

from ..env import ToolSpec
from ..types import Message


def json_schema(spec: ToolSpec) -> dict:
    return {
        "type": "object",
        "properties": {k: {"type": v} for k, v in spec.params.items()},
        "required": list(spec.params),
    }


def split_system(messages: list[Message]) -> tuple[str, list[Message]]:
    system = "\n".join(m.content for m in messages if m.role == "system")
    return system, [m for m in messages if m.role != "system"]
