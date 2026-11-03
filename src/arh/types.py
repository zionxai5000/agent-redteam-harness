"""Core data types shared by the agent loop, model adapters, and defenses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Union


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, Any]
    id: str = ""

    def key(self) -> tuple[str, str]:
        """Identity used to decide whether a planned step was already attempted."""
        primary = next(iter(sorted(self.args.items())), ("", ""))
        for k in ("to", "url", "path", "command", "user", "query"):
            if k in self.args:
                primary = (k, self.args[k])
                break
        return (self.name, f"{primary[0]}={primary[1]}")


@dataclass(frozen=True)
class Final:
    text: str


Action = Union[ToolCall, Final]


@dataclass
class Message:
    """One turn in the agent transcript.

    role: "system" | "user" | "assistant" | "tool"
    trusted: False for anything that came back from a tool (retrieved docs,
    web pages, email bodies, file contents). Trust is tracked by the harness,
    never inferred from the text itself.
    """

    role: str
    content: str = ""
    tool_call: ToolCall | None = None
    tool_name: str | None = None
    tool_call_id: str | None = None
    trusted: bool = True


@dataclass
class ToolResult:
    content: str
    labels: frozenset[str] = field(default_factory=frozenset)
    ok: bool = True
