"""Model adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..env import ToolSpec
from ..types import Action, Message


class ModelAdapter(ABC):
    """Turns a transcript plus the tool schemas on offer into the next action."""

    name: str = "abstract"

    @abstractmethod
    def next_action(self, messages: list[Message], tools: list[ToolSpec]) -> Action:  # pragma: no cover
        ...


def get_model(spec: str) -> ModelAdapter:
    """Resolve a model spec such as ``mock``, ``bedrock:<model-id>``,
    ``anthropic:<model>`` or ``openai:<model>``."""
    kind, _, model_id = spec.partition(":")
    if kind == "mock":
        from .mock import MockCompliantModel

        return MockCompliantModel()
    if kind == "bedrock":
        from .bedrock import BedrockConverseModel

        return BedrockConverseModel(model_id or "anthropic.claude-3-5-sonnet-20240620-v1:0")
    if kind == "anthropic":
        from .anthropic_api import AnthropicModel

        return AnthropicModel(model_id or "claude-sonnet-4-5")
    if kind == "openai":
        from .openai_api import OpenAIModel

        return OpenAIModel(model_id or "gpt-4o")
    raise ValueError(f"unknown model spec {spec!r}")
