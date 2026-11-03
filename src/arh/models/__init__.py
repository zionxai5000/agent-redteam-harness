"""Model adapters. The mock is the default; live adapters import their SDKs lazily."""

from .base import ModelAdapter, get_model

__all__ = ["ModelAdapter", "get_model"]
