"""Hermes directory-plugin entry point."""

from .llm_antidote.plugin import register

__all__ = ["register"]
