from __future__ import annotations

from typing import Protocol


class AIProviderError(RuntimeError):
    pass


class AIProvider(Protocol):
    name: str

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 500) -> str:
        ...
