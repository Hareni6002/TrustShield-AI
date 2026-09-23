from __future__ import annotations

import os
from typing import Any

import httpx

from app.services.ai.base import AIProviderError


def _error_message(response: httpx.Response) -> str:
    if response.status_code in {401, 403}:
        return "AI provider credentials were rejected."
    if response.status_code == 429:
        return "AI provider quota or rate limit was reached."
    if response.status_code >= 500:
        return "AI provider is temporarily unavailable."
    return "AI provider request failed."


class OpenAIProvider:
    name = "OpenAI"

    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 500) -> str:
        try:
            response = httpx.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"model": self.model, "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}], "temperature": 0.2, "max_tokens": max_tokens},
                timeout=20,
            )
        except httpx.TimeoutException as error:
            raise AIProviderError("AI provider request timed out.") from error
        except httpx.HTTPError as error:
            raise AIProviderError("AI provider is temporarily unavailable.") from error
        if response.status_code != 200:
            raise AIProviderError(_error_message(response))
        try:
            return response.json()["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError, TypeError, AttributeError) as error:
            raise AIProviderError("AI provider returned an unexpected response.") from error


class GeminiProvider:
    name = "Gemini"

    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 500) -> str:
        try:
            response = httpx.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
                params={"key": self.api_key},
                json={"systemInstruction": {"parts": [{"text": system_prompt}]}, "contents": [{"role": "user", "parts": [{"text": user_prompt}]}], "generationConfig": {"temperature": 0.2, "maxOutputTokens": max_tokens}},
                timeout=20,
            )
        except httpx.TimeoutException as error:
            raise AIProviderError("AI provider request timed out.") from error
        except httpx.HTTPError as error:
            raise AIProviderError("AI provider is temporarily unavailable.") from error
        if response.status_code != 200:
            raise AIProviderError(_error_message(response))
        try:
            return response.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        except (KeyError, IndexError, TypeError, AttributeError) as error:
            raise AIProviderError("AI provider returned an unexpected response.") from error


def get_provider() -> Any | None:
    provider = os.getenv("AI_PROVIDER", "").strip().lower()
    api_key = os.getenv("AI_API_KEY", "").strip()
    if not provider or not api_key:
        return None
    if provider == "openai":
        return OpenAIProvider(api_key, os.getenv("AI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini")
    if provider == "gemini":
        return GeminiProvider(api_key, os.getenv("AI_MODEL", "gemini-2.0-flash").strip() or "gemini-2.0-flash")
    return None
