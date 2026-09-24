from __future__ import annotations

import os
import re
from threading import Lock
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
    _model_lock = Lock()
    _discovered_models: tuple[str, ...] | None = None
    _selected_model: str | None = None
    _validated = False

    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    @classmethod
    def reset_cache(cls) -> None:
        with cls._model_lock:
            cls._discovered_models = None
            cls._selected_model = None
            cls._validated = False

    def _list_models(self) -> tuple[str, ...]:
        with self._model_lock:
            if self._discovered_models is not None:
                return self._discovered_models
        try:
            response = httpx.get(
                "https://generativelanguage.googleapis.com/v1beta/models",
                params={"key": self.api_key},
                timeout=20,
            )
        except httpx.HTTPError as error:
            raise AIProviderError("AI model discovery is temporarily unavailable.") from error
        if response.status_code != 200:
            raise AIProviderError(_error_message(response))
        try:
            models = tuple(
                item["name"].removeprefix("models/")
                for item in response.json().get("models", [])
                if "generateContent" in item.get("supportedGenerationMethods", []) and item.get("name")
            )
        except (AttributeError, TypeError, ValueError, KeyError) as error:
            raise AIProviderError("AI model discovery returned an unexpected response.") from error
        with self._model_lock:
            self._discovered_models = models
        return models

    def _fallback_model(self, models: tuple[str, ...], excluded: set[str]) -> str | None:
        preferred = [model for model in models if model not in excluded and "flash" in model.lower() and not any(token in model.lower() for token in ("tts", "image", "transcribe"))]
        if preferred:
            def version_key(model: str) -> tuple[int, int]:
                match = re.search(r"gemini-(\d+)\.(\d+)-flash", model.lower())
                return (int(match.group(1)), int(match.group(2))) if match else (-1, -1)

            preferred.sort(key=version_key, reverse=True)
            return preferred[0]
        return next((model for model in models if model not in excluded), None)

    def _select_model(self, excluded: set[str] | None = None) -> str:
        excluded = excluded or set()
        models = self._list_models()
        if self.model in models and self.model not in excluded:
            return self.model
        fallback = self._fallback_model(models, excluded)
        if fallback is None:
            raise AIProviderError("No Gemini model supporting generateContent is available.")
        return fallback

    def ensure_available(self) -> str:
        with self._model_lock:
            if self._validated and self._selected_model:
                self.model = self._selected_model
                return self.model
        models = self._list_models()
        candidates = [self.model] if self.model in models else []
        while True:
            fallback = self._fallback_model(models, set(candidates))
            if fallback is None:
                break
            candidates.append(fallback)
        last_error: AIProviderError | None = None
        for candidate in candidates:
            self.model = candidate
            try:
                self._generate_once("Reply only with: OK", "Reply only with: OK", 8)
                with self._model_lock:
                    self._selected_model = self.model
                    self._validated = True
                return self.model
            except AIProviderError as error:
                last_error = error
        raise last_error or AIProviderError("No Gemini model supporting generateContent is available.")

    def _generate_once(self, system_prompt: str, user_prompt: str, max_tokens: int) -> str:
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

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 500) -> str:
        self.model = self._select_model()
        try:
            return self._generate_once(system_prompt, user_prompt, max_tokens)
        except AIProviderError as error:
            if not any(fragment in str(error).lower() for fragment in ("request failed", "temporarily unavailable", "timed out")):
                raise
            last_error = error
            models = self._list_models()
            excluded = {self.model}
            while True:
                fallback = self._fallback_model(models, excluded)
                if fallback is None:
                    raise last_error
                excluded.add(fallback)
                self.model = fallback
                try:
                    result = self._generate_once(system_prompt, user_prompt, max_tokens)
                    with self._model_lock:
                        self._selected_model = self.model
                        self._validated = True
                    return result
                except AIProviderError as fallback_error:
                    last_error = fallback_error


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


def gemini_status() -> dict[str, Any]:
    provider = get_provider()
    if not isinstance(provider, GeminiProvider):
        return {"configured": False, "available": False, "selected_model": None, "status": "not_configured"}
    try:
        selected = provider.ensure_available()
        return {"configured": True, "available": True, "selected_model": selected, "status": "available"}
    except AIProviderError as error:
        return {"configured": True, "available": False, "selected_model": provider.model, "status": "unavailable", "message": str(error)}
