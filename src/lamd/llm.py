"""Async OpenAI-compatible client used by the reproducible LAMD pipeline."""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Protocol

import openai
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)


class LLMClient(Protocol):
    """Small interface that makes the analysis pipeline independently testable."""

    model: str

    async def complete(self, prompt: str, *, json_mode: bool = False) -> str:
        """Complete one prompt."""

    def usage(self) -> dict[str, int]:
        """Return cumulative token counts."""


class PromptTooLongError(ValueError):
    """Raised before a request when its prompt exceeds the configured budget."""


@dataclass(frozen=True)
class OpenAIConfig:
    """Configuration for the paper's GPT-4o-mini backend."""

    model: str = "gpt-4o-mini-2024-07-18"
    base_url: str | None = None
    timeout_seconds: float = 120.0
    max_concurrency: int = 5
    min_request_interval: float = 0.0
    max_input_tokens: int = 120_000
    max_attempts: int = 6


def parse_json_object(content: str) -> dict[str, Any]:
    """Parse a JSON object, tolerating Markdown fences from compatible APIs."""

    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("Expected the model to return a JSON object")
    return value


class OpenAIChatClient:
    """Rate-limited Chat Completions client with deterministic model settings."""

    def __init__(self, config: OpenAIConfig, api_key: str | None = None) -> None:
        key = api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Copy .env.example to .env or export the key."
            )
        if config.max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        if config.max_input_tokens < 1:
            raise ValueError("max_input_tokens must be positive")
        if config.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if config.min_request_interval < 0:
            raise ValueError("min_request_interval must be non-negative")
        if config.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")

        kwargs: dict[str, Any] = {
            "api_key": key,
            "timeout": config.timeout_seconds,
            "max_retries": 0,
        }
        if config.base_url:
            kwargs["base_url"] = config.base_url
        self._client = openai.AsyncOpenAI(**kwargs)
        self._config = config
        self.model = config.model
        self._semaphore = asyncio.Semaphore(config.max_concurrency)
        self._pacing_lock = asyncio.Lock()
        self._last_request_started = 0.0
        self._input_tokens = 0
        self._output_tokens = 0

    def _count_tokens(self, text: str) -> int:
        # A conservative local guard, not billing telemetry. Avoiding a model
        # tokenizer here prevents tiktoken from downloading an encoding table
        # at first use. Successful requests use the API's exact usage counts.
        return max(1, (len(text.encode("utf-8")) + 2) // 3)

    async def _pace(self) -> None:
        async with self._pacing_lock:
            elapsed = time.monotonic() - self._last_request_started
            delay = self._config.min_request_interval - elapsed
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_request_started = time.monotonic()

    async def complete(self, prompt: str, *, json_mode: bool = False) -> str:
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Prompt must be a non-empty string")
        estimated_tokens = self._count_tokens(prompt)
        if estimated_tokens > self._config.max_input_tokens:
            raise PromptTooLongError(
                f"Prompt has about {estimated_tokens:,} tokens, above the configured "
                f"limit of {self._config.max_input_tokens:,}. Reduce the graph context."
            )

        retryable = (
            openai.RateLimitError,
            openai.APIConnectionError,
            openai.APITimeoutError,
            openai.InternalServerError,
        )
        async for attempt in AsyncRetrying(
            wait=wait_random_exponential(min=1, max=60),
            stop=stop_after_attempt(self._config.max_attempts),
            retry=retry_if_exception_type(retryable),
            reraise=True,
        ):
            with attempt:
                async with self._semaphore:
                    await self._pace()
                    request: dict[str, Any] = {
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.0,
                    }
                    if json_mode:
                        request["response_format"] = {"type": "json_object"}
                    response = await self._client.chat.completions.create(**request)

        if not response.choices or not response.choices[0].message.content:
            raise RuntimeError("The model returned an empty response")
        content = response.choices[0].message.content
        if response.usage:
            self._input_tokens += response.usage.prompt_tokens
            self._output_tokens += response.usage.completion_tokens
        else:
            self._input_tokens += estimated_tokens
            self._output_tokens += self._count_tokens(content)
        return content

    def usage(self) -> dict[str, int]:
        return {
            "input_tokens": self._input_tokens,
            "output_tokens": self._output_tokens,
            "total_tokens": self._input_tokens + self._output_tokens,
        }

    async def close(self) -> None:
        await self._client.close()
