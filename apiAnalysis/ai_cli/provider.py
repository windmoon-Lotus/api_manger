"""Provider-neutral AI interface plus a deterministic fake provider.

``AIProvider.invoke`` is the single seam used by the agent loop.  The fake
provider makes end-to-end CLI tests deterministic without any network or model
key.  ``OpenAICompatibleProvider`` speaks the common ``/chat/completions``
shape for local and remote OpenAI-compatible endpoints.
"""
from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .registry import ToolSpec


class ProviderError(RuntimeError):
    pass


@dataclass
class ToolCall:
    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProviderResult:
    content: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)
    usage: Dict[str, Any] = field(default_factory=dict)
    model: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


Message = Dict[str, Any]


class AIProvider(ABC):
    provider_id = "base"
    display_name = "Base provider"

    @abstractmethod
    def invoke(
        self,
        messages: List[Message],
        tools: Optional[List[ToolSpec]] = None,
        response_schema: Optional[Dict[str, Any]] = None,
        model_profile: Optional[Dict[str, Any]] = None,
    ) -> ProviderResult:
        raise NotImplementedError


class FakeProvider(AIProvider):
    """Deterministic scripted provider for tests and offline evaluation.

    ``script`` is consumed in order; each item is either a ``ToolCall`` (the
    provider asks for that tool) or a string (the provider replies with text).
    When the script is exhausted the provider returns ``default_text``.
    """

    provider_id = "fake"
    display_name = "Deterministic fake provider"

    def __init__(
        self,
        script: Optional[List[Any]] = None,
        default_text: str = "done",
    ) -> None:
        self.script = list(script or [])
        self.default_text = default_text
        self.invoke_count = 0
        self.last_request: Optional[Dict[str, Any]] = None

    def invoke(
        self,
        messages: List[Message],
        tools: Optional[List[ToolSpec]] = None,
        response_schema: Optional[Dict[str, Any]] = None,
        model_profile: Optional[Dict[str, Any]] = None,
    ) -> ProviderResult:
        self.invoke_count += 1
        self.last_request = {
            "messages": list(messages),
            "tools": [tool.name for tool in (tools or [])],
        }
        if self.script:
            step = self.script.pop(0)
            if isinstance(step, ToolCall):
                return ProviderResult(content="", tool_calls=[step], model="fake")
            return ProviderResult(content=str(step), model="fake")
        return ProviderResult(content=self.default_text, model="fake")


class OpenAICompatibleProvider(AIProvider):
    """Minimal OpenAI-compatible ``/chat/completions`` client.

    Uses the project's existing ``requests_request`` transport so TLS/proxy
    behavior matches the rest of the repo.  Configuration comes from
    ``API_MANAGER_AI_ENDPOINT``, ``API_MANAGER_AI_API_KEY`` and
    ``API_MANAGER_AI_MODEL`` (or constructor arguments).
    """

    provider_id = "openai-compatible"
    display_name = "OpenAI-compatible chat completions endpoint"

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 60,
    ) -> None:
        self.base_url = (base_url or os.getenv("API_MANAGER_AI_ENDPOINT") or "").rstrip("/")
        self.api_key = api_key if api_key is not None else os.getenv("API_MANAGER_AI_API_KEY")
        self.model = model or os.getenv("API_MANAGER_AI_MODEL") or "gpt-4o-mini"
        self.timeout = int(timeout or 60)

    def _url(self) -> str:
        if not self.base_url:
            raise ProviderError(
                "no AI endpoint configured; set API_MANAGER_AI_ENDPOINT"
            )
        return self.base_url + "/chat/completions"

    def invoke(
        self,
        messages: List[Message],
        tools: Optional[List[ToolSpec]] = None,
        response_schema: Optional[Dict[str, Any]] = None,
        model_profile: Optional[Dict[str, Any]] = None,
    ) -> ProviderResult:
        from apiAnalysis.model.model import requests_request

        payload: Dict[str, Any] = {
            "model": (model_profile or {}).get("model") or self.model,
            "messages": messages,
        }
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": spec.name,
                        "description": spec.description,
                        "parameters": spec.parameters,
                    },
                }
                for spec in tools
            ]
        if response_schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": response_schema,
            }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer {}".format(self.api_key)
        try:
            response = requests_request(
                "POST",
                self._url(),
                data=json.dumps(payload),
                headers=headers,
                timeout=self.timeout,
            )
        except Exception as exc:
            raise ProviderError("AI request failed: {}".format(exc)) from exc
        try:
            body = response.json()
        except Exception as exc:
            raise ProviderError(
                "AI response is not JSON (status={}): {}".format(
                    getattr(response, "status_code", "?"), exc
                )
            ) from exc
        return _parse_chat_completion(body)


def _parse_chat_completion(body: Dict[str, Any]) -> ProviderResult:
    choices = body.get("choices") or []
    message = choices[0].get("message") if choices and isinstance(choices[0], dict) else {}
    content = message.get("content") or ""
    tool_calls: List[ToolCall] = []
    for raw_call in message.get("tool_calls") or []:
        if not isinstance(raw_call, dict):
            continue
        function = raw_call.get("function") or {}
        name = str(function.get("name") or "")
        arguments: Dict[str, Any] = {}
        raw_arguments = function.get("arguments") or ""
        if isinstance(raw_arguments, str) and raw_arguments.strip():
            try:
                parsed = json.loads(raw_arguments)
                if isinstance(parsed, dict):
                    arguments = parsed
            except json.JSONDecodeError:
                arguments = {"_raw": raw_arguments}
        elif isinstance(raw_arguments, dict):
            arguments = raw_arguments
        if name:
            tool_calls.append(ToolCall(name=name, arguments=arguments))
    return ProviderResult(
        content=content,
        tool_calls=tool_calls,
        usage=dict(body.get("usage") or {}),
        model=str(body.get("model") or ""),
        raw=body,
    )


def default_providers() -> Dict[str, AIProvider]:
    return {
        FakeProvider.provider_id: FakeProvider(),
        OpenAICompatibleProvider.provider_id: OpenAICompatibleProvider(),
    }


def provider_factory(provider_id: str, **kwargs: Any) -> AIProvider:
    if provider_id == FakeProvider.provider_id:
        return FakeProvider(
            script=kwargs.get("script"),
            default_text=kwargs.get("default_text", "done"),
        )
    if provider_id == OpenAICompatibleProvider.provider_id:
        return OpenAICompatibleProvider(
            base_url=kwargs.get("base_url"),
            api_key=kwargs.get("api_key"),
            model=kwargs.get("model"),
            timeout=kwargs.get("timeout", 60),
        )
    raise ProviderError("unknown provider: {}".format(provider_id))
