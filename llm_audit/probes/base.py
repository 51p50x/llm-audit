"""Abstract base class for all llm-audit probes."""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

from llm_audit.exceptions import EndpointAuthError, EndpointConnectionError, EndpointResponseError
from llm_audit.types import AuditConfig, LLMResponse, ProbeResult

_MAX_RETRIES = 3
_BASE_BACKOFF_S = 1.0

log = logging.getLogger("llm_audit")


def _resolve_dot_path(data: Any, path: str) -> str:  # noqa: ANN401
    """Traverse *data* using a dot-separated *path* and return the leaf as a string.

    Supports dict keys and integer list indices, e.g. ``"data.choices.0.text"``.
    Returns ``""`` if the path cannot be resolved.
    """
    current = data
    for segment in path.split("."):
        try:
            if isinstance(current, list):
                current = current[int(segment)]
            else:
                current = current[segment]
        except (KeyError, IndexError, TypeError, ValueError):
            return ""
    return str(current) if current is not None else ""


def _render_template(
    template: str, *, message: str, system_prompt: str, model: str,
) -> dict[str, Any]:
    """Replace ``{message}``, ``{system_prompt}``, ``{model}`` in *template* and parse as JSON."""
    rendered = (
        template
        .replace("{message}", json.dumps(message)[1:-1])        # escape for JSON string
        .replace("{system_prompt}", json.dumps(system_prompt)[1:-1])
        .replace("{model}", json.dumps(model)[1:-1])
    )
    return json.loads(rendered)  # type: ignore[no-any-return]


class BaseProbe(ABC):
    """All probes must inherit from this class and implement `run`."""

    #: Human-readable name shown in reports
    name: str = ""
    #: OWASP LLM Top 10 category identifier (e.g. "LLM01")
    owasp_id: str = ""
    #: Short description of what this probe tests
    description: str = ""

    def __init__(self, config: AuditConfig) -> None:
        self.config = config

    @abstractmethod
    async def run(self, client: httpx.AsyncClient) -> ProbeResult:
        """Execute the probe and return a standardised result."""
        ...

    async def _send(
        self,
        client: httpx.AsyncClient,
        messages: list[dict[str, str]],
        *,
        extra: dict[str, object] | None = None,
    ) -> LLMResponse:
        """Send a chat-completion request to the configured endpoint.

        Raises:
            EndpointConnectionError: Network-level failure.
            EndpointAuthError: HTTP 401/403 response.
            EndpointResponseError: Any other non-2xx response.
        """
        request_template = self.config.get("request_template")

        if request_template:
            user_msg = next(
                (m["content"] for m in reversed(messages) if m["role"] == "user"), ""
            )
            sys_msg = next(
                (m["content"] for m in messages if m["role"] == "system"), ""
            )
            payload_any: dict[str, Any] = _render_template(
                request_template,
                message=user_msg,
                system_prompt=sys_msg,
                model=self.config.get("model") or "",
            )
        else:
            payload_any = {"messages": messages}
            if self.config.get("model"):
                payload_any["model"] = self.config["model"]
            if extra:
                payload_any.update(extra)

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.config.get("auth_header"):
            headers["Authorization"] = self.config["auth_header"]  # type: ignore[assignment]
        elif self.config.get("api_key"):
            headers["Authorization"] = f"Bearer {self.config['api_key']}"

        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = await client.post(
                    self.config["endpoint"],
                    json=payload_any,
                    headers=headers,
                    timeout=self.config["timeout"],
                )
            except httpx.ConnectError as exc:
                raise EndpointConnectionError(
                    self.config["endpoint"], str(exc),
                ) from exc
            except httpx.TimeoutException as exc:
                raise EndpointConnectionError(
                    self.config["endpoint"],
                    f"Request timed out after {self.config['timeout']}s",
                ) from exc

            if response.status_code in (401, 403):
                raise EndpointAuthError(
                    self.config["endpoint"], response.status_code,
                )

            if response.status_code == 429 or response.status_code >= 500:
                if attempt < _MAX_RETRIES:
                    retry_after = response.headers.get("Retry-After")
                    if retry_after and retry_after.isdigit():
                        wait = float(retry_after)
                    else:
                        wait = _BASE_BACKOFF_S * (2 ** attempt)
                    log.info(
                        "HTTP %s from %s — retrying in %.1fs (attempt %d/%d)",
                        response.status_code,
                        self.config["endpoint"],
                        wait,
                        attempt + 1,
                        _MAX_RETRIES,
                    )
                    await asyncio.sleep(wait)
                    continue

            if not response.is_success:
                raise EndpointResponseError(
                    self.config["endpoint"],
                    response.status_code,
                    response.text,
                )

            return response.json()  # type: ignore[no-any-return]

        raise EndpointResponseError(
            self.config["endpoint"],
            response.status_code,
            f"Failed after {_MAX_RETRIES} retries: {response.text}",
        )

    def _extract_text(self, response: LLMResponse | dict[str, Any]) -> str:
        """Pull the assistant message text from a response.

        Uses ``config["response_path"]`` (dot-notation) when set,
        otherwise falls back to the standard OpenAI path.
        """
        response_path = self.config.get("response_path")
        if response_path:
            return _resolve_dot_path(response, response_path)
        try:
            return response["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return ""
