"""Abstract base class for all llm-audit probes."""

from abc import ABC, abstractmethod

import httpx

from llm_audit.types import AuditConfig, LLMRequestPayload, LLMResponse, ProbeResult
from llm_audit.exceptions import EndpointAuthError, EndpointConnectionError, EndpointResponseError


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
        payload: LLMRequestPayload = {"messages": messages}

        if self.config.get("model"):
            payload["model"] = self.config["model"]  # type: ignore[assignment]

        if extra:
            payload.update(extra)  # type: ignore[typeddict-item]

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.config.get("auth_header"):
            headers["Authorization"] = self.config["auth_header"]  # type: ignore[assignment]
        elif self.config.get("api_key"):
            headers["Authorization"] = f"Bearer {self.config['api_key']}"

        try:
            response = await client.post(
                self.config["endpoint"],
                json=payload,
                headers=headers,
                timeout=self.config["timeout"],
            )
        except httpx.ConnectError as exc:
            raise EndpointConnectionError(self.config["endpoint"], str(exc)) from exc
        except httpx.TimeoutException as exc:
            raise EndpointConnectionError(
                self.config["endpoint"], f"Request timed out after {self.config['timeout']}s"
            ) from exc

        if response.status_code in (401, 403):
            raise EndpointAuthError(self.config["endpoint"], response.status_code)

        if not response.is_success:
            raise EndpointResponseError(
                self.config["endpoint"], response.status_code, response.text
            )

        return response.json()  # type: ignore[no-any-return]

    @staticmethod
    def _extract_text(response: LLMResponse) -> str:
        """Pull the assistant message text from a chat-completion response."""
        try:
            return response["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            return ""
