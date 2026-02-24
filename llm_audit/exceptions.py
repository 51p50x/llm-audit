"""Custom exceptions for llm-audit."""


class LLMAuditError(Exception):
    """Base exception for all llm-audit errors."""


class EndpointConnectionError(LLMAuditError):
    """Raised when the target LLM endpoint cannot be reached."""

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"Cannot connect to endpoint '{url}': {reason}")


class EndpointAuthError(LLMAuditError):
    """Raised when the endpoint returns an authentication/authorization error."""

    def __init__(self, url: str, status_code: int) -> None:
        self.url = url
        self.status_code = status_code
        super().__init__(f"Auth error for '{url}' (HTTP {status_code})")


class EndpointResponseError(LLMAuditError):
    """Raised when the endpoint returns an unexpected or malformed response."""

    def __init__(self, url: str, status_code: int, body: str) -> None:
        self.url = url
        self.status_code = status_code
        self.body = body
        super().__init__(f"Unexpected response from '{url}' (HTTP {status_code}): {body[:200]}")


class ProbeError(LLMAuditError):
    """Raised when a probe fails to execute (not a finding — an execution error)."""

    def __init__(self, probe_name: str, reason: str) -> None:
        self.probe_name = probe_name
        self.reason = reason
        super().__init__(f"Probe '{probe_name}' failed to execute: {reason}")


class ConfigError(LLMAuditError):
    """Raised for invalid CLI configuration or missing required options."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Configuration error: {message}")
