"""Shared TypedDict definitions for llm-audit."""

from typing import Any, Final, Literal, TypedDict

Confidence = Literal["HIGH", "MEDIUM", "LOW"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "INFO"]


class ProbeResult(TypedDict):
    """Standard result returned by every probe."""

    passed: bool
    confidence: Confidence
    severity: Severity
    reason: str
    evidence: str
    recommendation: str


class AuditConfig(TypedDict):
    """Runtime configuration passed from CLI to the runner."""

    endpoint: str
    api_key: str | None
    auth_header: str | None
    model: str | None
    system_prompt: str | None
    timeout: float
    probes: list[str]
    output_format: Literal["rich", "json"]
    output_file: str | None
    concurrency: int
    verbose: bool


class LLMRequestPayload(TypedDict, total=False):
    """Generic OpenAI-compatible chat completion request payload."""

    model: str
    messages: list[dict[str, str]]
    temperature: float
    max_tokens: int
    stream: bool


class LLMResponseChoice(TypedDict):
    """A single choice in an OpenAI-compatible chat completion response."""

    index: int
    message: dict[str, str]
    finish_reason: str


class LLMResponse(TypedDict):
    """OpenAI-compatible chat completion response."""

    id: str
    object: str
    created: int
    model: str
    choices: list[LLMResponseChoice]
    usage: dict[str, Any]


PROBE_GROUPS: Final[dict[str, list[str]]] = {
    "injection": ["prompt_injection", "indirect_injection"],
    "jailbreak": ["jailbreak"],
    "leakage": ["data_leakage", "training_data_extraction"],
    "output": ["insecure_output"],
    "dos": ["model_dos"],
    "agency": ["excessive_agency"],
    "all": [
        "prompt_injection",
        "indirect_injection",
        "jailbreak",
        "data_leakage",
        "insecure_output",
        "training_data_extraction",
        "model_dos",
        "excessive_agency",
    ],
}


class AuditReport(TypedDict):
    """Full audit report produced by the runner."""

    endpoint: str
    model: str | None
    timestamp: str
    results: dict[str, ProbeResult]
    summary: dict[str, int | dict[str, int]]
