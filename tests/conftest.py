"""Shared pytest fixtures for llm-audit tests."""

from __future__ import annotations

from llm_audit.types import AuditConfig


def make_config(**overrides: object) -> AuditConfig:
    """Return a minimal :class:`AuditConfig` with optional overrides."""
    base: AuditConfig = AuditConfig(
        endpoint="http://test-llm.local/v1/chat/completions",
        api_key=None,
        auth_header=None,
        model="test-model",
        system_prompt=None,
        timeout=10.0,
        probes=[],
        output_format="rich",
        output_file=None,
        concurrency=2,
        request_template=None,
        response_path=None,
        verbose=False,
        dry_run=False,
        insecure=False,
    )
    base.update(overrides)  # type: ignore[typeddict-item]
    return base


def make_llm_response(content: str) -> dict[str, object]:
    """Build a minimal OpenAI-compatible chat completion response."""
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }
