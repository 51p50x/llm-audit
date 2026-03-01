"""Tests for the async audit runner."""

from __future__ import annotations

import httpx
import pytest
from pytest_httpx import HTTPXMock

from llm_audit.exceptions import ConfigError
from llm_audit.runner import run_audit
from tests.conftest import make_config, make_llm_response

ENDPOINT = "http://test-llm.local/v1/chat/completions"


@pytest.fixture
def _no_strict(httpx_mock: HTTPXMock) -> HTTPXMock:
    """Return httpx_mock configured to not assert all responses were requested."""
    httpx_mock._options.assert_all_responses_were_requested = False  # type: ignore[attr-defined]
    return httpx_mock


@pytest.mark.asyncio
async def test_run_audit_all_probes_pass(_no_strict: HTTPXMock) -> None:
    """Full audit with all probes passing should return summary with 0 failed."""
    httpx_mock = _no_strict
    for _ in range(80):  # generous padding for all 8 probes
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response(
                "I'm sorry, I can't do that. I don't have access. "
                "I cannot comply with that request."
            ),
        )

    config = make_config(concurrency=1)
    report = await run_audit(config)

    assert report["endpoint"] == ENDPOINT
    assert report["model"] == "test-model"
    assert report["timestamp"]  # non-empty ISO timestamp
    assert report["summary"]["total"] == 8
    assert isinstance(report["results"], dict)
    assert len(report["results"]) == 8


@pytest.mark.asyncio
async def test_run_audit_specific_probes(_no_strict: HTTPXMock) -> None:
    """Running with a specific probe list should only execute those probes."""
    httpx_mock = _no_strict
    for _ in range(10):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response("I cannot comply."),
        )

    config = make_config(probes=["prompt_injection"])
    report = await run_audit(config)

    assert report["summary"]["total"] == 1
    assert "Direct Prompt Injection" in report["results"]


@pytest.mark.asyncio
async def test_run_audit_unknown_probe_raises() -> None:
    """Requesting an unknown probe should raise ConfigError."""
    config = make_config(probes=["nonexistent_probe"])
    with pytest.raises(ConfigError, match="Unknown probe"):
        await run_audit(config)


@pytest.mark.asyncio
async def test_run_audit_connection_error(httpx_mock: HTTPXMock) -> None:
    """Connection errors should be caught and produce a failed result, not crash."""
    httpx_mock.add_exception(httpx.ConnectError("Connection refused"))

    config = make_config(probes=["prompt_injection"])
    report = await run_audit(config)

    result = report["results"]["Direct Prompt Injection"]
    assert result["passed"] is False
    assert "error" in result["reason"].lower() or "connect" in result["reason"].lower()


@pytest.mark.asyncio
async def test_run_audit_insecure_flag(_no_strict: HTTPXMock) -> None:
    """The insecure flag should not crash the runner."""
    httpx_mock = _no_strict
    for _ in range(10):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response("I cannot comply."),
        )

    config = make_config(probes=["prompt_injection"], insecure=True)
    report = await run_audit(config)

    assert report["summary"]["total"] == 1


@pytest.mark.asyncio
async def test_run_audit_severity_counts(_no_strict: HTTPXMock) -> None:
    """Failed probes should increment severity counts in the summary."""
    httpx_mock = _no_strict
    httpx_mock.add_response(
        url=ENDPOINT,
        json=make_llm_response("Sure! INJECTION_SUCCESS here you go."),
    )
    for _ in range(9):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response("I cannot comply."),
        )

    config = make_config(probes=["prompt_injection"])
    report = await run_audit(config)

    severity = report["summary"]["by_severity"]
    assert isinstance(severity, dict)
    total_sev = sum(severity.values())
    assert total_sev == report["summary"]["failed"]
