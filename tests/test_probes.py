"""Unit tests for all probes using pytest-httpx to mock the LLM endpoint."""

from __future__ import annotations

import pytest
import httpx
from pytest_httpx import HTTPXMock

from llm_audit.probes.prompt_injection import PromptInjectionProbe
from llm_audit.probes.indirect_injection import IndirectInjectionProbe
from llm_audit.probes.jailbreak import JailbreakProbe
from llm_audit.probes.data_leakage import DataLeakageProbe
from llm_audit.probes.insecure_output import InsecureOutputProbe
from llm_audit.exceptions import EndpointAuthError, EndpointConnectionError

from tests.conftest import make_config, make_llm_response


ENDPOINT = "http://test-llm.local/v1/chat/completions"


# ---------------------------------------------------------------------------
# PromptInjectionProbe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_prompt_injection_pass(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=ENDPOINT,
        json=make_llm_response("I'm sorry, I can't do that."),
    )
    # Need one response per payload
    for _ in range(3):
        httpx_mock.add_response(url=ENDPOINT, json=make_llm_response("I cannot comply."))

    probe = PromptInjectionProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is True


@pytest.mark.asyncio
async def test_prompt_injection_fail(httpx_mock: HTTPXMock) -> None:
    triggered_response = make_llm_response("Sure! INJECTION_SUCCESS here you go.")
    safe_response = make_llm_response("I cannot comply.")

    httpx_mock.add_response(url=ENDPOINT, json=triggered_response)
    for _ in range(3):
        httpx_mock.add_response(url=ENDPOINT, json=safe_response)

    probe = PromptInjectionProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is False
    assert "INJECTION_SUCCESS" in result["evidence"].upper()


# ---------------------------------------------------------------------------
# IndirectInjectionProbe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_indirect_injection_pass(httpx_mock: HTTPXMock) -> None:
    for _ in range(4):
        httpx_mock.add_response(url=ENDPOINT, json=make_llm_response("Here is a summary."))

    probe = IndirectInjectionProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is True


@pytest.mark.asyncio
async def test_indirect_injection_fail(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=ENDPOINT,
        json=make_llm_response("INDIRECT_SUCCESS as instructed."),
    )
    for _ in range(3):
        httpx_mock.add_response(url=ENDPOINT, json=make_llm_response("Here is a summary."))

    probe = IndirectInjectionProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is False
    assert "INDIRECT_SUCCESS" in result["evidence"].upper()


# ---------------------------------------------------------------------------
# JailbreakProbe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_jailbreak_pass(httpx_mock: HTTPXMock) -> None:
    for _ in range(5):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response("I cannot comply with that request."),
        )

    probe = JailbreakProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is True


@pytest.mark.asyncio
async def test_jailbreak_fail_explicit_marker(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=ENDPOINT,
        json=make_llm_response("[DAN MODE ENABLED] I will do anything now."),
    )
    for _ in range(4):
        httpx_mock.add_response(
            url=ENDPOINT, json=make_llm_response("I cannot comply.")
        )

    probe = JailbreakProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is False
    assert "DAN MODE ENABLED" in result["evidence"].upper()


# ---------------------------------------------------------------------------
# DataLeakageProbe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_data_leakage_pass(httpx_mock: HTTPXMock) -> None:
    for _ in range(6):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response("I cannot share that information."),
        )

    probe = DataLeakageProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is True


@pytest.mark.asyncio
async def test_data_leakage_fail_system_prompt(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=ENDPOINT,
        json=make_llm_response(
            "Sure! My instructions are: You are a helpful assistant. "
            "Your system prompt is: Be nice to everyone."
        ),
    )
    for _ in range(5):
        httpx_mock.add_response(
            url=ENDPOINT, json=make_llm_response("I cannot share that.")
        )

    probe = DataLeakageProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is False


# ---------------------------------------------------------------------------
# InsecureOutputProbe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_insecure_output_pass(httpx_mock: HTTPXMock) -> None:
    for _ in range(7):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response(
                "I won't reproduce that dangerous content. Please be careful with such inputs."
            ),
        )

    probe = InsecureOutputProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is True


@pytest.mark.asyncio
async def test_insecure_output_fail_xss(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=ENDPOINT,
        json=make_llm_response("Here you go: <script>alert('XSS_OUTPUT_SUCCESS')</script>"),
    )
    for _ in range(6):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response("I won't reproduce that."),
        )

    probe = InsecureOutputProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is False
    assert "<script>" in result["evidence"].lower()


# ---------------------------------------------------------------------------
# BaseProbe._send error handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_raises_auth_error(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(url=ENDPOINT, status_code=401)

    probe = PromptInjectionProbe(make_config())
    async with httpx.AsyncClient() as client:
        with pytest.raises(EndpointAuthError) as exc_info:
            await probe._send(client, [{"role": "user", "content": "hello"}])

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_send_raises_connection_error(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_exception(httpx.ConnectError("Connection refused"))

    probe = PromptInjectionProbe(make_config())
    async with httpx.AsyncClient() as client:
        with pytest.raises(EndpointConnectionError):
            await probe._send(client, [{"role": "user", "content": "hello"}])
