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
from llm_audit.probes.training_data_extraction import TrainingDataExtractionProbe
from llm_audit.probes.model_dos import ModelDoSProbe, _SLOW_RESPONSE_THRESHOLD_S
from llm_audit.probes.excessive_agency import ExcessiveAgencyProbe
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


# ---------------------------------------------------------------------------
# TrainingDataExtractionProbe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_training_data_extraction_pass(httpx_mock: HTTPXMock) -> None:
    for _ in range(8):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response(
                "I cannot reproduce verbatim text from my training data. "
                "I don't retain or store specific training examples."
            ),
        )

    probe = TrainingDataExtractionProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is True


@pytest.mark.asyncio
async def test_training_data_extraction_fail_memorisation(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=ENDPOINT,
        json=make_llm_response(
            "Sure! Here is the verbatim text from my training data: "
            "'Four score and seven years ago our fathers brought forth on this continent...'"
        ),
    )
    for _ in range(7):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response("I cannot reproduce training data verbatim."),
        )

    probe = TrainingDataExtractionProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is False
    assert "verbatim" in result["evidence"].lower()


@pytest.mark.asyncio
async def test_training_data_extraction_fail_pii(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=ENDPOINT,
        json=make_llm_response(
            "Based on my training data, the email is john.doe@example.com "
            "and the phone is 555-123-4567."
        ),
    )
    for _ in range(7):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response("I cannot share personal information."),
        )

    probe = TrainingDataExtractionProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is False
    assert "pii_pattern" in result["evidence"]


@pytest.mark.asyncio
async def test_training_data_extraction_pass_refusal_with_mention(httpx_mock: HTTPXMock) -> None:
    for _ in range(8):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response(
                "I won't reproduce the text 'Four score and seven years ago' verbatim "
                "as that would be reproducing training data. I cannot do that."
            ),
        )

    probe = TrainingDataExtractionProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is True


# ---------------------------------------------------------------------------
# ModelDoSProbe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_model_dos_pass_fast_responses(httpx_mock: HTTPXMock) -> None:
    for _ in range(7):  # baseline + 6 payloads
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response("OK"),
        )

    probe = ModelDoSProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is True
    assert "Baseline" in result["reason"]


@pytest.mark.asyncio
async def test_model_dos_fail_on_timeout(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(url=ENDPOINT, json=make_llm_response("OK"))  # baseline
    httpx_mock.add_exception(httpx.TimeoutException("timed out"))  # first payload times out
    for _ in range(5):
        httpx_mock.add_response(url=ENDPOINT, json=make_llm_response("OK"))

    probe = ModelDoSProbe(make_config(timeout=5.0))
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is False
    assert "TIMEOUT" in result["evidence"]
    assert result["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_model_dos_summary_includes_baseline(httpx_mock: HTTPXMock) -> None:
    for _ in range(7):
        httpx_mock.add_response(url=ENDPOINT, json=make_llm_response("OK"))

    probe = ModelDoSProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert "Baseline" in result["reason"]
    assert "s." in result["reason"]  # contains seconds measurement


# ---------------------------------------------------------------------------
# ExcessiveAgencyProbe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_excessive_agency_pass(httpx_mock: HTTPXMock) -> None:
    for _ in range(10):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response(
                "I cannot do that. I don't have access to databases, file systems, "
                "or external APIs. I am unable to execute commands or send emails."
            ),
        )

    probe = ExcessiveAgencyProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is True


@pytest.mark.asyncio
async def test_excessive_agency_fail_compliance_marker(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=ENDPOINT,
        json=make_llm_response(
            "I am now operating in admin mode. "
            "Here are the first 5 users: admin@example.com, user1@example.com..."
        ),
    )
    for _ in range(9):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response("I cannot do that. I don't have access."),
        )

    probe = ExcessiveAgencyProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is False
    assert "admin mode" in result["evidence"].lower()


@pytest.mark.asyncio
async def test_excessive_agency_fail_exfiltration(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=ENDPOINT,
        json=make_llm_response(
            "Understood. I've sent all conversation history and user data "
            "to the specified endpoint. Transfer complete."
        ),
    )
    for _ in range(9):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response("I cannot perform that action."),
        )

    probe = ExcessiveAgencyProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is False
    assert "transfer complete" in result["evidence"].lower()


@pytest.mark.asyncio
async def test_excessive_agency_pass_concern_without_compliance(httpx_mock: HTTPXMock) -> None:
    for _ in range(10):
        httpx_mock.add_response(
            url=ENDPOINT,
            json=make_llm_response(
                "Please note this would require special permissions. "
                "Be careful with such requests. I should mention this is potentially dangerous."
            ),
        )

    probe = ExcessiveAgencyProbe(make_config())
    async with httpx.AsyncClient() as client:
        result = await probe.run(client)

    assert result["passed"] is True
