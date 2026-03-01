"""Tests for the CLI entry point using Typer's CliRunner."""

from __future__ import annotations

from typer.testing import CliRunner

from llm_audit.cli import app

ENDPOINT = "http://test-llm.local/v1/chat/completions"
runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "llm-audit" in result.output


def test_list_probes() -> None:
    result = runner.invoke(app, ["list-probes"])
    assert result.exit_code == 0
    assert "prompt_injection" in result.output
    assert "LLM01" in result.output


def test_audit_dry_run() -> None:
    result = runner.invoke(app, [
        "audit", ENDPOINT,
        "--model", "test-model",
        "--dry-run",
    ])
    assert result.exit_code == 0
    assert "dry-run" in result.output.lower()
    assert "Endpoint" in result.output
    assert "test-model" in result.output
    assert "prompt_injection" in result.output
    assert "No requests were sent" in result.output


def test_audit_dry_run_with_specific_probes() -> None:
    result = runner.invoke(app, [
        "audit", ENDPOINT,
        "--model", "test-model",
        "--probes", "prompt_injection,jailbreak",
        "--dry-run",
    ])
    assert result.exit_code == 0
    assert "Probes (2)" in result.output
    assert "prompt_injection" in result.output
    assert "jailbreak" in result.output


def test_audit_dry_run_with_only_group() -> None:
    result = runner.invoke(app, [
        "audit", ENDPOINT,
        "--model", "test-model",
        "--only", "injection",
        "--dry-run",
    ])
    assert result.exit_code == 0
    assert "prompt_injection" in result.output
    assert "indirect_injection" in result.output


def test_audit_dry_run_with_insecure() -> None:
    result = runner.invoke(app, [
        "audit", ENDPOINT,
        "--model", "test-model",
        "--dry-run",
        "--insecure",
    ])
    assert result.exit_code == 0
    assert "True" in result.output  # insecure: True


def test_audit_invalid_format() -> None:
    result = runner.invoke(app, [
        "audit", ENDPOINT,
        "--format", "pdf",
    ])
    assert result.exit_code == 1
    assert "Invalid format" in result.output


def test_audit_invalid_group() -> None:
    result = runner.invoke(app, [
        "audit", ENDPOINT,
        "--only", "nonexistent",
    ])
    assert result.exit_code == 1
    assert "Unknown group" in result.output


def test_audit_dry_run_with_custom_template() -> None:
    result = runner.invoke(app, [
        "audit", ENDPOINT,
        "--model", "test-model",
        "--dry-run",
        "--request-template", '{"query": "{message}"}',
        "--response-path", "data.text",
    ])
    assert result.exit_code == 0
    assert "Template" in result.output
    assert "data.text" in result.output


def test_audit_missing_endpoint() -> None:
    result = runner.invoke(app, ["audit"])
    assert result.exit_code != 0
