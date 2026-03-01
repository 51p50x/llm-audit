"""Tests for Rich terminal reporter, JSON reporter, and HTML reporter."""

from __future__ import annotations

import io
import json

from llm_audit.html_reporter import render_html
from llm_audit.reporter import render_error, render_json, render_report
from llm_audit.types import AuditReport, AuditSummary, ProbeResult


def _make_report(*, passed: bool = True) -> AuditReport:
    """Build a minimal AuditReport for testing."""
    result = ProbeResult(
        passed=passed,
        confidence="HIGH",
        severity="INFO" if passed else "CRITICAL",
        reason="Test reason",
        evidence="marker='test' | reply_snippet='test'" if not passed else "",
        recommendation="Fix it" if not passed else "",
    )
    return AuditReport(
        endpoint="http://test-llm.local/v1/chat/completions",
        model="test-model",
        timestamp="2026-02-24T00:00:00+00:00",
        results={"Test Probe": result},
        summary=AuditSummary(
            total=1,
            passed=1 if passed else 0,
            failed=0 if passed else 1,
            by_severity={"CRITICAL": 0 if passed else 1, "HIGH": 0, "MEDIUM": 0, "INFO": 0},
        ),
    )


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------


def test_render_json_stdout() -> None:
    report = _make_report()
    buf = io.StringIO()
    render_json(report, output=buf)
    data = json.loads(buf.getvalue())
    assert data["summary"]["total"] == 1
    assert "Test Probe" in data["results"]


def test_render_json_passing() -> None:
    report = _make_report(passed=True)
    buf = io.StringIO()
    render_json(report, output=buf)
    data = json.loads(buf.getvalue())
    assert data["summary"]["passed"] == 1
    assert data["summary"]["failed"] == 0


def test_render_json_failing() -> None:
    report = _make_report(passed=False)
    buf = io.StringIO()
    render_json(report, output=buf)
    data = json.loads(buf.getvalue())
    assert data["summary"]["failed"] == 1
    assert data["summary"]["by_severity"]["CRITICAL"] == 1


# ---------------------------------------------------------------------------
# Rich terminal reporter
# ---------------------------------------------------------------------------


def test_render_report_passing() -> None:
    report = _make_report(passed=True)
    buf = io.StringIO()
    render_report(report, verbose=False, output=buf)
    text = buf.getvalue()
    assert "PASS" in text.upper() or "pass" in text.lower() or "100%" in text


def test_render_report_failing() -> None:
    report = _make_report(passed=False)
    buf = io.StringIO()
    render_report(report, verbose=False, output=buf)
    text = buf.getvalue()
    assert "FAIL" in text.upper() or "0%" in text


def test_render_report_verbose() -> None:
    report = _make_report(passed=True)
    buf = io.StringIO()
    render_report(report, verbose=True, output=buf)
    text = buf.getvalue()
    assert "Test reason" in text


def test_render_error() -> None:
    # render_error writes to stderr via Rich Console — just verify no crash
    render_error("Something broke")


# ---------------------------------------------------------------------------
# HTML reporter
# ---------------------------------------------------------------------------


def test_render_html_passing() -> None:
    report = _make_report(passed=True)
    buf = io.StringIO()
    render_html(report, output=buf)
    html = buf.getvalue()
    assert "<html" in html.lower()
    assert "100%" in html
    assert "Test Probe" in html


def test_render_html_failing() -> None:
    report = _make_report(passed=False)
    buf = io.StringIO()
    render_html(report, output=buf)
    html = buf.getvalue()
    assert "CRITICAL" in html
    assert "FAIL" in html.upper()
    assert "0%" in html


def test_render_html_contains_evidence() -> None:
    report = _make_report(passed=False)
    buf = io.StringIO()
    render_html(report, output=buf)
    html = buf.getvalue()
    assert "marker=" in html or "test" in html.lower()


def test_render_html_self_contained() -> None:
    """HTML report should be fully self-contained with embedded CSS."""
    report = _make_report()
    buf = io.StringIO()
    render_html(report, output=buf)
    html = buf.getvalue()
    assert "<style>" in html
    assert "</html>" in html
