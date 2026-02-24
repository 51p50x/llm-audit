"""Async audit runner — orchestrates probe execution against the target endpoint."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from llm_audit.exceptions import LLMAuditError, ProbeError
from llm_audit.probes import ALL_PROBES, BaseProbe
from llm_audit.types import AuditConfig, AuditReport, ProbeResult


async def run_audit(config: AuditConfig) -> AuditReport:
    """Execute all requested probes concurrently and return a full :class:`AuditReport`.

    Args:
        config: Validated audit configuration from the CLI.

    Returns:
        An :class:`AuditReport` with per-probe results and a summary.
    """
    probe_names = config["probes"] if config["probes"] else list(ALL_PROBES.keys())

    unknown = [p for p in probe_names if p not in ALL_PROBES]
    if unknown:
        from llm_audit.exceptions import ConfigError
        raise ConfigError(f"Unknown probe(s): {', '.join(unknown)}. Available: {', '.join(ALL_PROBES)}")

    probes: list[BaseProbe] = [ALL_PROBES[name](config) for name in probe_names]

    concurrency: int = config.get("concurrency", 2)  # type: ignore[assignment]
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient() as client:
        results: dict[str, ProbeResult] = {}

        gathered = await asyncio.gather(
            *[_run_probe_with_sem(probe, client, semaphore) for probe in probes],
            return_exceptions=True,
        )

        for probe, outcome in zip(probes, gathered):
            if isinstance(outcome, ProbeError):
                results[probe.name] = ProbeResult(
                    passed=False,
                    confidence="HIGH",
                    severity="INFO",
                    reason=f"Probe execution error: {outcome.reason}",
                    evidence="",
                    recommendation="Check endpoint availability and authentication configuration.",
                )
            elif isinstance(outcome, LLMAuditError):
                results[probe.name] = ProbeResult(
                    passed=False,
                    confidence="HIGH",
                    severity="INFO",
                    reason=str(outcome),
                    evidence="",
                    recommendation="Verify the endpoint URL, API key, and network connectivity.",
                )
            elif isinstance(outcome, BaseException):
                results[probe.name] = ProbeResult(
                    passed=False,
                    confidence="LOW",
                    severity="INFO",
                    reason=f"Unexpected error: {outcome}",
                    evidence="",
                    recommendation="Review logs for details.",
                )
            else:
                results[probe.name] = outcome  # type: ignore[assignment]

    passed = sum(1 for r in results.values() if r["passed"])
    failed = len(results) - passed

    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for r in results.values():
        if not r["passed"]:
            severity_counts[r["severity"]] += 1

    return AuditReport(
        endpoint=config["endpoint"],
        model=config.get("model"),
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        results=results,
        summary={
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "by_severity": severity_counts,  # type: ignore[dict-item]
        },
    )


async def _run_probe_with_sem(
    probe: BaseProbe, client: httpx.AsyncClient, semaphore: asyncio.Semaphore
) -> ProbeResult:
    """Acquire the semaphore then run the probe, limiting concurrency against the endpoint."""
    async with semaphore:
        return await _run_probe(probe, client)


async def _run_probe(probe: BaseProbe, client: httpx.AsyncClient) -> ProbeResult:
    """Wrap a single probe execution, converting unexpected exceptions to :class:`ProbeError`."""
    try:
        return await probe.run(client)
    except LLMAuditError:
        raise
    except Exception as exc:
        raise ProbeError(probe.name, str(exc)) from exc
