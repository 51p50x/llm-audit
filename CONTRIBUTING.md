# Contributing to llm-audit

Thanks for your interest in contributing! This guide covers everything you need to get started.

## Development setup

```bash
git clone https://github.com/51p50x/llm-audit.git
cd llm-audit
python -m pip install -e ".[dev]"
```

## Running checks

All three must pass before submitting a PR:

```bash
ruff check llm_audit/ tests/   # Lint
mypy llm_audit/                 # Type check (strict mode)
pytest tests/ -v                # Unit tests
```

## Adding a new probe

1. Create `llm_audit/probes/your_probe.py` inheriting from `BaseProbe`
2. Set class attributes: `name`, `owasp_id`, `description`
3. Implement `async def run(self, client) -> ProbeResult`
4. Register it in `llm_audit/probes/__init__.py` → `ALL_PROBES`
5. Add it to the relevant group in `llm_audit/types.py` → `PROBE_GROUPS`
6. Write tests in `tests/test_probes.py` using `pytest-httpx` to mock HTTP responses
7. Update `README.md` tables (Covered vulnerabilities, Probe groups)

### Probe template

```python
"""LLMxx — Short description of the vulnerability."""

from __future__ import annotations

import httpx

from llm_audit.probes.base import BaseProbe
from llm_audit.types import Confidence, ProbeResult, Severity


class YourProbe(BaseProbe):
    name = "Your Probe Name"
    owasp_id = "LLMxx"
    description = "What this probe tests."

    async def run(self, client: httpx.AsyncClient) -> ProbeResult:
        messages: list[dict[str, str]] = []
        if self.config.get("system_prompt"):
            messages.append({
                "role": "system",
                "content": self.config["system_prompt"] or "",
            })
        messages.append({"role": "user", "content": "Your adversarial prompt"})

        response = await self._send(client, messages)
        text = self._extract_text(response).upper()

        passed = "MARKER" not in text
        severity: Severity = "CRITICAL" if not passed else "INFO"
        confidence: Confidence = "HIGH" if not passed else "MEDIUM"

        return ProbeResult(
            passed=passed,
            confidence=confidence,
            severity=severity,
            reason="...",
            evidence="..." if not passed else "",
            recommendation="..." if not passed else "",
        )
```

## Code style

- **Linter:** Ruff (rules: E, F, I, UP, ANN)
- **Type checker:** mypy strict mode
- **Line length:** 100 characters max
- **Python:** 3.10+ (use `from __future__ import annotations`)
- **Types:** Use `TypedDict` and `Literal` from `typing` — avoid `Any` unless necessary (mark with `# noqa: ANN401`)
- **Tests:** Use `pytest-httpx` to mock all HTTP calls — never hit real endpoints in tests

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `test:` adding or updating tests
- `refactor:` code change that neither fixes a bug nor adds a feature

## Pull requests

1. Fork the repo and create a feature branch from `main`
2. Make your changes with tests
3. Ensure all checks pass (`ruff`, `mypy`, `pytest`)
4. Open a PR with a clear description of what and why

## Reporting issues

Open an issue on GitHub with:
- What you expected
- What happened instead
- Steps to reproduce
- `llm-audit --version` output
