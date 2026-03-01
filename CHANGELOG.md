# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - Unreleased

### Added
- `--dry-run` flag to validate configuration without sending requests
- `--insecure` flag to skip TLS certificate verification for self-signed endpoints
- `--proxy` flag and `LLM_AUDIT_PROXY` env var for corporate proxy environments
- Dynamic probe registry — new probes are auto-discovered without editing `__init__.py`
- `probe_key` class attribute on `BaseProbe` for registry identification
- GitHub Actions release workflow for automated PyPI publishing on tag push
- `CONTRIBUTING.md` with probe development guide and code style standards
- `CHANGELOG.md` for tracking releases
- Dependabot configuration for automated dependency updates
- Roadmap section in README with progress tracking
- Output examples section in README
- Codecov integration and coverage badge
- `authors` and `Changelog` URL in `pyproject.toml` for PyPI metadata

### Changed
- Expanded test suite to 69 tests with 91%+ coverage (HTTP 429 retries, invalid JSON, timeouts, proxy, dynamic registry)
- Probe registry (`llm_audit/probes/__init__.py`) rewritten from static imports to dynamic auto-discovery

## [0.1.0] - 2026-02-24

### Added
- Initial release
- 8 security probes covering OWASP LLM Top 10: prompt injection, indirect injection, jailbreak, data leakage, insecure output, training data extraction, model DoS, excessive agency
- Rich terminal, JSON, and self-contained HTML report output
- Custom endpoint support via `--request-template` and `--response-path`
- Probe groups with `--only` filter
- Concurrent probe execution with `--concurrency`
- Retry with exponential backoff for HTTP 429 and 5xx responses
- CI/CD pipeline examples for GitHub Actions, GitLab CI, Azure DevOps, Bitbucket Pipelines, Jenkins, and Docker
- Strict mypy and Ruff linting
- 29 unit tests with pytest-httpx
