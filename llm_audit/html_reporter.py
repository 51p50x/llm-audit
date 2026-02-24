"""HTML report renderer for llm-audit."""

from __future__ import annotations

import html
import sys
from typing import TextIO

from llm_audit.types import AuditReport, ProbeResult

_SEVERITY_COLOR: dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "INFO": "#6b7280",
}

_CONFIDENCE_COLOR: dict[str, str] = {
    "HIGH": "#16a34a",
    "MEDIUM": "#d97706",
    "LOW": "#6b7280",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>llm-audit Report</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      margin: 0;
      padding: 2rem;
      line-height: 1.6;
    }}
    h1 {{ color: #38bdf8; margin-bottom: 0.25rem; font-size: 1.75rem; }}
    .subtitle {{ color: #94a3b8; font-size: 0.9rem; margin-bottom: 2rem; }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .meta-card {{
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 0.5rem;
      padding: 1rem 1.25rem;
    }}
    .meta-card .label {{
      color: #94a3b8; font-size: 0.75rem;
      text-transform: uppercase; letter-spacing: 0.05em;
    }}
    .meta-card .value {{
      font-size: 1rem; font-weight: 600;
      color: #f1f5f9; word-break: break-all;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
      margin-bottom: 2.5rem;
    }}
    .stat-card {{
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 0.5rem;
      padding: 1.25rem;
      text-align: center;
    }}
    .stat-card .stat-value {{ font-size: 2rem; font-weight: 700; }}
    .stat-card .stat-label {{ color: #94a3b8; font-size: 0.8rem; margin-top: 0.25rem; }}
    .stat-pass {{ color: #22c55e; }}
    .stat-fail {{ color: #ef4444; }}
    .stat-score {{ color: {score_color}; }}
    .stat-critical {{ color: #dc2626; }}
    .stat-high {{ color: #ea580c; }}
    .stat-medium {{ color: #d97706; }}
    .probe-list {{ display: flex; flex-direction: column; gap: 1rem; }}
    .probe-card {{
      background: #1e293b;
      border-radius: 0.5rem;
      border-left: 4px solid;
      overflow: hidden;
    }}
    .probe-card.pass {{ border-color: #22c55e; }}
    .probe-card.fail {{ border-color: #ef4444; }}
    .probe-header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1rem 1.25rem;
      cursor: pointer;
      user-select: none;
      gap: 1rem;
    }}
    .probe-header:hover {{ background: #263348; }}
    .probe-title {{ font-weight: 600; font-size: 1rem; flex: 1; }}
    .probe-badges {{ display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }}
    .badge {{
      font-size: 0.7rem;
      font-weight: 700;
      padding: 0.2rem 0.55rem;
      border-radius: 9999px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }}
    .badge-pass {{ background: #14532d; color: #86efac; }}
    .badge-fail {{ background: #450a0a; color: #fca5a5; }}
    .badge-critical {{ background: #450a0a; color: #fca5a5; }}
    .badge-high {{ background: #431407; color: #fdba74; }}
    .badge-medium {{ background: #451a03; color: #fde68a; }}
    .badge-info {{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }}
    .badge-conf-high {{ background: #14532d; color: #86efac; }}
    .badge-conf-medium {{ background: #451a03; color: #fde68a; }}
    .badge-conf-low {{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }}
    .chevron {{ color: #94a3b8; transition: transform 0.2s; font-size: 0.85rem; }}
    .probe-body {{ padding: 0 1.25rem 1.25rem; display: none; }}
    .probe-body.open {{ display: block; }}
    .probe-body .reason {{ color: #cbd5e1; margin-bottom: 1rem; }}
    .section-label {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #64748b;
      margin-bottom: 0.4rem;
      margin-top: 1rem;
    }}
    .evidence-block {{
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 0.375rem;
      padding: 0.75rem 1rem;
      font-family: "JetBrains Mono", "Fira Code", monospace;
      font-size: 0.78rem;
      color: #94a3b8;
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 200px;
      overflow-y: auto;
    }}
    .recommendation-block {{
      background: #1c2a1c;
      border: 1px solid #365314;
      border-radius: 0.375rem;
      padding: 0.75rem 1rem;
      color: #bbf7d0;
      font-size: 0.85rem;
    }}
    .footer {{
      margin-top: 3rem;
      text-align: center;
      color: #475569;
      font-size: 0.8rem;
    }}
    .footer a {{ color: #38bdf8; text-decoration: none; }}
  </style>
</head>
<body>
  <h1>llm-audit</h1>
  <p class="subtitle">OWASP LLM Top 10 Security Audit Report</p>

  <div class="meta-grid">
    <div class="meta-card">
      <div class="label">Endpoint</div>
      <div class="value">{endpoint}</div>
    </div>
    <div class="meta-card">
      <div class="label">Model</div>
      <div class="value">{model}</div>
    </div>
    <div class="meta-card">
      <div class="label">Timestamp</div>
      <div class="value">{timestamp}</div>
    </div>
  </div>

  <div class="summary-grid">
    <div class="stat-card">
      <div class="stat-value">{total}</div>
      <div class="stat-label">Total Probes</div>
    </div>
    <div class="stat-card">
      <div class="stat-value stat-pass">{passed}</div>
      <div class="stat-label">Passed</div>
    </div>
    <div class="stat-card">
      <div class="stat-value stat-fail">{failed}</div>
      <div class="stat-label">Failed</div>
    </div>
    <div class="stat-card">
      <div class="stat-value stat-score">{score}%</div>
      <div class="stat-label">Security Score</div>
    </div>
    {severity_stats}
  </div>

  <div class="probe-list">
    {probe_cards}
  </div>

  <div class="footer">
    Generated by <a href="https://github.com/51p50x/llm-audit">llm-audit</a> &mdash;
    OWASP LLM Top 10 security auditing tool
  </div>

  <script>
    document.querySelectorAll('.probe-header').forEach(function(header) {{
      header.addEventListener('click', function() {{
        var body = this.nextElementSibling;
        var chevron = this.querySelector('.chevron');
        body.classList.toggle('open');
        chevron.textContent = body.classList.contains('open') ? '▲' : '▼';
      }});
    }});
    // Auto-expand failed probes
    document.querySelectorAll('.probe-card.fail .probe-body').forEach(function(b) {{
      b.classList.add('open');
      var chevron = b.previousElementSibling.querySelector('.chevron');
      if (chevron) chevron.textContent = '▲';
    }});
  </script>
</body>
</html>
"""


def _severity_badge(severity: str) -> str:
    cls = f"badge-{severity.lower()}"
    return f'<span class="badge {cls}">{html.escape(severity)}</span>'


def _confidence_badge(confidence: str) -> str:
    cls = f"badge-conf-{confidence.lower()}"
    return f'<span class="badge {cls}">conf: {html.escape(confidence)}</span>'


def _render_probe_card(probe_name: str, result: ProbeResult) -> str:
    passed = result["passed"]
    card_cls = "pass" if passed else "fail"
    status_badge = (
        '<span class="badge badge-pass">✔ PASS</span>'
        if passed
        else '<span class="badge badge-fail">✘ FAIL</span>'
    )
    severity = result.get("severity", "INFO")
    confidence = result.get("confidence", "HIGH")

    evidence_html = ""
    if result["evidence"]:
        evidence_html = f"""
      <div class="section-label">Evidence</div>
      <div class="evidence-block">{html.escape(result['evidence'])}</div>"""

    recommendation_html = ""
    if result["recommendation"]:
        recommendation_html = f"""
      <div class="section-label">Recommendation</div>
      <div class="recommendation-block">{html.escape(result['recommendation'])}</div>"""

    return f"""
    <div class="probe-card {card_cls}">
      <div class="probe-header">
        <div class="probe-title">{html.escape(probe_name)}</div>
        <div class="probe-badges">
          {status_badge}
          {_severity_badge(severity)}
          {_confidence_badge(confidence)}
        </div>
        <span class="chevron">▼</span>
      </div>
      <div class="probe-body">
        <div class="reason">{html.escape(result['reason'])}</div>
        {evidence_html}
        {recommendation_html}
      </div>
    </div>"""


def render_html(report: AuditReport, *, output: TextIO = sys.stdout) -> None:
    """Render the audit report as a self-contained HTML file."""
    summary = report["summary"]
    total = summary["total"]
    passed = summary["passed"]
    failed = summary["failed"]
    score = int((passed / total) * 100) if total else 0

    if score == 100:
        score_color = "#22c55e"
    elif score >= 60:
        score_color = "#d97706"
    else:
        score_color = "#ef4444"

    by_severity = summary.get("by_severity", {})

    severity_stats_parts: list[str] = []
    for sev, css_cls in [("CRITICAL", "critical"), ("HIGH", "high"), ("MEDIUM", "medium")]:
        count = by_severity.get(sev, 0)
        if count:
            severity_stats_parts.append(f"""
    <div class="stat-card">
      <div class="stat-value stat-{css_cls}">{count}</div>
      <div class="stat-label">{sev}</div>
    </div>""")

    probe_cards = "\n".join(
        _render_probe_card(name, result)
        for name, result in report["results"].items()
    )

    output.write(
        _HTML_TEMPLATE.format(
            endpoint=html.escape(report["endpoint"]),
            model=html.escape(report["model"] or "not specified"),
            timestamp=html.escape(report["timestamp"]),
            total=total,
            passed=passed,
            failed=failed,
            score=score,
            score_color=score_color,
            severity_stats="\n".join(severity_stats_parts),
            probe_cards=probe_cards,
        )
    )
