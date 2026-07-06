from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from ..metrics import METRIC_NAMES


def build_dashboard(run_dir: str | Path, output_path: str | Path | None = None) -> Path:
    run_path = Path(run_dir)
    output = Path(output_path) if output_path else run_path / "dashboard.html"
    metrics = _read_json(run_path / "metrics.json")
    events = _read_audit_events(run_path / "audit")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_render_dashboard(metrics, events), encoding="utf-8")
    return output


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _read_audit_events(audit_dir: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not audit_dir.exists():
        return events
    for path in sorted(audit_dir.glob("*.jsonl")):
        mode = path.stem.replace("_audit", "")
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                event = json.loads(line)
                event.setdefault("labels", {})
                event["labels"].setdefault("mode", mode)
                events.append(event)
    return events


def _render_dashboard(metrics: dict[str, Any], events: list[dict[str, Any]]) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentGuard Dashboard</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #17202a;
      --muted: #5d6978;
      --line: #d7dde5;
      --surface: #f7f9fb;
      --allow: #147a53;
      --block: #b42318;
      --review: #a15c07;
      --redact: #475467;
      --accent: #0f5e9c;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      color: var(--ink);
      background: #ffffff;
    }}
    header {{
      padding: 28px 32px 18px;
      border-bottom: 1px solid var(--line);
      background: var(--surface);
    }}
    h1, h2 {{ margin: 0; letter-spacing: 0; }}
    h1 {{ font-size: 28px; }}
    h2 {{ font-size: 18px; margin-bottom: 12px; }}
    main {{
      display: grid;
      gap: 24px;
      padding: 24px 32px 40px;
      max-width: 1380px;
      margin: 0 auto;
    }}
    section {{
      border-top: 1px solid var(--line);
      padding-top: 18px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
      font-size: 13px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }}
    th {{ color: var(--muted); font-weight: 700; background: #fbfcfd; }}
    .metric-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
    }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      min-height: 86px;
    }}
    .metric strong {{ display: block; font-size: 20px; margin-top: 8px; }}
    .muted {{ color: var(--muted); }}
    .pill {{
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border-radius: 999px;
      padding: 2px 9px;
      color: #fff;
      font-weight: 700;
      font-size: 12px;
      white-space: nowrap;
    }}
    .allow {{ background: var(--allow); }}
    .allow_with_redaction {{ background: var(--redact); }}
    .block {{ background: var(--block); }}
    .require_confirmation {{ background: var(--review); }}
    .toolbar {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 12px;
    }}
    button {{
      border: 1px solid var(--line);
      background: #fff;
      border-radius: 6px;
      min-height: 32px;
      padding: 6px 10px;
      cursor: pointer;
      color: var(--ink);
    }}
    button:hover {{ border-color: var(--accent); }}
    pre {{
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      margin: 8px 0 0;
      padding: 10px;
      background: #f4f6f8;
      border-radius: 6px;
      max-height: 220px;
      overflow: auto;
    }}
    @media (max-width: 720px) {{
      header, main {{ padding-left: 16px; padding-right: 16px; }}
      table {{ font-size: 12px; }}
      th:nth-child(1), td:nth-child(1) {{ width: 76px; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>AgentGuard Dashboard</h1>
    <p class="muted">Runtime tool-call protection, attack coverage, audit decisions, and evaluation metrics.</p>
  </header>
  <main>
    <section>
      <h2>Evaluation Metrics</h2>
      {_metrics_grid(metrics)}
      {_metrics_table(metrics)}
    </section>
    <section>
      <h2>Audit Timeline</h2>
      <div class="toolbar">
        <button type="button" data-filter="all">All</button>
        <button type="button" data-filter="allow">Allow</button>
        <button type="button" data-filter="block">Block</button>
        <button type="button" data-filter="require_confirmation">Review</button>
      </div>
      {_audit_table(events)}
    </section>
  </main>
  <script>
    document.querySelectorAll('[data-filter]').forEach((button) => {{
      button.addEventListener('click', () => {{
        const filter = button.dataset.filter;
        document.querySelectorAll('[data-decision]').forEach((row) => {{
          row.style.display = filter === 'all' || row.dataset.decision === filter ? '' : 'none';
        }});
      }});
    }});
    document.querySelectorAll('[data-confirm-action]').forEach((button) => {{
      button.addEventListener('click', () => {{
        const cell = button.closest('[data-confirm-cell]');
        const action = button.dataset.confirmAction;
        cell.querySelector('[data-confirm-state]').textContent = action === 'approve' ? 'approved locally' : 'denied locally';
      }});
    }});
  </script>
</body>
</html>
"""


def _metrics_grid(metrics: dict[str, Any]) -> str:
    gateway = metrics.get("gateway", {}).get("metrics", {})
    if not gateway:
        return '<p class="muted">No metrics found. Run evaluation first.</p>'
    cards = []
    for name in ["task_completion_rate", "unsafe_call_rate", "false_block_rate", "review_rate"]:
        cards.append(
            '<div class="metric">'
            f'<span class="muted">{_label(name)}</span>'
            f"<strong>{html.escape(str(gateway.get(name, 0)))}</strong>"
            "</div>"
        )
    return '<div class="metric-grid">' + "".join(cards) + "</div>"


def _metrics_table(metrics: dict[str, Any]) -> str:
    if not metrics:
        return ""
    header = "<tr><th>Mode</th>" + "".join(f"<th>{html.escape(_label(name))}</th>" for name in METRIC_NAMES) + "</tr>"
    rows = []
    for mode, payload in metrics.items():
        values = payload.get("metrics", {})
        rows.append(
            "<tr>"
            f"<td>{html.escape(mode)}</td>"
            + "".join(f"<td>{html.escape(str(values.get(name, 0)))}</td>" for name in METRIC_NAMES)
            + "</tr>"
        )
    return "<table>" + header + "".join(rows) + "</table>"


def _audit_table(events: list[dict[str, Any]]) -> str:
    if not events:
        return '<p class="muted">No audit events found.</p>'
    rows = []
    for event in events[-300:]:
        decision = event.get("decision", {}).get("decision", "unknown")
        call = event.get("call", {})
        labels = event.get("labels", {})
        signals = event.get("decision", {}).get("signals", [])
        confirm = ""
        if decision == "require_confirmation":
            confirm = (
                '<div data-confirm-cell>'
                '<button type="button" data-confirm-action="approve">Approve</button> '
                '<button type="button" data-confirm-action="deny">Deny</button> '
                '<span class="muted" data-confirm-state>pending</span>'
                '</div>'
            )
        rows.append(
            f'<tr data-decision="{html.escape(decision)}">'
            f"<td>{html.escape(str(labels.get('mode', 'runtime')))}</td>"
            f"<td>{html.escape(str(call.get('task_id', 'manual')))}<br>{html.escape(str(call.get('step_id', 'step-0')))}</td>"
            f"<td>{html.escape(str(call.get('tool_name', 'unknown')))}</td>"
            f'<td><span class="pill {html.escape(decision)}">{html.escape(decision)}</span></td>'
            f"<td>{html.escape(str(event.get('decision', {}).get('risk_level', 'unknown')))}</td>"
            f"<td>{html.escape(str(event.get('decision', {}).get('reason', '')))}{confirm}{_signals(signals)}</td>"
            "</tr>"
        )
    header = "<tr><th>Mode</th><th>Task</th><th>Tool</th><th>Decision</th><th>Risk</th><th>Reason</th></tr>"
    return "<table>" + header + "".join(rows) + "</table>"


def _signals(signals: list[dict[str, Any]]) -> str:
    if not signals:
        return ""
    text = json.dumps(signals, ensure_ascii=False, indent=2)
    return f"<details><summary>Signals</summary><pre>{html.escape(text)}</pre></details>"


def _label(name: str) -> str:
    return name.replace("_", " ").title()
