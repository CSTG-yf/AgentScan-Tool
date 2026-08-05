"""Build a self-contained static HTML dashboard for AgentRange evidence."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "integration" / "reports" / "final-report.json"
OUTPUT = ROOT / "dashboard" / "index.html"


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def json_for_script(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False).replace("</", "<\\/")


def build_html(report: dict[str, Any]) -> str:
    runtime = report.get("runtime") or {}
    title = "AgentRange DefenseClaw Dashboard"
    generated = html.escape(str(report.get("generated_at") or "not generated"))
    event_count = runtime.get("event_count", 0)
    chain_count = runtime.get("attack_chain_count", 0)
    blocked = runtime.get("blocked_chain_count", 0)
    decisions = runtime.get("decisions") or {}
    severities = runtime.get("severities") or {}
    data = json_for_script(report)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #1d2433;
      --muted: #667085;
      --line: #d9dee8;
      --good: #0f766e;
      --warn: #b45309;
      --bad: #b42318;
      --accent: #1f5eff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    header {{
      padding: 28px 32px 18px;
      border-bottom: 1px solid var(--line);
      background: #fff;
    }}
    h1 {{ margin: 0 0 6px; font-size: 26px; font-weight: 700; letter-spacing: 0; }}
    h2 {{ margin: 0 0 14px; font-size: 17px; letter-spacing: 0; }}
    p {{ margin: 0; color: var(--muted); }}
    main {{ padding: 24px 32px 42px; display: grid; gap: 18px; }}
    .cards {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }}
    .card, section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }}
    .label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; }}
    .value {{ margin-top: 6px; font-size: 28px; font-weight: 700; }}
    .split {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }}
    table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
    th, td {{ padding: 10px 8px; border-bottom: 1px solid var(--line); vertical-align: top; font-size: 13px; }}
    th {{ text-align: left; color: var(--muted); font-weight: 600; }}
    td {{ word-break: break-word; }}
    .pill {{
      display: inline-block;
      min-width: 58px;
      padding: 3px 7px;
      border-radius: 999px;
      font-size: 12px;
      text-align: center;
    }}
    .pill.block {{ background: #fee4e2; color: var(--bad); }}
    .pill.allow {{ background: #dff7ef; color: var(--good); }}
    .pill.inspect_unavailable, .pill.unknown {{ background: #fff3d6; color: var(--warn); }}
    .chain {{ border-top: 1px solid var(--line); padding: 12px 0; }}
    .chain:first-child {{ border-top: 0; padding-top: 0; }}
    .chain-title {{ display: flex; gap: 10px; align-items: center; justify-content: space-between; }}
    .node-list {{ margin-top: 8px; display: grid; gap: 6px; }}
    .node {{ padding: 8px; border: 1px solid var(--line); border-radius: 6px; background: #fafbfc; font-size: 13px; }}
    .empty {{ color: var(--muted); padding: 12px 0; }}
    @media (max-width: 900px) {{
      header, main {{ padding-left: 18px; padding-right: 18px; }}
      .cards, .split {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>{title}</h1>
    <p>Generated: {generated}. Source: project-side DefenseClaw audit evidence.</p>
  </header>
  <main>
    <div class="cards">
      <div class="card"><div class="label">Runtime Events</div><div class="value">{event_count}</div></div>
      <div class="card"><div class="label">Attack Chains</div><div class="value">{chain_count}</div></div>
      <div class="card"><div class="label">Blocked Chains</div><div class="value">{blocked}</div></div>
      <div class="card">
        <div class="label">Sessions</div>
        <div class="value">{runtime.get("session_count", 0)}</div>
      </div>
    </div>
    <div class="split">
      <section>
        <h2>Decisions</h2>
        <div id="decisions">{html.escape(json.dumps(decisions, ensure_ascii=False))}</div>
      </section>
      <section>
        <h2>Severities</h2>
        <div id="severities">{html.escape(json.dumps(severities, ensure_ascii=False))}</div>
      </section>
    </div>
    <section>
      <h2>Attack Chains</h2>
      <div id="chains"></div>
    </section>
    <section>
      <h2>Recent Runtime Events</h2>
      <div id="events"></div>
    </section>
  </main>
  <script type="application/json" id="dashboard-data">{data}</script>
  <script>
    const dataEl = document.getElementById("dashboard-data");
    const data = JSON.parse(dataEl.textContent || "{{}}");
    const chains = data.chains || [];
    const events = data.recent_events || [];

    function pill(decision) {{
      const value = String(decision || "unknown");
      return `<span class="pill ${{value}}">${{value}}</span>`;
    }}

    function text(value) {{
      return String(value ?? "").replace(/[&<>"']/g, ch => ({{
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
      }}[ch]));
    }}

    const chainBox = document.getElementById("chains");
    chainBox.innerHTML = chains.length ? chains.map(chain => `
      <div class="chain">
        <div class="chain-title">
          <strong>${{text(chain.chain_id)}} · ${{text(chain.sequence_type)}}</strong>
          ${{chain.blocked ? pill("block") : pill("allow")}}
        </div>
        <div class="node-list">
          ${{(chain.nodes || []).map(node => `
            <div class="node">
              <strong>${{text(node.stage)}}</strong>
              ${{pill(node.decision)}}
              <div>${{text(node.summary)}}</div>
              <div>${{text(node.reason || node.raw_ref || "")}}</div>
            </div>
          `).join("")}}
        </div>
      </div>
    `).join("") : `<div class="empty">No AgentRange runtime chains found yet.</div>`;

    const rows = events.slice().reverse().map(event => `
      <tr>
        <td>${{text(event.timestamp)}}</td>
        <td>${{text(event.stage)}}</td>
        <td>${{text(event.destination_app || event.proxy_kind)}}</td>
        <td>${{text(event.tool_name || event.mcp_server)}}</td>
        <td>${{pill(event.decision)}}</td>
        <td>${{text(event.reason || event.details || "")}}</td>
      </tr>
    `).join("");
    document.getElementById("events").innerHTML = rows ? `
      <table>
        <thead><tr><th>Time</th><th>Stage</th><th>Asset</th><th>Tool</th><th>Decision</th><th>Evidence</th></tr></thead>
        <tbody>${{rows}}</tbody>
      </table>
    ` : `
      <div class="empty">
        No runtime events found. Run the AgentRange replay after sidecars can authenticate to DefenseClaw.
      </div>
    `;
  </script>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=REPORT)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    report = read_json(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(build_html(report), encoding="utf-8")
    print(json.dumps({"output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
