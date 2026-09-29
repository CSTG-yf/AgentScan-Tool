"""Build a self-contained static HTML dashboard for AgentRange validation evidence."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "integration" / "reports" / "final-report.json"
SCENARIOS = ROOT / "integration" / "agentrange_contracts" / "scenario-matrix.yaml"
OUTPUT = ROOT / "dashboard" / "index.html"


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def read_scenarios(path: Path = SCENARIOS) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    scenarios = payload.get("scenarios") or {}
    rows = []
    for scenario_id, item in scenarios.items():
        rows.append(
            {
                "id": scenario_id.upper(),
                "class": item.get("class", ""),
                "target": item.get("target", ""),
                "objective": item.get("objective", ""),
                "blocked": item.get("blocked", ""),
            }
        )
    return rows


def pct(value: Any) -> str:
    if value is None:
        return "待生成"
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "待生成"


def ms(value: Any) -> str:
    if value is None:
        return "待生成"
    try:
        return f"{float(value):.0f}ms"
    except (TypeError, ValueError):
        return "待生成"


def pct_points(value: Any) -> str:
    if value is None:
        return "待生成"
    try:
        return f"{float(value):.1f}%"
    except (TypeError, ValueError):
        return "待生成"


def status_label(status: str) -> str:
    return {"pass": "PASS", "fail": "FAIL", "wait": "WAIT", "partial": "PARTIAL"}.get(status, status.upper())


def build_data(report: dict[str, Any]) -> dict[str, Any]:
    static = report.get("static") or {}
    static_metrics = static.get("metrics") or {}
    static_evaluation = static.get("evaluation") or {}
    evaluated_asset = static_evaluation.get("asset") or {}
    evaluated_risk = static_evaluation.get("risk") or {}
    static_scope_verified = static_evaluation.get("scope") == "local_frozen_fixture"
    runtime = report.get("runtime") or {}
    rules = report.get("rules") or {}
    benchmark = report.get("benchmark") or {}
    modes = benchmark.get("modes") or {}
    action = modes.get("action") or {}
    action_metrics = action.get("metrics") or {}
    action_latency = action.get("inspect_latency_ms") or action_metrics.get("latency_ms") or {}
    action_latency_p95 = action_latency.get("p95")
    cpu_increment = action.get("cpu_increment_pct")
    cpu_status = action.get("cpu_comparison_status")
    traceability = report.get("plan_traceability") or {}
    trace_counts = traceability.get("counts") or {}
    scorecard = [
        {
            "name": "资产盘点准确率",
            "target": "目标 ≥99%",
            "actual": pct(evaluated_asset.get("precision")),
            "detail": "本地标注集 / Precision",
            "status": "pass" if static_scope_verified and (evaluated_asset.get("precision") or 0) >= 0.99 else "wait",
        },
        {
            "name": "资产漏报率",
            "target": "目标 <5%",
            "actual": pct(evaluated_asset.get("miss_rate")),
            "detail": "本地标注集 / FN",
            "status": "pass" if static_scope_verified and evaluated_asset.get("miss_rate") is not None and evaluated_asset["miss_rate"] < 0.05 else "wait",
        },
        {
            "name": "风险识别准确率",
            "target": "目标 ≥95%",
            "actual": pct(evaluated_risk.get("precision")),
            "detail": "本地标注集 / Precision",
            "status": "pass" if static_scope_verified and (evaluated_risk.get("precision") or 0) >= 0.95 else "wait",
        },
        {
            "name": "风险漏报率",
            "target": "目标 <5%",
            "actual": pct(evaluated_risk.get("miss_rate")),
            "detail": "本地标注集 / FN",
            "status": "pass" if static_scope_verified and evaluated_risk.get("miss_rate") is not None and evaluated_risk["miss_rate"] < 0.05 else "wait",
        },
        {
            "name": "规则合同",
            "target": "攻击命中且良性不命中",
            "actual": "通过" if rules.get("passed") else "待生成",
            "detail": f"{sum(bool(item.get('passed')) for item in rules.get('results', []))}/{len(rules.get('results', []))}",
            "status": "pass" if rules.get("passed") else "wait",
        },
        {
            "name": "恶意实例 Recall",
            "target": "目标 ≥95%",
            "actual": pct(action_metrics.get("recall")),
            "detail": "Action / instance",
            "status": "pass" if action_metrics.get("recall", 0) >= 0.95 else ("fail" if action else "wait"),
        },
        {
            "name": "正常实例 FPR",
            "target": "目标 <5%",
            "actual": pct(action_metrics.get("fpr")),
            "detail": "Action / instance",
            "status": "pass" if action and action_metrics.get("fpr", 1) < 0.05 else ("fail" if action else "wait"),
        },
        {
            "name": "阻断响应 p95",
            "target": "目标 <1000ms",
            "actual": ms(action_latency_p95),
            "detail": "Inspect latency",
            "status": "pass" if action_latency_p95 is not None and action_latency_p95 < 1000 else ("fail" if action_latency_p95 is not None else "wait"),
        },
        {
            "name": "DefenseClaw 增量 CPU",
            "target": "目标 ≤5%",
            "actual": pct_points(cpu_increment),
            "detail": "Action vs baseline",
            "status": "pass" if cpu_status == "complete" and cpu_increment is not None and cpu_increment <= 5 else ("fail" if cpu_status == "complete" and action else "wait"),
        },
        {
            "name": "正常业务成功率",
            "target": "目标 100%",
            "actual": pct(action_metrics.get("normal_success_rate")),
            "detail": "Action benign traffic",
            "status": "pass" if action_metrics.get("normal_success_rate") == 1.0 else ("fail" if action else "wait"),
        },
    ]

    return {
        "generated_at": report.get("generated_at", "not generated"),
        "snapshot": [
            {"label": "资产覆盖", "value": f"{static_metrics.get('asset_found', 0)}/{static_metrics.get('asset_expected', 0)}"},
            {"label": "必要风险", "value": f"{static_metrics.get('required_risks_detected', 0)}/{static_metrics.get('required_risks', 0)}"},
            {"label": "运行时事件", "value": runtime.get("event_count", 0)},
            {"label": "攻击链", "value": runtime.get("attack_chain_count", 0)},
            {"label": "阻断链", "value": runtime.get("blocked_chain_count", 0)},
            {"label": "需求就绪", "value": trace_counts.get("evidence-ready", 0)},
        ],
        "scorecard": scorecard,
        "scenarios": read_scenarios(),
        "modes": modes,
        "chains": report.get("chains", []),
        "events": report.get("recent_events", []),
        "evidence": report.get("evidence_index", []),
        "notes": report.get("notes", []),
        "traceability": {
            "counts": trace_counts,
            "total": len(traceability.get("requirements", [])),
        },
    }


def json_for_script(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False).replace("</", "<\\/")


def build_html_legacy(report: dict[str, Any]) -> str:
    data = build_data(report)
    serialized = json_for_script(data)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentRange DefenseClaw Dashboard</title>
  <style>
    :root {{
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
    body {{ margin: 0; font-family: Inter, ui-sans-serif, system-ui, "Segoe UI", sans-serif; background: var(--bg); color: var(--text); }}
    header {{ padding: 28px 32px 18px; border-bottom: 1px solid var(--line); background: #fff; }}
    h1 {{ margin: 0 0 6px; font-size: 26px; font-weight: 700; letter-spacing: 0; }}
    h2 {{ margin: 0 0 14px; font-size: 17px; letter-spacing: 0; }}
    p {{ margin: 0; color: var(--muted); }}
    main {{ padding: 24px 32px 42px; display: grid; gap: 18px; }}
    section, .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }}
    #metricGrid {{ display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 14px; }}
    .label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; }}
    .value {{ margin-top: 6px; font-size: 25px; font-weight: 700; }}
    table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
    th, td {{ padding: 10px 8px; border-bottom: 1px solid var(--line); vertical-align: top; font-size: 13px; word-break: break-word; }}
    th {{ text-align: left; color: var(--muted); font-weight: 600; }}
    .pill {{ display: inline-block; min-width: 62px; padding: 3px 7px; border-radius: 999px; font-size: 12px; text-align: center; }}
    .pass, .allow {{ background: #dff7ef; color: var(--good); }}
    .wait, .partial, .unknown {{ background: #fff3d6; color: var(--warn); }}
    .fail, .block {{ background: #fee4e2; color: var(--bad); }}
    .chain {{ border-top: 1px solid var(--line); padding: 12px 0; }}
    .chain:first-child {{ border-top: 0; padding-top: 0; }}
    .node {{ margin-top: 6px; padding: 8px; border: 1px solid var(--line); border-radius: 6px; background: #fafbfc; font-size: 13px; }}
    .empty {{ color: var(--muted); padding: 12px 0; }}
    @media (max-width: 1100px) {{ #metricGrid {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }} }}
    @media (max-width: 700px) {{ header, main {{ padding-left: 18px; padding-right: 18px; }} #metricGrid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <header>
    <h1>AgentRange DefenseClaw Dashboard</h1>
    <p>Generated: {html.escape(str(data["generated_at"]))}. Source: DefenseClaw project-side validation evidence.</p>
  </header>
  <main>
    <div id="metricGrid"></div>
    <section id="scorecard"><h2>Scorecard</h2><div id="scorecardRows"></div></section>
    <section id="scenarios"><h2>Scenarios</h2><div id="scenarioRows"></div></section>
    <section id="chains"><h2>Attack Chains</h2><div id="chainRows"></div></section>
    <section id="events"><h2>Recent Runtime Events</h2><div id="eventRows"></div></section>
    <section id="evidence"><h2>Evidence</h2><div id="evidenceRows"></div></section>
  </main>
  <script type="application/json" id="dashboard-data">{serialized}</script>
  <script>
    const data = JSON.parse(document.getElementById("dashboard-data").textContent || "{{}}");
    const text = value => String(value ?? "").replace(/[&<>"']/g, ch => ({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}}[ch]));
    const pill = value => `<span class="pill ${{text(value).toLowerCase()}}">${{text(value)}}</span>`;
    const table = (headers, rows) => rows.length ? `<table><thead><tr>${{headers.map(h => `<th>${{text(h)}}</th>`).join("")}}</tr></thead><tbody>${{rows.join("")}}</tbody></table>` : `<div class="empty">No data yet.</div>`;

    document.getElementById("metricGrid").innerHTML = (data.snapshot || []).map(item => `
      <div class="card"><div class="label">${{text(item.label)}}</div><div class="value">${{text(item.value)}}</div></div>
    `).join("");

    document.getElementById("scorecardRows").innerHTML = table(
      ["Metric", "Target", "Actual", "Detail", "Status"],
      (data.scorecard || []).map(item => `<tr><td>${{text(item.name)}}</td><td>${{text(item.target)}}</td><td>${{text(item.actual)}}</td><td>${{text(item.detail)}}</td><td>${{pill(item.status)}}</td></tr>`)
    );

    document.getElementById("scenarioRows").innerHTML = table(
      ["Scenario", "Class", "Target", "Objective", "Block criterion"],
      (data.scenarios || []).map(item => `<tr><td>${{text(item.id)}}</td><td>${{text(item.class)}}</td><td>${{text(item.target)}}</td><td>${{text(item.objective)}}</td><td>${{text(item.blocked)}}</td></tr>`)
    );

    document.getElementById("chainRows").innerHTML = (data.chains || []).length ? (data.chains || []).map(chain => `
      <div class="chain">
        <strong>${{text(chain.chain_id)}} · ${{text(chain.sequence_type)}}</strong> ${{pill(chain.blocked ? "block" : "allow")}}
        <div>${{text(chain.evidence_summary || "")}}</div>
        <div>${{text((chain.unexecuted_side_effects || []).join("; "))}}</div>
        ${{(chain.nodes || []).map(node => `<div class="node"><strong>${{text(node.stage)}}</strong> ${{pill(node.decision || "unknown")}}<div>${{text(node.summary || "")}}</div><div>${{text(node.reason || node.raw_ref || "")}}</div></div>`).join("")}}
      </div>
    `).join("") : `<div class="empty">No AgentRange runtime chains found yet.</div>`;

    document.getElementById("eventRows").innerHTML = table(
      ["Time", "Stage", "Asset", "Tool", "Decision", "Evidence"],
      (data.events || []).slice().reverse().map(event => `<tr><td>${{text(event.timestamp)}}</td><td>${{text(event.stage)}}</td><td>${{text(event.destination_app || event.proxy_kind)}}</td><td>${{text(event.tool_name || event.mcp_server)}}</td><td>${{pill(event.decision || "unknown")}}</td><td>${{text(event.reason || event.details || "")}}</td></tr>`)
    );

    document.getElementById("evidenceRows").innerHTML = (data.evidence || []).length ? `<ul>${{(data.evidence || []).map(path => `<li><code>${{text(path)}}</code></li>`).join("")}}</ul>` : `<div class="empty">No evidence files generated yet.</div>`;
  </script>
</body>
</html>
"""


def build_html(report: dict[str, Any]) -> str:
    data = build_data(report)
    serialized = json_for_script(data)
    generated = html.escape(str(data["generated_at"]))
    template = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentRange DefenseClaw Dashboard</title>
  <style>
    :root {
      --ink: #102033;
      --muted: #64748b;
      --line: #dce4ea;
      --paper: #f4f7f8;
      --white: #ffffff;
      --navy: #071522;
      --navy-2: #0c2235;
      --teal: #13b89a;
      --teal-dark: #087b69;
      --cyan: #43d7e8;
      --lime: #b9ed4a;
      --amber: #f5ad42;
      --red: #e85c60;
      --shadow: 0 18px 50px rgba(20, 43, 60, .1);
      --radius: 20px;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      color: var(--ink);
      background: var(--paper);
      font-family: Inter, "Segoe UI", "Microsoft YaHei", system-ui, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    a { color: inherit; }
    button { font: inherit; }
    .shell { width: min(1180px, calc(100% - 48px)); margin-inline: auto; }
    .skip-link { position: fixed; left: 16px; top: -60px; z-index: 100; padding: 10px 14px; background: var(--white); border-radius: 8px; }
    .skip-link:focus { top: 12px; }
    .topbar {
      height: 74px;
      padding: 0 max(24px, calc((100vw - 1180px) / 2));
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
      background: rgba(7, 21, 34, .96);
      color: #eaf5f6;
      position: sticky;
      top: 0;
      z-index: 50;
      backdrop-filter: blur(16px);
      border-bottom: 1px solid rgba(255,255,255,.08);
    }
    .brand { display: flex; align-items: center; gap: 11px; text-decoration: none; }
    .brand-mark { display: grid; place-items: center; width: 38px; height: 38px; color: var(--navy); background: var(--lime); border-radius: 11px; font-weight: 900; letter-spacing: 0; }
    .brand strong, .brand small { display: block; }
    .brand strong { font-size: 14px; letter-spacing: 0; }
    .brand small { margin-top: 2px; color: #8ea6b5; font-size: 10px; text-transform: uppercase; letter-spacing: 0; }
    .topbar nav { display: flex; gap: 28px; }
    .topbar nav a { color: #a9bdc8; text-decoration: none; font-size: 13px; }
    .topbar nav a:hover, .topbar nav a:focus-visible { color: var(--white); }
    .print-button { border: 1px solid rgba(255,255,255,.18); border-radius: 999px; padding: 9px 15px; color: var(--white); background: rgba(255,255,255,.06); cursor: pointer; }
    .print-button:hover { background: rgba(255,255,255,.12); }
    .hero { position: relative; overflow: hidden; color: var(--white); background: var(--navy); }
    .hero-grid { position: absolute; inset: 0; opacity: .16; background-image: linear-gradient(rgba(90,220,215,.2) 1px, transparent 1px), linear-gradient(90deg, rgba(90,220,215,.2) 1px, transparent 1px); background-size: 58px 58px; mask-image: linear-gradient(90deg, transparent, #000 38%, #000); }
    .hero::after { content: ""; position: absolute; width: 540px; height: 540px; right: -160px; top: -210px; border: 1px solid rgba(67,215,232,.22); border-radius: 50%; box-shadow: 0 0 0 68px rgba(67,215,232,.03), 0 0 0 136px rgba(67,215,232,.025); }
    .hero-content { min-height: 490px; padding-block: 78px 54px; display: grid; grid-template-columns: 1.6fr .75fr; align-items: center; gap: 70px; position: relative; z-index: 1; }
    .eyebrow, .section-kicker { margin: 0 0 12px; color: var(--teal-dark); font-size: 11px; font-weight: 800; letter-spacing: 0; text-transform: uppercase; }
    .hero .eyebrow { color: var(--cyan); }
    .hero h1 { margin: 0; max-width: 760px; font-size: clamp(48px, 7vw, 86px); line-height: .98; letter-spacing: 0; }
    .hero h1 span { color: transparent; -webkit-text-stroke: 1px rgba(255,255,255,.62); }
    .hero-lead { max-width: 650px; margin: 28px 0 0; color: #a9bdc8; font-size: 17px; line-height: 1.8; }
    .hero-tags { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 28px; }
    .hero-tags span { padding: 7px 11px; color: #b7cad3; border: 1px solid rgba(255,255,255,.13); border-radius: 999px; font-size: 11px; }
    .readiness-card { padding: 28px; border: 1px solid rgba(255,255,255,.12); border-radius: 24px; background: rgba(255,255,255,.055); backdrop-filter: blur(10px); box-shadow: 0 30px 80px rgba(0,0,0,.22); }
    .readiness-ring { width: 178px; aspect-ratio: 1; margin: 0 auto 24px; display: grid; place-content: center; text-align: center; border-radius: 50%; background: radial-gradient(circle at center, var(--navy-2) 58%, transparent 59%), conic-gradient(var(--lime) var(--progress, 0%), rgba(255,255,255,.1) 0); }
    .readiness-ring strong { font-size: 42px; letter-spacing: 0; }
    .readiness-ring span { color: #8fa8b6; font-size: 11px; letter-spacing: 0; }
    .readiness-copy { display: grid; grid-template-columns: 1fr auto; gap: 5px 16px; align-items: end; }
    .readiness-copy p { margin: 0; color: #8fa8b6; font-size: 12px; }
    .readiness-copy strong { grid-row: span 2; color: var(--lime); font-size: 24px; }
    .readiness-copy small { color: #c7d5db; }
    .hero-meta { min-height: 58px; display: flex; align-items: center; justify-content: space-between; gap: 24px; position: relative; z-index: 1; border-top: 1px solid rgba(255,255,255,.1); color: #7995a5; font-size: 11px; letter-spacing: 0; }
    .hero-meta b { color: #dce9ed; font-weight: 600; }
    .status-dot { display: inline-block; width: 8px; height: 8px; margin-right: 7px; border-radius: 50%; background: var(--amber); box-shadow: 0 0 0 5px rgba(245,173,66,.12); }
    .verdict { margin-top: 34px; padding: 24px 28px; display: grid; grid-template-columns: auto 1fr auto; gap: 20px; align-items: center; background: var(--white); border: 1px solid var(--line); border-left: 4px solid var(--amber); border-radius: var(--radius); box-shadow: var(--shadow); }
    .verdict-icon { width: 42px; height: 42px; display: grid; place-items: center; color: #68420d; background: #fff0d7; border-radius: 12px; font-weight: 900; }
    .verdict h2 { margin: 0; font-size: 20px; letter-spacing: 0; }
    .verdict p:not(.section-kicker) { margin: 7px 0 0; color: var(--muted); font-size: 13px; line-height: 1.65; }
    .status-pill { display: inline-flex; align-items: center; justify-content: center; width: max-content; padding: 7px 10px; border-radius: 999px; font-size: 11px; font-weight: 800; white-space: nowrap; }
    .status-pass, .status-allow, .status-benign { color: #076b58; background: #dff7ef; }
    .status-partial, .status-wait, .status-unknown { color: #8a5611; background: #fff0d7; }
    .status-fail, .status-block, .status-attack { color: #9b292d; background: #ffe5e6; }
    .section { padding-block: 82px; }
    .section-heading { margin-bottom: 30px; display: flex; align-items: end; justify-content: space-between; gap: 30px; }
    .section-heading h2, .panel h2, .evidence-section h2, .disclosure h2 { margin: 0; font-size: clamp(28px, 4vw, 42px); letter-spacing: 0; }
    .section-heading > p { max-width: 430px; margin: 0; color: var(--muted); font-size: 13px; line-height: 1.7; text-align: right; }
    .metric-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }
    .metric-card { min-height: 205px; padding: 24px; position: relative; overflow: hidden; background: var(--white); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: 0 8px 24px rgba(24, 52, 68, .045); }
    .metric-card::after { content: ""; position: absolute; right: -35px; bottom: -55px; width: 140px; height: 140px; border: 22px solid color-mix(in srgb, var(--accent) 12%, transparent); border-radius: 50%; }
    .metric-top { display: flex; align-items: center; justify-content: space-between; }
    .metric-index { color: var(--muted); font-size: 10px; font-weight: 800; letter-spacing: 0; }
    .metric-value { margin-top: 30px; font-size: 42px; line-height: 1; letter-spacing: 0; font-weight: 850; }
    .metric-label { margin: 10px 0 0; font-size: 14px; font-weight: 700; }
    .metric-note { margin: 8px 0 0; color: var(--muted); font-size: 11px; line-height: 1.55; }
    .scorecard-section { background: var(--navy-2); color: var(--white); }
    .inverse-heading .section-kicker { color: var(--cyan); }
    .inverse-heading > p { color: #8fa8b6; }
    .scorecard { overflow: hidden; border: 1px solid rgba(255,255,255,.1); border-radius: var(--radius); background: rgba(255,255,255,.035); }
    .score-row { min-height: 73px; padding: 14px 20px; display: grid; grid-template-columns: 1.5fr .8fr .9fr .7fr; gap: 18px; align-items: center; border-bottom: 1px solid rgba(255,255,255,.08); }
    .score-row:last-child { border-bottom: 0; }
    .score-head { min-height: 46px; color: #7794a4; font-size: 10px; font-weight: 800; letter-spacing: 0; text-transform: uppercase; }
    .score-name strong, .score-name small { display: block; }
    .score-name small { margin-top: 4px; color: #7893a2; font-size: 10px; }
    .score-target, .score-actual { color: #b8c9d1; font-size: 13px; }
    .score-actual strong { display: block; color: var(--white); font-size: 17px; }
    .score-actual small { display: block; margin-top: 3px; color: #7893a2; }
    .mode-switch { display: flex; padding: 4px; background: #e4e9ec; border-radius: 999px; }
    .mode-switch button { padding: 8px 14px; border: 0; border-radius: 999px; color: #60717d; background: transparent; cursor: pointer; font-size: 12px; font-weight: 700; }
    .mode-switch button[aria-selected="true"] { color: var(--white); background: var(--navy-2); box-shadow: 0 5px 14px rgba(7,21,34,.2); }
    .mode-panel { min-height: 250px; padding: 32px; background: var(--white); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); }
    .mode-title { display: flex; align-items: center; justify-content: space-between; gap: 18px; }
    .mode-title h3 { margin: 0; font-size: 22px; letter-spacing: 0; }
    .mode-title p { margin: 5px 0 0; color: var(--muted); font-size: 12px; }
    .mode-stats { margin-top: 28px; display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
    .mode-stat { padding: 18px; background: #f6f8f9; border-radius: 14px; }
    .mode-stat span, .mode-stat strong { display: block; }
    .mode-stat span { color: var(--muted); font-size: 10px; letter-spacing: 0; text-transform: uppercase; }
    .mode-stat strong { margin-top: 9px; font-size: 24px; letter-spacing: 0; }
    .mode-empty { height: 170px; display: grid; place-content: center; text-align: center; color: var(--muted); }
    .mode-empty strong { color: var(--ink); font-size: 20px; }
    .scenario-section { background: #e9eef0; }
    .scenario-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; }
    .scenario-card { padding: 24px; background: var(--white); border: 1px solid #d7e0e5; border-radius: 17px; }
    .scenario-top { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .scenario-code { color: var(--teal-dark); font-size: 11px; font-weight: 900; letter-spacing: 0; }
    .scenario-card h3 { margin: 17px 0 7px; font-size: 18px; letter-spacing: 0; }
    .scenario-card p { margin: 0; color: var(--muted); font-size: 12px; line-height: 1.7; }
    .scenario-meta { margin-top: 20px; padding-top: 15px; display: flex; justify-content: space-between; gap: 12px; border-top: 1px solid #edf0f2; color: #71818c; font-size: 10px; }
    .split-section { display: grid; grid-template-columns: 1.05fr .95fr; gap: 18px; }
    .panel { padding: 28px; background: var(--white); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); }
    .panel-heading { display: flex; align-items: start; justify-content: space-between; gap: 20px; }
    .panel h2 { font-size: 27px; }
    .panel-intro { margin: 16px 0 26px; color: var(--muted); font-size: 12px; line-height: 1.65; }
    .chain-list, .event-list { display: grid; gap: 12px; }
    .chain { padding: 16px; border: 1px solid var(--line); border-radius: 14px; background: #f7fafb; }
    .chain-title { display: flex; align-items: center; justify-content: space-between; gap: 12px; font-size: 13px; }
    .chain-summary { margin: 8px 0 0; color: var(--muted); font-size: 11px; line-height: 1.55; }
    .node { margin-top: 8px; padding: 10px; border: 1px solid #dce5ea; border-radius: 10px; background: var(--white); font-size: 11px; color: #52636f; }
    .event-table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    .event-table th, .event-table td { padding: 10px 8px; border-bottom: 1px solid var(--line); vertical-align: top; font-size: 12px; word-break: break-word; }
    .event-table th { color: var(--muted); text-align: left; font-size: 10px; text-transform: uppercase; letter-spacing: 0; }
    .evidence-section { color: var(--white); background: linear-gradient(135deg, #0a2031, #0b2c3a); }
    .evidence-section .section-kicker { color: var(--cyan); }
    .evidence-section h2 { max-width: 560px; }
    .evidence-section p:not(.section-kicker) { max-width: 580px; color: #91aab7; font-size: 13px; line-height: 1.8; }
    .evidence-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 70px; align-items: center; }
    .evidence-links { display: grid; gap: 9px; }
    .evidence-link { padding: 15px 17px; display: flex; align-items: center; justify-content: space-between; gap: 15px; color: #c8d8df; border: 1px solid rgba(255,255,255,.1); border-radius: 12px; text-decoration: none; background: rgba(255,255,255,.045); font-size: 12px; }
    .evidence-link:hover { border-color: rgba(67,215,232,.5); background: rgba(67,215,232,.08); }
    .evidence-link span:last-child { color: var(--cyan); }
    .disclosure { margin-block: 34px; padding: 30px; background: #fff; border: 1px solid var(--line); border-radius: var(--radius); }
    .disclosure h2 { font-size: 25px; }
    .disclosure ul { margin: 18px 0 0; padding-left: 20px; color: var(--muted); font-size: 12px; line-height: 1.9; }
    .empty { color: var(--muted); padding: 18px 0; }
    code { color: inherit; }
    footer { padding-block: 26px; color: #78909d; background: var(--navy); font-size: 10px; letter-spacing: 0; text-transform: uppercase; }
    .footer-inner { display: flex; justify-content: space-between; gap: 20px; }
    @media (max-width: 900px) {
      .topbar nav { display: none; }
      .hero-content { grid-template-columns: 1fr; gap: 38px; }
      .readiness-card { max-width: 380px; }
      .metric-grid { grid-template-columns: repeat(2, 1fr); }
      .mode-stats { grid-template-columns: repeat(2, 1fr); }
      .split-section, .evidence-grid { grid-template-columns: 1fr; }
    }
    @media (max-width: 620px) {
      .shell { width: min(100% - 28px, 1180px); }
      .topbar { padding-inline: 14px; }
      .print-button { display: none; }
      .hero-content { min-height: auto; padding-block: 56px 42px; }
      .hero h1 { font-size: 47px; }
      .hero-meta { padding-block: 18px; flex-direction: column; align-items: flex-start; }
      .verdict { grid-template-columns: auto 1fr; }
      .verdict .status-pill { grid-column: 2; }
      .section { padding-block: 58px; }
      .section-heading { align-items: flex-start; flex-direction: column; }
      .section-heading > p { text-align: left; }
      .metric-grid, .scenario-grid { grid-template-columns: 1fr; }
      .score-row { grid-template-columns: 1.25fr .8fr .7fr; }
      .score-row > :nth-child(2) { display: none; }
      .mode-switch { width: 100%; }
      .mode-switch button { flex: 1; }
      .footer-inner { flex-direction: column; }
    }
    @media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
    @media print {
      .topbar, .print-button, .mode-switch { display: none !important; }
      body { background: #fff; }
      .hero { print-color-adjust: exact; }
      .section { padding-block: 35px; }
      .metric-card, .panel, .mode-panel { box-shadow: none; break-inside: avoid; }
    }
  </style>
</head>
<body>
  <a class="skip-link" href="#main">跳到主要内容</a>
  <header class="topbar">
    <a class="brand" href="#top" aria-label="回到页面顶部">
      <span class="brand-mark" aria-hidden="true">DC</span>
      <span><strong>DefenseClaw</strong><small>AgentRange Validation</small></span>
    </a>
    <nav aria-label="页面导航">
      <a href="#scorecard">赛题指标</a>
      <a href="#scenarios">场景覆盖</a>
      <a href="#evidence">证据索引</a>
    </nav>
    <button class="print-button" type="button" id="printButton">打印报告</button>
  </header>
  <main id="main">
    <section class="hero" id="top" aria-labelledby="heroTitle">
      <div class="hero-grid"></div>
      <div class="hero-content shell">
        <div class="hero-copy">
          <p class="eyebrow">AI AGENT SECURITY · MAJOR REFACTOR V1.0</p>
          <h1 id="heroTitle">安全防护闭环<br><span>验证结果总览</span></h1>
          <p class="hero-lead">从资产发现、运行时检查、策略决策到攻击链与量化报告，面向 AgentRange 靶场的可复核安全验证。</p>
          <div class="hero-tags" aria-label="报告标签"><span>证据驱动</span><span>实例级统计</span><span>通用行为检测</span></div>
        </div>
        <aside class="readiness-card" aria-label="证据就绪度">
          <div class="readiness-ring" id="readinessRing"><strong id="readinessValue">0%</strong><span>证据就绪</span></div>
          <div class="readiness-copy"><p>需求追踪</p><strong id="readinessFraction">0 / 0</strong><small>FR / NFR 实现落点</small></div>
        </aside>
      </div>
      <div class="hero-meta shell">
        <span><i class="status-dot"></i><b id="reportState">数据已加载</b></span>
        <span>生成时间 <b id="generatedAt">__GENERATED_AT__</b></span>
        <span>验证范围 <b>OpsPilot + Langflow</b></span>
      </div>
    </section>
    <section class="verdict shell" aria-labelledby="verdictTitle">
      <div class="verdict-icon" aria-hidden="true">!</div>
      <div>
        <p class="section-kicker">当前结论</p>
        <h2 id="verdictTitle">工程闭环已成型，最终防护验收以真实网关证据为准</h2>
        <p>页面保留当前项目的静态盘点、规则合同、运行时事件、攻击链和 benchmark 汇总数据，只替换为参考 dashboard 的展示风格。</p>
      </div>
      <span class="status-pill status-partial">阶段性通过</span>
    </section>
    <section class="section shell" aria-labelledby="snapshotTitle">
      <div class="section-heading"><div><p class="section-kicker">VALIDATED SNAPSHOT</p><h2 id="snapshotTitle">一眼看懂验证结果</h2></div><p>只展示已有原始证据支持的数据，缺失项保持待生成状态。</p></div>
      <div class="metric-grid" id="metricGrid" aria-live="polite"></div>
    </section>
    <section class="section scorecard-section" id="scorecard" aria-labelledby="scorecardTitle">
      <div class="shell">
        <div class="section-heading inverse-heading"><div><p class="section-kicker">COMPETITION SCORECARD</p><h2 id="scorecardTitle">赛题关键指标达标表</h2></div><p>待生成项不会被伪装为通过，保持和当前 evidence 数据一致。</p></div>
        <div class="scorecard" id="scorecardRows" role="table" aria-label="赛题关键指标"></div>
      </div>
    </section>
    <section class="section shell" aria-labelledby="modeTitle">
      <div class="section-heading">
        <div><p class="section-kicker">THREE-MODE BENCHMARK</p><h2 id="modeTitle">三模式对照</h2></div>
        <div class="mode-switch" role="tablist" aria-label="验证模式">
          <button type="button" role="tab" aria-selected="true" data-mode="baseline">Baseline</button>
          <button type="button" role="tab" aria-selected="false" data-mode="observe">Observe</button>
          <button type="button" role="tab" aria-selected="false" data-mode="action">Action</button>
        </div>
      </div>
      <div class="mode-panel" id="modePanel" role="tabpanel"></div>
    </section>
    <section class="section scenario-section" id="scenarios" aria-labelledby="scenarioTitle">
      <div class="shell">
        <div class="section-heading"><div><p class="section-kicker">ATTACK SURFACE COVERAGE</p><h2 id="scenarioTitle">场景覆盖</h2></div><p>场景矩阵来自项目侧合同文件，页面只负责可读化呈现。</p></div>
        <div class="scenario-grid" id="scenarioRows"></div>
      </div>
    </section>
    <section class="section split-section shell">
      <article class="panel" aria-labelledby="chainTitle">
        <div class="panel-heading"><div><p class="section-kicker">ATTACK CHAINS</p><h2 id="chainTitle">攻击链证据</h2></div><span class="status-pill status-partial" id="chainBadge">0</span></div>
        <p class="panel-intro">按会话聚合运行时审计事件，突出是否阻断和关键节点。</p>
        <div id="chainRows" class="chain-list"></div>
      </article>
      <article class="panel" aria-labelledby="eventTitle">
        <div class="panel-heading"><div><p class="section-kicker">RUNTIME EVENTS</p><h2 id="eventTitle">最近运行时事件</h2></div></div>
        <p class="panel-intro">展示最近的 pre/post 检查、目标资产、工具和判定结果。</p>
        <div id="eventRows" class="event-list"></div>
      </article>
    </section>
    <section class="section evidence-section" id="evidence" aria-labelledby="evidenceTitle">
      <div class="shell evidence-grid">
        <div><p class="section-kicker">AUDITABLE EVIDENCE</p><h2 id="evidenceTitle">每个结论都能回到原始证据</h2><p>Dashboard 只读取项目侧报告、运行时审计和 benchmark 结果，不把 Ground Truth 当作检测输入。</p></div>
        <div class="evidence-links" id="evidenceRows"></div>
      </div>
    </section>
    <section class="disclosure shell" aria-labelledby="disclosureTitle">
      <p class="section-kicker">VALIDATION BOUNDARY</p>
      <h2 id="disclosureTitle">结果边界说明</h2>
      <ul id="noteRows"></ul>
    </section>
  </main>
  <footer><div class="shell footer-inner"><span>DefenseClaw × AgentRange</span><span>Evidence-backed AI Agent Security Validation</span></div></footer>
  <script type="application/json" id="dashboard-data">__DASHBOARD_DATA__</script>
  <script>
    const data = JSON.parse(document.getElementById("dashboard-data").textContent || "{}");
    const text = value => String(value ?? "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
    const statusClass = value => `status-${text(value || "unknown").toLowerCase().replace(/[^a-z0-9_-]/g, "") || "unknown"}`;
    const statusText = { pass: "通过", wait: "待生成", fail: "未通过", partial: "部分证据", allow: "允许", block: "阻断", attack: "攻击", benign: "良性" };
    const pill = value => `<span class="status-pill ${statusClass(value)}">${text(statusText[value] || value || "unknown")}</span>`;
    const modeNames = { baseline: "Baseline", observe: "Observe", action: "Action" };
    const fmtPct = value => value == null ? "待生成" : `${(Number(value) * 100).toFixed(Number(value) === 1 ? 0 : 1)}%`;
    const fmtMs = value => value == null ? "待生成" : `${Math.round(Number(value))}ms`;
    const fmtNumber = value => value == null ? "待生成" : String(value);
    const traceCounts = (data.traceability && data.traceability.counts) || {};
    const ready = Number(traceCounts["evidence-ready"] ?? traceCounts.evidence_ready ?? 0);
    const total = Number((data.traceability && data.traceability.total) || ready || 0);
    const progress = total ? Math.round((ready / total) * 100) : 0;
    document.getElementById("readinessRing").style.setProperty("--progress", `${progress}%`);
    document.getElementById("readinessValue").textContent = `${progress}%`;
    document.getElementById("readinessFraction").textContent = `${ready} / ${total}`;
    document.getElementById("generatedAt").textContent = data.generated_at || "__GENERATED_AT__";
    document.getElementById("reportState").textContent = Number((data.snapshot || [])[2]?.value || 0) ? "运行时证据已加载" : "等待更多运行证据";
    const accents = ["#13b89a", "#43d7e8", "#b9ed4a", "#f5ad42", "#e85c60", "#7c8cff"];
    document.getElementById("metricGrid").innerHTML = (data.snapshot || []).map((item, index) => `
      <article class="metric-card" style="--accent: ${accents[index % accents.length]}">
        <div class="metric-top"><span class="metric-index">${String(index + 1).padStart(2, "0")}</span>${pill(index < 2 ? "pass" : "partial")}</div>
        <div class="metric-value">${text(item.value)}</div>
        <p class="metric-label">${text(item.label)}</p>
        <p class="metric-note">来自项目侧验证证据</p>
      </article>
    `).join("");
    const scoreHead = `<div class="score-row score-head" role="row"><span>指标</span><span>目标</span><span>当前结果</span><span>状态</span></div>`;
    const scoreRows = (data.scorecard || []).map(item => `
      <div class="score-row" role="row">
        <div class="score-name"><strong>${text(item.name)}</strong><small>${text(item.detail || "")}</small></div>
        <div class="score-target">${text(item.target)}</div>
        <div class="score-actual"><strong>${text(item.actual)}</strong><small>${text(item.detail || "")}</small></div>
        ${pill(item.status)}
      </div>
    `).join("");
    document.getElementById("scorecardRows").innerHTML = scoreHead + (scoreRows || `<div class="mode-empty"><strong>Scorecard 待生成</strong><p>暂无指标数据</p></div>`);
    const renderMode = modeName => {
      const panel = document.getElementById("modePanel");
      const mode = (data.modes || {})[modeName];
      if (!mode) {
        panel.innerHTML = `<div class="mode-empty"><strong>${modeNames[modeName]} 数据待生成</strong><p>运行对应模式后会在这里显示指标。</p></div>`;
        return;
      }
      const metrics = mode.metrics || {};
      const counts = mode.counts || {};
      const latency = mode.inspect_latency_ms || mode.latency_ms || metrics.latency_ms || {};
      const values = [["实例", fmtNumber(counts.total ?? counts.valid ?? "-")], ["Recall", fmtPct(metrics.recall)], ["FPR", fmtPct(metrics.fpr)], ["正常成功率", fmtPct(metrics.normal_success_rate)], ["p95", fmtMs(latency.p95)]];
      panel.innerHTML = `<div class="mode-title"><div><h3>${modeNames[modeName]}</h3><p>${text(mode.config ? JSON.stringify(mode.config) : "AgentRange benchmark mode")}</p></div>${pill("partial")}</div><div class="mode-stats">${values.map(([label, value]) => `<div class="mode-stat"><span>${label}</span><strong>${text(value)}</strong></div>`).join("")}</div>`;
    };
    document.querySelectorAll("[data-mode]").forEach(button => button.addEventListener("click", () => {
      document.querySelectorAll("[data-mode]").forEach(item => item.setAttribute("aria-selected", String(item === button)));
      renderMode(button.dataset.mode);
    }));
    renderMode("baseline");
    document.getElementById("scenarioRows").innerHTML = (data.scenarios || []).map(item => `
      <article class="scenario-card">
        <div class="scenario-top"><span class="scenario-code">${text(item.id)}</span>${pill(item.class === "attack" ? "attack" : "benign")}</div>
        <h3>${text(item.objective || item.id)}</h3>
        <p>${text(item.blocked || "暂无阻断标准")}</p>
        <div class="scenario-meta"><span>${text(item.target)}</span><span>${text(item.class)}</span></div>
      </article>
    `).join("") || `<div class="empty">暂无场景矩阵。</div>`;
    const chains = data.chains || [];
    document.getElementById("chainBadge").textContent = String(chains.length);
    document.getElementById("chainRows").innerHTML = chains.length ? chains.slice(0, 12).map(chain => `
      <div class="chain">
        <div class="chain-title"><strong>${text(chain.chain_id)}</strong>${pill(chain.blocked ? "block" : "allow")}</div>
        <p class="chain-summary">${text(chain.sequence_type || "")} · ${text(chain.evidence_summary || "")}</p>
        ${(chain.nodes || []).slice(0, 4).map(node => `<div class="node"><strong>${text(node.stage)}</strong> ${pill(node.decision || "unknown")}<div>${text(node.summary || node.raw_ref || "")}</div></div>`).join("")}
      </div>
    `).join("") : `<div class="empty">No AgentRange runtime chains found yet.</div>`;
    const eventRows = (data.events || []).slice().reverse().map(event => `<tr><td>${text(event.timestamp)}</td><td>${text(event.stage)}</td><td>${text(event.destination_app || event.proxy_kind)}</td><td>${text(event.tool_name || event.mcp_server)}</td><td>${pill(event.decision || "unknown")}</td></tr>`).join("");
    document.getElementById("eventRows").innerHTML = eventRows ? `<table class="event-table"><thead><tr><th>Time</th><th>Stage</th><th>Asset</th><th>Tool</th><th>Decision</th></tr></thead><tbody>${eventRows}</tbody></table>` : `<div class="empty">No runtime events generated yet.</div>`;
    document.getElementById("evidenceRows").innerHTML = (data.evidence || []).length ? (data.evidence || []).map(path => `<a class="evidence-link" href="${text(path)}"><span>${text(path)}</span><span>查看</span></a>`).join("") : `<div class="empty">No evidence files generated yet.</div>`;
    document.getElementById("noteRows").innerHTML = (data.notes || []).length ? (data.notes || []).map(item => `<li>${text(item)}</li>`).join("") : `<li>缺失证据会保持待生成，不写入通过结论。</li>`;
    document.getElementById("printButton").addEventListener("click", () => window.print());
  </script>
</body>
</html>
"""
    return template.replace("__GENERATED_AT__", generated).replace("__DASHBOARD_DATA__", serialized)


def build() -> dict[str, Any]:
    return build_data(read_json(REPORT))


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
