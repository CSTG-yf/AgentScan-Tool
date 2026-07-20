(() => {
  "use strict";
  const data = window.AGENTRANGE_DASHBOARD_DATA;
  if (!data) {
    document.getElementById("reportState").textContent = "报告数据缺失";
    return;
  }

  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const fmtPct = value => value == null ? "待实测" : `${(value * 100).toFixed(value === 1 ? 0 : 1)}%`;
  const fmtMs = value => value == null ? "待实测" : `${Math.round(value)}ms`;
  const statusLabel = { pass: "通过", wait: "待实测", fail: "未通过", partial: "部分证据" };
  const pill = status => el("span", `status-pill status-${status}`, statusLabel[status] || status);

  const ready = data.traceability.counts.evidence_ready;
  const total = data.traceability.total;
  const progress = Math.round((ready / total) * 100);
  document.getElementById("readinessRing").style.setProperty("--progress", `${progress}%`);
  document.getElementById("readinessValue").textContent = `${progress}%`;
  document.getElementById("readinessFraction").textContent = `${ready} / ${total}`;
  document.getElementById("generatedAt").textContent = data.meta.generated_at;
  document.getElementById("reportState").textContent = data.meta.report_state;

  const metricGrid = document.getElementById("metricGrid");
  data.snapshot.forEach((item, index) => {
    const card = el("article", "metric-card");
    card.style.setProperty("--accent", item.accent);
    const top = el("div", "metric-top");
    top.append(el("span", "metric-index", String(index + 1).padStart(2, "0")), pill(item.status));
    card.append(top, el("div", "metric-value", item.value), el("p", "metric-label", item.label), el("p", "metric-note", item.note));
    metricGrid.append(card);
  });

  const scorecard = document.getElementById("scorecardTable");
  const head = el("div", "score-row score-head");
  head.setAttribute("role", "row");
  ["指标", "口径", "当前结果", "状态"].forEach(text => {
    const cell = el("span", "", text);
    cell.setAttribute("role", "columnheader");
    head.append(cell);
  });
  scorecard.append(head);
  data.scorecard.forEach(item => {
    const row = el("div", "score-row");
    row.setAttribute("role", "row");
    const name = el("div", "score-name");
    name.append(el("strong", "", item.name), el("small", "", item.target));
    const actual = el("div", "score-actual");
    actual.append(el("strong", "", item.actual), el("small", "", item.detail || ""));
    const scope = el("div", "score-target", item.scope);
    [name, scope, actual].forEach(cell => cell.setAttribute("role", "cell"));
    const status = pill(item.status);
    status.setAttribute("role", "cell");
    row.append(name, scope, actual, status);
    scorecard.append(row);
  });

  const renderMode = modeName => {
    const panel = document.getElementById("modePanel");
    panel.replaceChildren();
    const mode = data.modes[modeName];
    if (!mode.available) {
      const empty = el("div", "mode-empty");
      empty.append(el("strong", "", `${mode.label} 数据待生成`), el("p", "", mode.message));
      panel.append(empty);
      return;
    }
    const title = el("div", "mode-title");
    const titleCopy = el("div", "");
    titleCopy.append(el("h3", "", mode.label), el("p", "", mode.description));
    title.append(titleCopy, pill(mode.status));
    const stats = el("div", "mode-stats");
    const values = [
      ["有效实例", `${mode.valid}/${mode.total}`],
      ["正常成功率", fmtPct(mode.normal_success_rate)],
      ["Recall", modeName === "baseline" ? "基线不适用" : fmtPct(mode.recall)],
      ["FPR", modeName === "baseline" ? fmtPct(mode.fpr) : fmtPct(mode.fpr)],
      ["端到端 p95", fmtMs(mode.p95_ms)]
    ];
    values.forEach(([label, value]) => { const item = el("div", "mode-stat"); item.append(el("span", "", label), el("strong", "", value)); stats.append(item); });
    panel.append(title, stats);
  };
  document.querySelectorAll("[data-mode]").forEach(button => button.addEventListener("click", () => {
    document.querySelectorAll("[data-mode]").forEach(item => item.setAttribute("aria-selected", String(item === button)));
    renderMode(button.dataset.mode);
  }));
  renderMode("baseline");

  const scenarios = document.getElementById("scenarioGrid");
  data.scenarios.forEach(item => {
    const card = el("article", "scenario-card");
    const top = el("div", "scenario-top");
    top.append(el("span", "scenario-code", item.id), pill(item.status));
    const meta = el("div", "scenario-meta");
    meta.append(el("span", "", item.target), el("span", "", item.checkpoint));
    card.append(top, el("h3", "", item.title), el("p", "", item.description), meta);
    scenarios.append(card);
  });

  const loop = document.getElementById("loopList");
  data.loop.forEach(item => { const node = el("li", ""); node.append(el("h3", "", item.title), el("p", "", item.description), pill(item.status)); loop.append(node); });

  const ruleList = document.getElementById("ruleList");
  data.rules.items.forEach(item => {
    const row = el("div", "rule-row");
    const label = el("div", "rule-label");
    label.append(el("span", "", item.id), el("span", "", `${item.elapsed_ms.toFixed(3)}ms`));
    const track = el("div", "rule-track");
    const fill = el("div", "rule-fill");
    fill.style.width = `${Math.min(100, (item.elapsed_ms / data.rules.limit_ms) * 100)}%`;
    track.append(fill); row.append(label, track); ruleList.append(row);
  });

  document.getElementById("traceBadge").textContent = `${ready} / ${total}`;
  const traceSummary = document.getElementById("traceSummary");
  [[data.traceability.counts.evidence_ready, "证据齐全"], [data.traceability.counts.awaiting, "待补证据"], [data.traceability.counts.not_implemented, "未实现"]].forEach(([value, label]) => {
    const item = el("div", "trace-stat"); item.append(el("strong", "", String(value)), el("span", "", label)); traceSummary.append(item);
  });
  const requirementList = document.getElementById("requirementList");
  data.traceability.items.forEach(item => requirementList.append(el("span", `requirement ${item.ready ? "ready" : "wait"}`, `${item.id} · ${item.ready ? "证据齐全" : "待补证据"}`)));

  const evidenceLinks = document.getElementById("evidenceLinks");
  data.evidence.forEach(item => {
    const link = el("a", "evidence-link"); link.href = item.href; link.target = "_blank"; link.rel = "noopener";
    link.append(el("span", "", item.label), el("span", "", "查看 →")); evidenceLinks.append(link);
  });
  document.getElementById("printButton").addEventListener("click", () => window.print());
})();
