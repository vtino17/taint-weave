import {
  analyzeSession,
  riskyManifest,
  riskyPolicy,
  safeManifest,
  safePolicy,
} from "@taintweave/core";
import type {
  FlowAnalysis,
  GraphNode,
  Severity,
} from "@taintweave/core";
import "./styles.css";

const root = document.querySelector<HTMLDivElement>("#app");
if (!root) throw new Error("Missing application root.");

let scenario: "risky" | "safe" = "risky";
let filter: Severity | "all" = "all";

const escapeHtml = (value: unknown): string =>
  String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

const nodeCard = (node: GraphNode): string => `
  <article class="node node--${node.trustZone}">
    <div class="node__head"><span>${escapeHtml(node.serverId)}</span><small>${node.trustZone}</small></div>
    <h3>${escapeHtml(node.tool.name)}</h3>
    <p>${escapeHtml(node.tool.description)}</p>
    <div class="tags">${node.tool.produces.map((item) => `<span class="tag tag--out">+ ${item}</span>`).join("")}${node.tool.consumes.map((item) => `<span class="tag">→ ${item}</span>`).join("")}</div>
  </article>
`;

const topology = (analysis: FlowAnalysis): string => {
  const zones = ["trusted", "partner", "untrusted"] as const;
  return zones.map((zone) => {
    const nodes = analysis.graph.nodes.filter((node) => node.trustZone === zone);
    return `
      <div class="zone">
        <div class="zone__title"><span>${zone}</span><small>${nodes.length} tools</small></div>
        <div class="zone__nodes">${nodes.length > 0 ? nodes.map(nodeCard).join("") : `<div class="zone__empty">No tools</div>`}</div>
      </div>
    `;
  }).join("");
};

const findings = (analysis: FlowAnalysis): string => {
  const selected = analysis.findings.filter((item) => filter === "all" || item.severity === filter);
  if (selected.length === 0) {
    return `<div class="empty"><span>✓</span><h3>No forbidden route</h3><p>Declared sanitization breaks the tainted path before a sensitive sink.</p></div>`;
  }
  return selected.map((item) => `
    <article class="finding finding--${item.severity}">
      <div class="finding__rail"><span>${item.severity}</span><i></i></div>
      <div>
        <div class="finding__meta"><code>${escapeHtml(item.code)}</code><small>#${item.id}</small></div>
        <h3>${escapeHtml(item.message)}</h3>
        <div class="path">${item.path.map((node, index) => `<span>${escapeHtml(node)}${index < item.path.length - 1 ? "<b>→</b>" : ""}</span>`).join("")}</div>
        <div class="finding__foot"><span>taint: ${item.dataClasses.join(", ")}</span><span>${item.crossesTrustZone ? "cross-zone" : "same-zone"}</span></div>
      </div>
    </article>
  `).join("");
};

const download = (analysis: FlowAnalysis): void => {
  const blob = new Blob([`${JSON.stringify(analysis, null, 2)}\n`], { type: "application/json" });
  const anchor = document.createElement("a");
  anchor.href = URL.createObjectURL(blob);
  anchor.download = `taint-weave-${scenario}.json`;
  anchor.click();
  URL.revokeObjectURL(anchor.href);
};

const render = async (): Promise<void> => {
  const manifest = scenario === "risky" ? riskyManifest : safeManifest;
  const policy = scenario === "risky" ? riskyPolicy : safePolicy;
  const analysis = await analyzeSession({
    manifest,
    policy,
    analyzedAt: new Date("2026-07-29T09:00:00.000Z"),
  });
  const filters: Array<Severity | "all"> = ["all", "critical", "high", "medium", "low"];
  root.innerHTML = `
    <header>
      <a class="brand" href="#"><span>TW</span>TaintWeave</a>
      <div class="header__center">MCP SESSION / INFORMATION-FLOW COMPILER</div>
      <a class="source" href="https://github.com/vtino17/taint-weave">Source ↗</a>
    </header>

    <main>
      <section class="hero">
        <div>
          <div class="kicker">SEE THE RISK BETWEEN TOOLS</div>
          <h1>Individually benign.<br><em>Dangerous together.</em></h1>
        </div>
        <div class="hero__side">
          <p>Compile every cross-server data route before an MCP toolset enters an agent session.</p>
          <div class="switch">
            <button data-scenario="risky" class="${scenario === "risky" ? "active" : ""}">Incident session</button>
            <button data-scenario="safe" class="${scenario === "safe" ? "active" : ""}">Sanitized session</button>
          </div>
        </div>
      </section>

      <section class="verdict verdict--${analysis.status}">
        <div><small>DECISION</small><strong>${analysis.status}</strong></div>
        <div><small>RISK SCORE</small><strong>${analysis.score}<i>/100</i></strong></div>
        <div><small>SURFACE</small><strong>${analysis.coverage.servers}<i> servers</i></strong></div>
        <div><small>GRAPH</small><strong>${analysis.graph.edges.length}<i> edges</i></strong></div>
        <button id="download">Report ↓</button>
      </section>

      <section class="section">
        <div class="section__title"><span>01</span><div><h2>Session topology</h2><p>Tools grouped by the trust boundary that operates them.</p></div></div>
        <div class="topology">${topology(analysis)}</div>
      </section>

      <section class="section">
        <div class="section__bar">
          <div class="section__title"><span>02</span><div><h2>Compiled risk paths</h2><p>Shortest accountable routes from tainted source to sensitive sink.</p></div></div>
          <div class="filters">${filters.map((item) => `<button data-filter="${item}" class="${filter === item ? "active" : ""}">${item}</button>`).join("")}</div>
        </div>
        <div class="findings">${findings(analysis)}</div>
      </section>

      <section class="rules">
        <div><span>03</span><h2>Deterministic controls</h2></div>
        <ul>
          <li><b>01</b><span>Private data → external sink</span></li>
          <li><b>02</b><span>Untrusted input → privileged action</span></li>
          <li><b>03</b><span>Cross-zone sensitive propagation</span></li>
          <li><b>04</b><span>Session-level lethal trifecta</span></li>
          <li><b>05</b><span>Fingerprint-bound approvals</span></li>
          <li><b>06</b><span>Bounded graph exploration</span></li>
        </ul>
      </section>
    </main>

    <footer><span>TaintWeave / 0.1.0</span><span>Local-first · deterministic · model-free</span></footer>
  `;
  root.querySelectorAll<HTMLButtonElement>("[data-scenario]").forEach((button) => {
    button.addEventListener("click", () => {
      scenario = button.dataset.scenario as "risky" | "safe";
      filter = "all";
      void render();
    });
  });
  root.querySelectorAll<HTMLButtonElement>("[data-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      filter = button.dataset.filter as Severity | "all";
      void render();
    });
  });
  root.querySelector<HTMLButtonElement>("#download")?.addEventListener("click", () => download(analysis));
};

await render();
