import type {
  FlowAnalysis,
  SessionManifest,
} from "@taintweave/core";

const symbol = (severity: string): string =>
  ({ critical: "◆", high: "▲", medium: "●", low: "·" })[severity] ?? "·";

export const formatManifest = (manifest: SessionManifest): string => {
  const tools = manifest.servers.reduce((sum, server) => sum + server.tools.length, 0);
  return [
    `TaintWeave · ${manifest.sessionId}`,
    `${manifest.servers.length} servers · ${tools} tools`,
    "",
    ...manifest.servers.flatMap((server) => [
      `${server.id} [${server.trustZone}]`,
      ...server.tools.map((tool) => `  - ${tool.name} · ${tool.produces.join(", ") || "no output"} → ${tool.consumes.join(", ") || "no input"}`),
    ]),
  ].join("\n");
};

export const formatAnalysis = (analysis: FlowAnalysis): string => {
  const lines = [
    `TaintWeave · ${analysis.sessionId}`,
    `Status: ${analysis.status.toUpperCase()} · score ${analysis.score}/100`,
    `${analysis.coverage.servers} servers · ${analysis.coverage.tools} tools · ${analysis.coverage.crossZoneEdges} cross-zone edges`,
  ];
  if (analysis.findings.length === 0) {
    lines.push("", "✓ No forbidden information-flow composition detected.");
  } else {
    lines.push("", "Risk paths");
    for (const item of analysis.findings) {
      lines.push(`  ${symbol(item.severity)} ${item.severity.toUpperCase()} ${item.code.toUpperCase()}${item.approved ? " [approved]" : ""}`);
      lines.push(`    ${item.path.join(" → ")}`);
      lines.push(`    ${item.message}`);
    }
  }
  if (analysis.coverage.truncated) lines.push("", "⚠ Analysis was truncated and cannot be certified.");
  return lines.join("\n");
};

export const formatDot = (analysis: FlowAnalysis): string => {
  const lines = ["digraph TaintWeave {", "  rankdir=LR;", "  node [shape=box fontname=\"monospace\"];"];
  for (const node of analysis.graph.nodes) {
    const color = node.trustZone === "trusted" ? "#74c365" : node.trustZone === "partner" ? "#e4a33a" : "#ef6351";
    lines.push(`  "${node.id}" [label="${node.id}\\n${node.trustZone}" color="${color}"];`);
  }
  for (const edge of analysis.graph.edges) {
    lines.push(`  "${edge.from}" -> "${edge.to}" [label="${edge.dataClasses.join(",")}"];`);
  }
  lines.push("}");
  return lines.join("\n");
};
