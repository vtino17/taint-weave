import { canonicalJson, hashValue, sha256 } from "./canonical.js";
import { acceptedTaints, buildGraph } from "./graph.js";
import type {
  Capability,
  DataClass,
  FlowAnalysis,
  FlowFinding,
  GraphNode,
  Severity,
} from "./types.js";
import { assertManifest, assertPolicy } from "./validation.js";

type RawFinding = Omit<FlowFinding, "id" | "approved">;
interface State {
  path: string[];
  taints: Set<DataClass>;
  crossed: boolean;
}

const hasCapability = (node: GraphNode, capabilities: Capability[]): boolean =>
  node.tool.capabilities.some((item) => capabilities.includes(item));
const intersects = <T>(left: T[], right: T[]): T[] => left.filter((item) => right.includes(item));
const unique = <T>(items: T[]): T[] => [...new Set(items)];
const severityCost: Record<Severity, number> = { low: 3, medium: 9, high: 20, critical: 34 };

const remediation = (source: string, sink: string, kind: string): string[] => [
  `Separate ${source} and ${sink} into different agent sessions.`,
  `Insert a trusted sanitizer before ${sink} for ${kind} data.`,
  "Bind an explicit human approval to this exact finding fingerprint.",
];

const finding = (
  code: string,
  severity: Severity,
  message: string,
  path: string[],
  dataClasses: DataClass[],
  crossesTrustZone: boolean,
): RawFinding => ({
  code,
  severity,
  message,
  path,
  dataClasses: unique(dataClasses).sort(),
  crossesTrustZone,
  remediation: remediation(path[0] ?? "source", path.at(-1) ?? "sink", dataClasses.join(", ")),
});

const stateKey = (state: State): string =>
  `${state.path[0]}:${state.path.at(-1)}:${[...state.taints].sort().join(",")}:${state.path.length}:${state.crossed}`;

export async function analyzeSession(input: {
  manifest: unknown;
  policy: unknown;
  analyzedAt?: Date;
}): Promise<FlowAnalysis> {
  assertManifest(input.manifest);
  assertPolicy(input.policy);
  const manifest = input.manifest;
  const policy = input.policy;
  if (manifest.sessionId !== policy.sessionId) throw new Error("Manifest and policy target different sessions.");
  const graph = buildGraph(manifest);
  const byId = new Map(graph.nodes.map((node) => [node.id, node]));
  const raw: RawFinding[] = [];
  const findingKeys = new Set<string>();
  const add = (item: RawFinding): void => {
    const key = `${item.code}:${item.path[0]}:${item.path.at(-1)}:${item.dataClasses.join(",")}`;
    if (!findingKeys.has(key)) {
      findingKeys.add(key);
      raw.push(item);
    }
  };

  const privateSource = graph.nodes.find((node) =>
    node.tool.capabilities.includes("private-read") ||
    intersects(node.tool.produces, policy.sensitiveClasses).length > 0);
  const untrustedSource = graph.nodes.find((node) =>
    node.tool.capabilities.includes("untrusted-read") ||
    intersects(node.tool.produces, policy.untrustedClasses).length > 0);
  const externalSink = graph.nodes.find((node) => hasCapability(node, policy.externalSinkCapabilities));
  if (privateSource && untrustedSource && externalSink) {
    add(finding(
      "session-lethal-trifecta",
      "critical",
      "The session combines private-data access, untrusted content, and external communication.",
      unique([privateSource.id, untrustedSource.id, externalSink.id]),
      unique([...intersects(privateSource.tool.produces, policy.sensitiveClasses), ...intersects(untrustedSource.tool.produces, policy.untrustedClasses)]),
      new Set([privateSource.trustZone, untrustedSource.trustZone, externalSink.trustZone]).size > 1,
    ));
  }

  for (const node of graph.nodes) {
    if (node.trustZone === "untrusted" && hasCapability(node, policy.privilegedCapabilities)) {
      add(finding(
        "untrusted-server-privileged-tool",
        "high",
        "An untrusted server exposes a privileged capability.",
        [node.id],
        node.tool.consumes,
        false,
      ));
    }
    if (node.tool.requiresHumanApproval) {
      add(finding(
        "declared-human-approval",
        "high",
        "This tool declares that execution requires human approval.",
        [node.id],
        node.tool.consumes,
        false,
      ));
    }
  }

  const queue: State[] = graph.nodes
    .filter((node) => intersects(node.tool.produces, [...policy.sensitiveClasses, ...policy.untrustedClasses]).length > 0)
    .map((node) => ({
      path: [node.id],
      taints: new Set(intersects(node.tool.produces, [...policy.sensitiveClasses, ...policy.untrustedClasses])),
      crossed: false,
    }));
  const visited = new Set<string>();
  let exploredStates = 0;
  let truncated = false;
  const stateLimit = Math.max(1000, policy.maxFindings * 200);

  while (queue.length > 0) {
    const state = queue.shift();
    if (!state) break;
    const key = stateKey(state);
    if (visited.has(key)) continue;
    visited.add(key);
    exploredStates++;
    if (exploredStates > stateLimit) {
      truncated = true;
      break;
    }
    const currentId = state.path.at(-1);
    const current = currentId ? byId.get(currentId) : undefined;
    if (!current) continue;
    const sensitive = intersects([...state.taints], policy.sensitiveClasses);
    const untrusted = intersects([...state.taints], policy.untrustedClasses);
    if (sensitive.length > 0 && hasCapability(current, policy.externalSinkCapabilities)) {
      add(finding("sensitive-data-exfiltration-path", "critical", "Sensitive data can reach an external communication capability.", state.path, sensitive, state.crossed));
    }
    if (untrusted.length > 0 && hasCapability(current, policy.privilegedCapabilities)) {
      add(finding("untrusted-to-privileged-path", "critical", "Untrusted content can reach a privileged capability.", state.path, untrusted, state.crossed));
    }
    if (state.crossed && sensitive.length > 0 && policy.requireApprovalAcrossZones) {
      add(finding("sensitive-cross-zone-flow", "high", "Sensitive data can cross a server trust boundary.", state.path, sensitive, true));
    }
    if (state.path.length >= policy.maxPathLength) continue;
    for (const next of graph.nodes) {
      if (state.path.includes(next.id)) continue;
      const accepted = acceptedTaints(state.taints, next.tool.consumes);
      if (accepted.length === 0) continue;
      const nextTaints = new Set<DataClass>([...accepted, ...next.tool.produces]);
      for (const clean of next.tool.sanitizes) nextTaints.delete(clean);
      queue.push({
        path: [...state.path, next.id],
        taints: nextTaints,
        crossed: state.crossed || current.trustZone !== next.trustZone,
      });
    }
  }
  if (raw.length > policy.maxFindings) truncated = true;
  const selected = raw.slice(0, policy.maxFindings);
  const findings: FlowFinding[] = [];
  for (const item of selected) {
    const id = (await sha256(canonicalJson(item))).slice(0, 16);
    findings.push({ ...item, id, approved: policy.approvals.includes(id) });
  }
  const unapproved = findings.filter((item) => !item.approved);
  const blocked = policy.blockUnapprovedHighRisk && unapproved.some((item) => ["high", "critical"].includes(item.severity));
  const review = unapproved.length > 0;
  const score = Math.max(0, 100 - unapproved.reduce((sum, item) => sum + severityCost[item.severity], 0));
  const base = {
    sessionId: manifest.sessionId,
    status: blocked ? "blocked" as const : review ? "review" as const : "safe" as const,
    score,
    analyzedAt: (input.analyzedAt ?? new Date()).toISOString(),
    graph,
    coverage: {
      servers: manifest.servers.length,
      tools: graph.nodes.length,
      crossZoneEdges: graph.edges.filter((edge) => edge.crossesTrustZone).length,
      exploredStates,
      truncated,
    },
    findings,
  };
  return { ...base, analysisHash: await hashValue(base) };
}
