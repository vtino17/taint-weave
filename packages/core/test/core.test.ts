import { describe, expect, it } from "vitest";
import {
  analyzeSession,
  buildGraph,
  compileFlowReceipt,
  policyFor,
  riskyManifest,
  riskyPolicy,
  safeManifest,
  safePolicy,
  verifyFlowReceipt,
} from "../src/index.js";

const at = new Date("2026-07-29T09:00:00.000Z");

describe("composition graph", () => {
  it("qualifies tool IDs by server", () => {
    const graph = buildGraph(riskyManifest);
    expect(graph.nodes.some((node) => node.id === "vault/read_secret")).toBe(true);
  });

  it("links compatible producer and consumer classes", () => {
    const graph = buildGraph(riskyManifest);
    expect(graph.edges.some((edge) => edge.from === "vault/read_secret" && edge.to === "messenger/send_message")).toBe(true);
  });

  it("marks cross-zone edges", () => {
    const graph = buildGraph(riskyManifest);
    expect(graph.edges.some((edge) => edge.crossesTrustZone)).toBe(true);
  });

  it("does not create self edges", () => {
    const graph = buildGraph(riskyManifest);
    expect(graph.edges.every((edge) => edge.from !== edge.to)).toBe(true);
  });
});

describe("flow analysis", () => {
  it("keeps a sanitized composition safe", async () => {
    const result = await analyzeSession({ manifest: safeManifest, policy: safePolicy, analyzedAt: at });
    expect(result.status).toBe("safe");
    expect(result.findings).toHaveLength(0);
    expect(result.score).toBe(100);
  });

  it("blocks the risky multi-server session", async () => {
    const result = await analyzeSession({ manifest: riskyManifest, policy: riskyPolicy, analyzedAt: at });
    expect(result.status).toBe("blocked");
    expect(result.coverage.servers).toBe(5);
    expect(result.coverage.crossZoneEdges).toBeGreaterThan(0);
  });

  it.each([
    "session-lethal-trifecta",
    "sensitive-data-exfiltration-path",
    "untrusted-to-privileged-path",
    "sensitive-cross-zone-flow",
    "declared-human-approval",
  ])("detects %s", async (code) => {
    const result = await analyzeSession({ manifest: riskyManifest, policy: riskyPolicy, analyzedAt: at });
    expect(result.findings.some((item) => item.code === code)).toBe(true);
  });

  it("returns concrete multi-tool paths", async () => {
    const result = await analyzeSession({ manifest: riskyManifest, policy: riskyPolicy, analyzedAt: at });
    const flow = result.findings.find((item) => item.code === "sensitive-data-exfiltration-path");
    expect(flow?.path[0]).toBe("vault/read_secret");
    expect(flow?.path.at(-1)).toBe("messenger/send_message");
  });

  it("adds remediation choices", async () => {
    const result = await analyzeSession({ manifest: riskyManifest, policy: riskyPolicy, analyzedAt: at });
    expect(result.findings.every((item) => item.remediation.length === 3)).toBe(true);
  });

  it("binds approval to finding fingerprints", async () => {
    const initial = await analyzeSession({ manifest: riskyManifest, policy: riskyPolicy, analyzedAt: at });
    const policy = { ...riskyPolicy, approvals: initial.findings.map((item) => item.id) };
    const reviewed = await analyzeSession({ manifest: riskyManifest, policy, analyzedAt: at });
    expect(reviewed.status).toBe("safe");
    expect(reviewed.findings.every((item) => item.approved)).toBe(true);
  });

  it("rejects a policy for another session", async () => {
    await expect(analyzeSession({
      manifest: safeManifest,
      policy: policyFor("other"),
    })).rejects.toThrow("different sessions");
  });

  it("rejects duplicate server IDs", async () => {
    await expect(analyzeSession({
      manifest: { ...safeManifest, servers: [safeManifest.servers[0], safeManifest.servers[0]] },
      policy: safePolicy,
    })).rejects.toThrow("Duplicate server");
  });

  it("marks capped analysis as truncated", async () => {
    const policy = { ...riskyPolicy, maxFindings: 1 };
    const result = await analyzeSession({ manifest: riskyManifest, policy, analyzedAt: at });
    expect(result.coverage.truncated).toBe(true);
    expect(result.findings).toHaveLength(1);
  });
});

describe("flow receipts", () => {
  it("compiles and verifies a safe receipt", async () => {
    const analysis = await analyzeSession({ manifest: safeManifest, policy: safePolicy, analyzedAt: at });
    const receipt = await compileFlowReceipt({ manifest: safeManifest, policy: safePolicy, analysis, issuedAt: at });
    const result = await verifyFlowReceipt({ receipt, manifest: safeManifest, policy: safePolicy });
    expect(result.valid).toBe(true);
    expect(Object.values(result.checks).every(Boolean)).toBe(true);
  });

  it("refuses a blocked session receipt", async () => {
    const analysis = await analyzeSession({ manifest: riskyManifest, policy: riskyPolicy, analyzedAt: at });
    await expect(compileFlowReceipt({ manifest: riskyManifest, policy: riskyPolicy, analysis })).rejects.toThrow("blocked");
  });

  it("refuses a truncated analysis receipt", async () => {
    const policy = { ...riskyPolicy, maxFindings: 1, blockUnapprovedHighRisk: false };
    const analysis = await analyzeSession({ manifest: riskyManifest, policy, analyzedAt: at });
    await expect(compileFlowReceipt({ manifest: riskyManifest, policy, analysis })).rejects.toThrow("truncated");
  });

  it("detects receipt tampering", async () => {
    const analysis = await analyzeSession({ manifest: safeManifest, policy: safePolicy, analyzedAt: at });
    const receipt = await compileFlowReceipt({ manifest: safeManifest, policy: safePolicy, analysis, issuedAt: at });
    const result = await verifyFlowReceipt({ receipt: { ...receipt, sessionId: "forged" } });
    expect(result.valid).toBe(false);
    expect(result.checks.receiptHash).toBe(false);
  });
});
