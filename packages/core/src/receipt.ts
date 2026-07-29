import { analyzeSession } from "./analyze.js";
import { canonicalJson, hashValue, sha256 } from "./canonical.js";
import type { FlowAnalysis, FlowReceipt, ReceiptVerification } from "./types.js";
import { assertManifest, assertPolicy } from "./validation.js";

export async function compileFlowReceipt(input: {
  manifest: unknown;
  policy: unknown;
  analysis: FlowAnalysis;
  issuedAt?: Date;
}): Promise<FlowReceipt> {
  assertManifest(input.manifest);
  assertPolicy(input.policy);
  const expected = await analyzeSession({
    manifest: input.manifest,
    policy: input.policy,
    analyzedAt: new Date(input.analysis.analyzedAt),
  });
  if (canonicalJson(expected) !== canonicalJson(input.analysis)) throw new Error("Analysis does not match a fresh evaluation.");
  if (input.analysis.status === "blocked") throw new Error("Cannot certify a blocked session.");
  if (input.analysis.coverage.truncated) throw new Error("Cannot certify a truncated analysis.");
  const base = {
    receiptVersion: "1.0" as const,
    sessionId: input.analysis.sessionId,
    manifestHash: await hashValue(input.manifest),
    policyHash: await hashValue(input.policy),
    analysisHash: input.analysis.analysisHash,
    analyzedAt: input.analysis.analyzedAt,
    issuedAt: (input.issuedAt ?? new Date()).toISOString(),
    approvedFindingIds: input.analysis.findings.filter((item) => item.approved).map((item) => item.id),
  };
  return { ...base, receiptHash: await sha256(canonicalJson(base)) };
}

export async function verifyFlowReceipt(input: {
  receipt: FlowReceipt;
  manifest?: unknown;
  policy?: unknown;
}): Promise<ReceiptVerification> {
  const receipt = input.receipt;
  const base: Omit<FlowReceipt, "receiptHash"> = {
    receiptVersion: receipt.receiptVersion,
    sessionId: receipt.sessionId,
    manifestHash: receipt.manifestHash,
    policyHash: receipt.policyHash,
    analysisHash: receipt.analysisHash,
    analyzedAt: receipt.analyzedAt,
    issuedAt: receipt.issuedAt,
    approvedFindingIds: receipt.approvedFindingIds,
  };
  const checks = {
    receiptHash: await sha256(canonicalJson(base)) === receipt.receiptHash,
    manifestHash: true,
    policyHash: true,
    analysisHash: true,
  };
  if (input.manifest !== undefined) {
    assertManifest(input.manifest);
    checks.manifestHash = await hashValue(input.manifest) === receipt.manifestHash;
  }
  if (input.policy !== undefined) {
    assertPolicy(input.policy);
    checks.policyHash = await hashValue(input.policy) === receipt.policyHash;
  }
  if (input.manifest !== undefined && input.policy !== undefined) {
    const analysis = await analyzeSession({
      manifest: input.manifest,
      policy: input.policy,
      analyzedAt: new Date(receipt.analyzedAt),
    });
    checks.analysisHash = analysis.analysisHash === receipt.analysisHash;
  }
  const errors = Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => `${name} check failed`);
  return { valid: errors.length === 0, checks, errors };
}
