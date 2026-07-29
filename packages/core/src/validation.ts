import type { FlowPolicy, SessionManifest } from "./types.js";

const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const strings = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((entry) => typeof entry === "string");

export function assertManifest(value: unknown): asserts value is SessionManifest {
  if (!object(value) || value.schemaVersion !== "1.0") throw new Error("Unsupported session manifest.");
  if (typeof value.sessionId !== "string" || typeof value.summary !== "string") {
    throw new Error("Manifest requires sessionId and summary.");
  }
  if (!Array.isArray(value.servers) || value.servers.length === 0) throw new Error("Manifest requires at least one server.");
  const serverIds = new Set<string>();
  const toolIds = new Set<string>();
  for (const server of value.servers) {
    if (!object(server) || typeof server.id !== "string" || !["trusted", "partner", "untrusted"].includes(String(server.trustZone)) || !Array.isArray(server.tools)) {
      throw new Error("Every server requires id, trustZone, and tools.");
    }
    if (serverIds.has(server.id)) throw new Error(`Duplicate server id: ${server.id}`);
    serverIds.add(server.id);
    for (const tool of server.tools) {
      if (!object(tool) || typeof tool.name !== "string" || typeof tool.description !== "string") {
        throw new Error("Every tool requires name and description.");
      }
      for (const field of ["consumes", "produces", "sanitizes", "capabilities"]) {
        if (!strings(tool[field])) throw new Error(`Tool "${tool.name}" requires string array "${field}".`);
      }
      if (typeof tool.requiresHumanApproval !== "boolean") throw new Error(`Tool "${tool.name}" requires requiresHumanApproval.`);
      const id = `${server.id}/${tool.name}`;
      if (toolIds.has(id)) throw new Error(`Duplicate tool id: ${id}`);
      toolIds.add(id);
    }
  }
}

export function assertPolicy(value: unknown): asserts value is FlowPolicy {
  if (!object(value) || value.policyVersion !== "1.0") throw new Error("Unsupported flow policy.");
  if (typeof value.sessionId !== "string") throw new Error("Policy requires sessionId.");
  for (const field of ["maxPathLength", "maxFindings"]) {
    if (!Number.isSafeInteger(value[field]) || Number(value[field]) < 1) throw new Error(`Policy "${field}" must be a positive integer.`);
  }
  for (const field of ["sensitiveClasses", "untrustedClasses", "externalSinkCapabilities", "privilegedCapabilities", "approvals"]) {
    if (!strings(value[field])) throw new Error(`Policy "${field}" must be a string array.`);
  }
  for (const field of ["requireApprovalAcrossZones", "blockUnapprovedHighRisk"]) {
    if (typeof value[field] !== "boolean") throw new Error(`Policy "${field}" must be boolean.`);
  }
}
