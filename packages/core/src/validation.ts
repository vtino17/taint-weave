import type { FlowPolicy, SessionManifest } from "./types.js";

const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const strings = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((entry) => typeof entry === "string");
const text = (value: unknown): value is string =>
  typeof value === "string" && value.trim().length > 0;
const values = (value: unknown, allowed: ReadonlySet<string>): value is string[] =>
  Array.isArray(value)
  && value.every((entry) => typeof entry === "string" && allowed.has(entry));
const dataClasses = new Set([
  "public", "internal", "personal", "confidential", "credential", "untrusted", "any",
]);
const capabilities = new Set([
  "private-read", "untrusted-read", "external-send", "external-read",
  "write", "destructive", "execute-code", "transform",
]);

export function assertManifest(value: unknown): asserts value is SessionManifest {
  if (!object(value) || value.schemaVersion !== "1.0") throw new Error("Unsupported session manifest.");
  if (!text(value.sessionId) || !text(value.summary)) {
    throw new Error("Manifest requires sessionId and summary.");
  }
  if (!Array.isArray(value.servers) || value.servers.length === 0) throw new Error("Manifest requires at least one server.");
  const serverIds = new Set<string>();
  const toolIds = new Set<string>();
  for (const server of value.servers) {
    if (!object(server) || !text(server.id) || !["trusted", "partner", "untrusted"].includes(String(server.trustZone)) || !Array.isArray(server.tools)) {
      throw new Error("Every server requires id, trustZone, and tools.");
    }
    if (serverIds.has(server.id)) throw new Error(`Duplicate server id: ${server.id}`);
    serverIds.add(server.id);
    for (const tool of server.tools) {
      if (!object(tool) || !text(tool.name) || typeof tool.description !== "string") {
        throw new Error("Every tool requires name and description.");
      }
      for (const field of ["consumes", "produces", "sanitizes"]) {
        if (!values(tool[field], dataClasses)) throw new Error(`Tool "${tool.name}" requires known data classes in "${field}".`);
      }
      if (!values(tool.capabilities, capabilities)) throw new Error(`Tool "${tool.name}" requires known capabilities.`);
      if (typeof tool.requiresHumanApproval !== "boolean") throw new Error(`Tool "${tool.name}" requires requiresHumanApproval.`);
      const id = `${server.id}/${tool.name}`;
      if (toolIds.has(id)) throw new Error(`Duplicate tool id: ${id}`);
      toolIds.add(id);
    }
  }
}

export function assertPolicy(value: unknown): asserts value is FlowPolicy {
  if (!object(value) || value.policyVersion !== "1.0") throw new Error("Unsupported flow policy.");
  if (!text(value.sessionId)) throw new Error("Policy requires sessionId.");
  for (const field of ["maxPathLength", "maxFindings"]) {
    if (!Number.isSafeInteger(value[field]) || Number(value[field]) < 1) throw new Error(`Policy "${field}" must be a positive integer.`);
  }
  for (const field of ["sensitiveClasses", "untrustedClasses"]) {
    if (!values(value[field], dataClasses)) throw new Error(`Policy "${field}" must contain known data classes.`);
  }
  for (const field of ["externalSinkCapabilities", "privilegedCapabilities"]) {
    if (!values(value[field], capabilities)) throw new Error(`Policy "${field}" must contain known capabilities.`);
  }
  if (!strings(value.approvals)) throw new Error('Policy "approvals" must be a string array.');
  for (const field of ["requireApprovalAcrossZones", "blockUnapprovedHighRisk"]) {
    if (typeof value[field] !== "boolean") throw new Error(`Policy "${field}" must be boolean.`);
  }
}
