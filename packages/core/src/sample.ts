import type { FlowPolicy, SessionManifest } from "./types.js";

export const safeManifest: SessionManifest = {
  schemaVersion: "1.0",
  sessionId: "safe-research-session",
  summary: "Search public documentation, sanitize results, and publish a summary.",
  servers: [
    {
      id: "web",
      trustZone: "partner",
      tools: [{
        name: "search_public_docs",
        description: "Read public, potentially untrusted documentation.",
        consumes: ["public"],
        produces: ["untrusted"],
        sanitizes: [],
        capabilities: ["untrusted-read", "external-read"],
        requiresHumanApproval: false,
      }],
    },
    {
      id: "local",
      trustZone: "trusted",
      tools: [{
        name: "sanitize_text",
        description: "Remove active instructions and return inert public text.",
        consumes: ["untrusted"],
        produces: ["public"],
        sanitizes: ["untrusted"],
        capabilities: ["transform"],
        requiresHumanApproval: false,
      }],
    },
    {
      id: "publisher",
      trustZone: "partner",
      tools: [{
        name: "publish_summary",
        description: "Publish reviewed public text.",
        consumes: ["public"],
        produces: ["public"],
        sanitizes: [],
        capabilities: ["external-send"],
        requiresHumanApproval: false,
      }],
    },
  ],
};

export const riskyManifest: SessionManifest = {
  schemaVersion: "1.0",
  sessionId: "incident-response-session",
  summary: "Investigate incidents using vault, calendar, messaging, and shell tools.",
  servers: [
    {
      id: "vault",
      trustZone: "trusted",
      tools: [{
        name: "read_secret",
        description: "Read a deployment credential.",
        consumes: ["internal"],
        produces: ["credential"],
        sanitizes: [],
        capabilities: ["private-read"],
        requiresHumanApproval: false,
      }],
    },
    {
      id: "calendar",
      trustZone: "partner",
      tools: [{
        name: "read_event",
        description: "Read calendar text supplied by external participants.",
        consumes: ["public"],
        produces: ["untrusted"],
        sanitizes: [],
        capabilities: ["untrusted-read", "external-read"],
        requiresHumanApproval: false,
      }],
    },
    {
      id: "context",
      trustZone: "trusted",
      tools: [{
        name: "merge_context",
        description: "Combine tool results into incident context.",
        consumes: ["any"],
        produces: ["internal"],
        sanitizes: [],
        capabilities: ["transform"],
        requiresHumanApproval: false,
      }],
    },
    {
      id: "messenger",
      trustZone: "partner",
      tools: [{
        name: "send_message",
        description: "Send supplied content to an external recipient.",
        consumes: ["any"],
        produces: ["public"],
        sanitizes: [],
        capabilities: ["external-send", "write"],
        requiresHumanApproval: true,
      }],
    },
    {
      id: "shell",
      trustZone: "trusted",
      tools: [{
        name: "run_command",
        description: "Execute a local shell command.",
        consumes: ["any"],
        produces: ["internal"],
        sanitizes: [],
        capabilities: ["execute-code", "destructive"],
        requiresHumanApproval: true,
      }],
    },
  ],
};

export const policyFor = (sessionId: string): FlowPolicy => ({
  policyVersion: "1.0",
  sessionId,
  maxPathLength: 4,
  maxFindings: 100,
  sensitiveClasses: ["personal", "confidential", "credential"],
  untrustedClasses: ["untrusted"],
  externalSinkCapabilities: ["external-send"],
  privilegedCapabilities: ["execute-code", "destructive"],
  requireApprovalAcrossZones: true,
  blockUnapprovedHighRisk: true,
  approvals: [],
});

export const riskyPolicy = policyFor(riskyManifest.sessionId);
export const safePolicy = policyFor(safeManifest.sessionId);
