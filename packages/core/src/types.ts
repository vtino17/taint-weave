export type TrustZone = "trusted" | "partner" | "untrusted";
export type DataClass = "public" | "internal" | "personal" | "confidential" | "credential" | "untrusted" | "any";
export type Capability =
  | "private-read"
  | "untrusted-read"
  | "external-send"
  | "external-read"
  | "write"
  | "destructive"
  | "execute-code"
  | "transform";
export type Severity = "low" | "medium" | "high" | "critical";

export interface ToolProfile {
  name: string;
  description: string;
  consumes: DataClass[];
  produces: DataClass[];
  sanitizes: DataClass[];
  capabilities: Capability[];
  requiresHumanApproval: boolean;
}

export interface ServerProfile {
  id: string;
  trustZone: TrustZone;
  tools: ToolProfile[];
}

export interface SessionManifest {
  schemaVersion: "1.0";
  sessionId: string;
  summary: string;
  servers: ServerProfile[];
}

export interface FlowPolicy {
  policyVersion: "1.0";
  sessionId: string;
  maxPathLength: number;
  maxFindings: number;
  sensitiveClasses: DataClass[];
  untrustedClasses: DataClass[];
  externalSinkCapabilities: Capability[];
  privilegedCapabilities: Capability[];
  requireApprovalAcrossZones: boolean;
  blockUnapprovedHighRisk: boolean;
  approvals: string[];
}

export interface GraphNode {
  id: string;
  serverId: string;
  trustZone: TrustZone;
  tool: ToolProfile;
}

export interface GraphEdge {
  from: string;
  to: string;
  dataClasses: DataClass[];
  crossesTrustZone: boolean;
}

export interface FlowFinding {
  id: string;
  code: string;
  severity: Severity;
  message: string;
  path: string[];
  dataClasses: DataClass[];
  crossesTrustZone: boolean;
  approved: boolean;
  remediation: string[];
}

export interface FlowAnalysis {
  sessionId: string;
  status: "safe" | "review" | "blocked";
  score: number;
  analyzedAt: string;
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  coverage: {
    servers: number;
    tools: number;
    crossZoneEdges: number;
    exploredStates: number;
    truncated: boolean;
  };
  findings: FlowFinding[];
  analysisHash: string;
}

export interface FlowReceipt {
  receiptVersion: "1.0";
  sessionId: string;
  manifestHash: string;
  policyHash: string;
  analysisHash: string;
  analyzedAt: string;
  issuedAt: string;
  approvedFindingIds: string[];
  receiptHash: string;
}

export interface ReceiptVerification {
  valid: boolean;
  checks: Record<"receiptHash" | "manifestHash" | "policyHash" | "analysisHash", boolean>;
  errors: string[];
}
