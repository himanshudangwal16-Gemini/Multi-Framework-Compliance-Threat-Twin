export interface GraphNode {
  id: string;
  label: string;
  type: "compute" | "storage" | "database" | "network" | "iam" | "loadbalancer" | "internet" | "user" | "other";
  status: "secure" | "vulnerable" | "compromised";
  properties: Record<string, string>;
  description?: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  type: "network" | "iam_access" | "trust" | "vulnerability";
  severity?: "low" | "medium" | "high" | "critical";
}

export interface AssetMap {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ComplianceViolation {
  id: string;
  framework: "NIST SP 800-53" | "ISO/IEC 27001" | "SOC 2 Type II" | "CIS Benchmarks";
  code: string; // e.g. "AC-4", "A.9.4.1"
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  targetNodeId: string;
  status: "FAIL" | "PASS";
}

export interface AttackStep {
  stepNumber: number;
  nodeId: string; // Resource node being accessed or exploited
  action: string; // Exploit description
  explanation: string; // Why it can occur
}

export interface AttackPath {
  id: string;
  title: string;
  mitreTechniques: string[]; // e.g., ["T1190 - Exploit Public-Facing Application"]
  steps: AttackStep[];
  exfiltrationTargetId: string; // Culmination point
  impactDescription: string;
  exploitPayloadSimulator?: string; // Theoretical bash / curl script demonstrating exploit
}

export interface RemediationPatch {
  id: string;
  targetNodeId: string;
  frameworkCode: string; // Mapping back to compliance gap
  title: string;
  filename: string; // e.g. "main.tf", "deployment.yaml"
  language: string; // e.g. "hcl", "yaml", "json"
  originalCode: string;
  remediatedCode: string;
  explanation: string;
}

export interface DualAnalysisResponse {
  assetMap: AssetMap;
  violations: ComplianceViolation[];
  attackPaths: AttackPath[];
  remediations: RemediationPatch[];
}
