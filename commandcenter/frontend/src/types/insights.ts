/**
 * Types for the insights endpoints (W1 backend → W2 frontend contract).
 * Shapes mirror the real engines byte-for-byte (verified against
 * modules/reporter.py::_annotate_mitre and coverage_bridge.py 2026-08-17):
 *   /api/coverage    → modules.coverage.CoverageScorer.score_all()   (R-2)
 *   /api/mitre       → reporter._annotate_mitre()                    (R-1)
 *   /api/compliance  → reporter COMPLIANCE_MAP cross-reference       (R-4)
 *   /api/drift       → boneyard "drift" findings                     (R-3)
 *   /api/scenarios   → scenarios.ScenarioLibrary.describe()          (R-6)
 */

// ─── R-1 MITRE ATT&CK ──────────────────────────────────────────────────────

export interface MitreTechnique {
  id: string; // "T1046" | "ALIAS:MCP.TOOL.CALL" | ...
  name: string;
  tactic: string;
}

export interface MitreResponse {
  techniques_used: MitreTechnique[];
  technique_counts: Record<string, number>; // tid → mapped occurrence count
  tactic_coverage: Record<string, number>;  // tactic → distinct technique count
  tactics: string[];                        // attack-forward tactic order
  coverage_pct: number;                     // 0..100 (percent of curated native universe)
  coverage_denominator: number;
  native_techniques_used: number;
  alias_techniques_used: number;
  compliance: Record<string, ComplianceReference>;
  mapped_phases: Record<string, MitreTechnique>; // phase → technique
  // mapped_findings intentionally excluded by the backend (large).
}

// ─── R-4 Compliance ────────────────────────────────────────────────────────

export interface ComplianceReference {
  nist?: string;
  pci?: string;
  iso?: string;
  [key: string]: string | undefined;
}

export interface ComplianceResponse {
  compliance: Record<string, ComplianceReference>; // technique id → frameworks
  techniques_used: MitreTechnique[];              // passthrough of technique dicts
  note: string;                                    // "Curated advisory cross-reference…"
}

// ─── R-2 Prevention strength ───────────────────────────────────────────────

export interface VerdictBreakdownEntry {
  coverage: string; // "verified" | "exploited" | "reachability" | "unknown"
  confidence: number; // 0..1
  weight: number; // phase weight
  contribution: number; // weighted points toward score
  points: number; // rubric points
  [key: string]: unknown;
}

export interface EngagementScore {
  engagement_index: number;
  target: string;
  mode: string;
  phases: string[];
  score: number; // 0..100
  verdict_counts: Record<string, number>; // coverage class → count
  breakdown: Record<string, VerdictBreakdownEntry>; // phase → verdict entry
}

export interface CoverageResponse {
  aggregated: number; // 0..100 mean prevention strength
  count: number; // engagements scored
  engagement_scores: EngagementScore[];
  error?: string;
}

// ─── R-3 Drift ─────────────────────────────────────────────────────────────

export interface DriftEvent {
  id: string | number;
  category: string; // "drift"
  tags: string[];
  data: {
    kind?: string;
    target?: string;
    phases?: Record<string, unknown>;
    ts?: string;
    [key: string]: unknown;
  };
  timestamp?: string;
  epoch?: number;
  risk_score?: number;
  [key: string]: unknown;
}

export interface DriftResponse {
  events: DriftEvent[];
  count: number;
  error?: string;
}

// ─── R-6 Scenarios ─────────────────────────────────────────────────────────

export interface ScenarioInfo {
  name: string;
  description: string;
  phases: string[];
  mitre_techniques: string[];
  version: string;
}

export interface ScenariosResponse {
  scenarios: ScenarioInfo[];
  count: number;
  error?: string;
}
