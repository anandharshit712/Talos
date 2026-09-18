// The wire shape of `demo_trace_engine.Trace`, mirrored field for field.
//
// It is a mirror rather than a generated client on purpose: the trace is five small dataclasses
// that are frozen alongside the P1 contracts, and a code-generation step in the build would be
// more machinery than the thing it generates. If these drift, the backend test
// `test_the_prepared_chain_traces_the_same_through_http_as_it_does_in_the_terminal` still passes
// while the page renders `undefined`, so treat any change to the Python dataclasses as a change
// here too.

export interface EvidenceView {
  kind: string;
  detail: string;
}

export interface VerdictView {
  detector: string;
  category: string;
  technique: string;
  attack_detected: boolean;
  confidence: number;
  used_llm: boolean;
  reasoning: string;
  evidence: EvidenceView[];
}

export interface IncidentView {
  incident_id: string;
  category: string;
  severity: string;
  confidence: number;
  summary: string;
  mitre: string[];
  affected_accounts: string[];
  affected_endpoints: string[];
  affected_hosts: string[];
  recommended_actions: string[];
}

export interface TraceStep {
  index: number;
  raw: string;
  domain: string;
  source: string;
  summary: string;
  verdicts: VerdictView[];
  incident: IncidentView | null;
}

export interface Trace {
  title: string;
  events: number;
  skipped: number;
  incidents: number;
  used_llm: boolean;
  steps: TraceStep[];
}

export interface DemoChain {
  domain: string;
  title: string;
  log: string;
}
