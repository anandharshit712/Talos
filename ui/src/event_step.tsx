// One event, and everything the pipeline concluded about it.
//
// The layout follows the pipeline rather than the severity: raw line, what the parser made of it,
// which detector took it, the evidence that detector stood on, and only then the incident. That
// order is the argument the whole demo makes -- a score at the top with the reasoning hidden
// underneath would be the thing Talos exists not to be.
//
// Events that fired nothing are rendered, quietly. They are not noise: a run where fifteen
// ordinary requests stay silent is what makes the two that fire mean anything.

import { useState } from "react";

import type { EvidenceView, IncidentView, TraceStep, VerdictView } from "./trace_types";

const SEVERITY_STYLES: Record<string, { text: string; ring: string; dot: string }> = {
  critical: { text: "text-sev-critical", ring: "ring-sev-critical/40", dot: "bg-sev-critical" },
  high: { text: "text-sev-high", ring: "ring-sev-high/40", dot: "bg-sev-high" },
  medium: { text: "text-sev-medium", ring: "ring-sev-medium/40", dot: "bg-sev-medium" },
  low: { text: "text-sev-low", ring: "ring-sev-low/40", dot: "bg-sev-low" },
};

function severityStyle(severity: string) {
  return SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.low!;
}

function ConfidenceBar({ value }: { value: number }) {
  const percent = Math.round(value * 100);
  return (
    <div className="flex items-center gap-2" title={`confidence ${value.toFixed(2)}`}>
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-edge">
        <div className="h-full rounded-full bg-signal" style={{ width: `${percent}%` }} />
      </div>
      <span className="font-mono text-xs tabular-nums text-quiet">{value.toFixed(2)}</span>
    </div>
  );
}

function Evidence({ evidence }: { evidence: EvidenceView[] }) {
  return (
    <ul className="mt-2 space-y-1.5">
      {evidence.map((item, index) => (
        <li key={index} className="flex gap-2 text-xs leading-relaxed">
          <span className="mt-0.5 shrink-0 rounded bg-edge px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-quiet">
            {item.kind}
          </span>
          <span className="break-all font-mono text-[#c9cdd6]">{item.detail}</span>
        </li>
      ))}
    </ul>
  );
}

function Verdict({ verdict }: { verdict: VerdictView }) {
  return (
    <div className="rounded-lg border border-edge bg-panel/60 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm text-[#e6e8ec]">{verdict.detector}</span>
          <span className="rounded bg-signal/10 px-1.5 py-0.5 font-mono text-[11px] text-signal">
            {verdict.technique}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span
            className="font-mono text-[10px] uppercase tracking-wide text-quiet"
            title={
              verdict.used_llm
                ? "a model wrote the narrative; the detection itself is statistical"
                : "no model was reached: the templated narrative, a supported mode"
            }
          >
            {verdict.used_llm ? "llm narrative" : "statistical"}
          </span>
          <ConfidenceBar value={verdict.confidence} />
        </div>
      </div>

      {verdict.evidence.length > 0 && <Evidence evidence={verdict.evidence} />}

      {verdict.reasoning && (
        <p className="mt-3 border-l-2 border-edge pl-3 text-sm leading-relaxed text-[#b9bfcb]">
          {verdict.reasoning}
        </p>
      )}
    </div>
  );
}

function ScopeRow({ label, values }: { label: string; values: string[] }) {
  if (values.length === 0) return null;
  return (
    <div className="flex gap-2">
      <span className="w-20 shrink-0 text-xs text-quiet">{label}</span>
      <span className="font-mono text-xs text-[#d6dae2]">{values.join(", ")}</span>
    </div>
  );
}

function Incident({ incident }: { incident: IncidentView }) {
  const style = severityStyle(incident.severity);
  return (
    <div className={`rounded-lg border border-edge bg-panel p-4 ring-1 ${style.ring}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className={`h-2 w-2 rounded-full ${style.dot}`} />
        <span className={`font-mono text-xs uppercase tracking-wider ${style.text}`}>
          incident / {incident.severity}
        </span>
        <span className="font-mono text-xs text-quiet">{incident.category}</span>
        {incident.mitre.map((technique) => (
          <span
            key={technique}
            className="rounded border border-edge px-1.5 py-0.5 font-mono text-[10px] text-quiet"
          >
            MITRE {technique}
          </span>
        ))}
      </div>

      <p className="mt-2 text-sm text-[#e6e8ec]">{incident.summary}</p>

      <div className="mt-3 space-y-1">
        <ScopeRow label="accounts" values={incident.affected_accounts} />
        <ScopeRow label="endpoints" values={incident.affected_endpoints} />
        <ScopeRow label="hosts" values={incident.affected_hosts} />
      </div>

      {incident.recommended_actions.length > 0 && (
        <div className="mt-3 border-t border-edge pt-3">
          <span className="text-xs text-quiet">next</span>
          <ul className="mt-1 space-y-1">
            {incident.recommended_actions.map((action) => (
              <li key={action} className="text-sm text-[#c9cdd6]">
                &rarr; {action}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export function EventStep({ step }: { step: TraceStep }) {
  const firing = step.verdicts.filter((verdict) => verdict.attack_detected);
  const quiet = firing.length === 0 && step.incident === null;
  const [open, setOpen] = useState(!quiet);

  return (
    <li className="relative pl-10">
      {/* The rail: one continuous line down the run, with this event's marker on it. */}
      <span
        className={`absolute left-[11px] top-6 h-full w-px ${quiet ? "bg-edge/50" : "bg-edge"}`}
        aria-hidden
      />
      <span
        className={`absolute left-1.5 top-4 h-3 w-3 rounded-full ring-4 ring-ground ${
          step.incident ? severityStyle(step.incident.severity).dot : quiet ? "bg-edge" : "bg-signal"
        }`}
        aria-hidden
      />

      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex w-full items-baseline gap-3 rounded py-2 text-left hover:bg-panel/40"
        aria-expanded={open}
      >
        <span className="font-mono text-xs text-quiet tabular-nums">
          {String(step.index).padStart(2, "0")}
        </span>
        <span className={`font-mono text-sm ${quiet ? "text-quiet" : "text-[#e6e8ec]"}`}>
          {step.summary}
        </span>
        <span className="font-mono text-xs text-quiet">{step.source}</span>
        {quiet && <span className="ml-auto font-mono text-[10px] text-quiet">no verdict</span>}
      </button>

      {open && (
        <div className="space-y-3 pb-4">
          <pre className="overflow-x-auto rounded-lg border border-edge bg-black/40 p-3 font-mono text-xs leading-relaxed text-[#9aa3b2]">
            {step.raw}
          </pre>

          {quiet ? (
            <p className="text-xs text-quiet">
              Parsed as a <span className="font-mono">{step.domain}</span> event and routed. No
              detector claimed it, so nothing was reported.
            </p>
          ) : (
            firing.map((verdict, index) => <Verdict key={index} verdict={verdict} />)
          )}

          {step.incident && <Incident incident={step.incident} />}
        </div>
      )}
    </li>
  );
}
