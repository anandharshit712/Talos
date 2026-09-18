// The trace visualiser: a log goes in, the pipeline's reasoning comes out.
//
// The page deliberately shows its input. An analyst -- or a judge -- can edit the log, add a
// payload, and watch which detector claims it and on what evidence. A canned animation would
// have been easier to make impressive and would have proved nothing; every trace on this page
// comes back from the same pipeline `talos scan` runs.

import { useCallback, useEffect, useState } from "react";

import { EventStep } from "./event_step";
import { fetchChains, runTrace } from "./trace_client";
import type { DemoChain, Trace } from "./trace_types";

function Stat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="flex flex-col">
      <span className={`font-mono text-lg tabular-nums ${tone ?? "text-[#e6e8ec]"}`}>{value}</span>
      <span className="text-[11px] uppercase tracking-wider text-quiet">{label}</span>
    </div>
  );
}

export function TracePage() {
  const [chains, setChains] = useState<DemoChain[]>([]);
  const [domain, setDomain] = useState("web");
  const [log, setLog] = useState("");
  const [trace, setTrace] = useState<Trace | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async (forDomain: string, text: string) => {
    setRunning(true);
    setError(null);
    try {
      setTrace(await runTrace(forDomain, text));
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
      setTrace(null);
    } finally {
      setRunning(false);
    }
  }, []);

  // Open on the web chain already traced. A page that starts empty makes its first impression a
  // form; the point of this one is the reasoning, so the reasoning is what is on screen first.
  useEffect(() => {
    let live = true;
    fetchChains()
      .then((loaded) => {
        if (!live) return;
        setChains(loaded);
        const first = loaded[0];
        if (!first) return;
        setDomain(first.domain);
        setLog(first.log);
        void run(first.domain, first.log);
      })
      .catch((failure: unknown) => {
        if (live) setError(failure instanceof Error ? failure.message : String(failure));
      });
    return () => {
      live = false;
    };
  }, [run]);

  function pickChain(chain: DemoChain) {
    setDomain(chain.domain);
    setLog(chain.log);
    void run(chain.domain, chain.log);
  }

  return (
    <div className="mx-auto flex min-h-full max-w-6xl flex-col gap-6 px-6 py-8">
      <header className="flex flex-wrap items-start justify-between gap-4 border-b border-edge pb-5">
        <div>
          <h1 className="font-mono text-xl tracking-tight text-[#e6e8ec]">
            talos<span className="text-signal"> / pipeline trace</span>
          </h1>
          <p className="mt-1 max-w-xl text-sm text-quiet">
            Most tooling answers &ldquo;did something bad happen?&rdquo; with a score. This is the
            whole reasoning: every event, the detector that claimed it, the evidence it stood on,
            and exactly what the attack reached.
          </p>
        </div>
        <a
          className="font-mono text-xs text-quiet underline decoration-edge underline-offset-4 hover:text-signal"
          href="/docs"
        >
          OpenAPI /docs
        </a>
      </header>

      <section className="grid gap-4 lg:grid-cols-[1fr_auto]">
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            {chains.map((chain) => (
              <button
                key={chain.domain}
                type="button"
                onClick={() => pickChain(chain)}
                className={`rounded-md border px-3 py-1.5 font-mono text-xs transition ${
                  domain === chain.domain
                    ? "border-signal/50 bg-signal/10 text-signal"
                    : "border-edge bg-panel text-quiet hover:text-[#e6e8ec]"
                }`}
              >
                {chain.title}
              </button>
            ))}
          </div>

          <label className="sr-only" htmlFor="log">
            Log to trace
          </label>
          <textarea
            id="log"
            value={log}
            spellCheck={false}
            onChange={(event) => setLog(event.target.value)}
            placeholder="Paste a log, or edit the chain above and run it again."
            className="h-44 w-full resize-y rounded-lg border border-edge bg-panel p-3 font-mono text-xs leading-relaxed text-[#c9cdd6] outline-none focus:border-signal/50"
          />
        </div>

        <div className="flex flex-col gap-3 lg:w-56">
          <select
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
            className="rounded-md border border-edge bg-panel px-3 py-2 font-mono text-xs text-[#e6e8ec] outline-none focus:border-signal/50"
            aria-label="Which parser reads the log"
          >
            <option value="web">web &mdash; access log</option>
            <option value="network">network &mdash; syslog</option>
          </select>
          <button
            type="button"
            onClick={() => void run(domain, log)}
            disabled={running || log.trim().length === 0}
            className="rounded-md bg-signal px-4 py-2.5 font-mono text-sm text-[#04070c] transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {running ? "tracing..." : "run the pipeline"}
          </button>
        </div>
      </section>

      {error && (
        <p className="rounded-lg border border-sev-critical/40 bg-sev-critical/10 px-4 py-3 font-mono text-sm text-sev-critical">
          {error}
        </p>
      )}

      {trace && (
        <section className="flex flex-col gap-5">
          <div className="flex flex-wrap items-center gap-8 rounded-lg border border-edge bg-panel px-5 py-4">
            <Stat label="events" value={String(trace.events)} />
            <Stat
              label="incidents"
              value={String(trace.incidents)}
              tone={trace.incidents > 0 ? "text-sev-high" : undefined}
            />
            <Stat label="lines skipped" value={String(trace.skipped)} />
            <Stat
              label="narrative"
              value={trace.used_llm ? "model" : "templated"}
              tone="text-quiet"
            />
            <p className="ml-auto max-w-sm text-xs leading-relaxed text-quiet">
              Detection is statistical and runs with no model reachable. A model, when one is
              configured, only words the narrative.
            </p>
          </div>

          <ol className="flex flex-col">
            {trace.steps.map((step) => (
              <EventStep key={step.index} step={step} />
            ))}
          </ol>

          {trace.steps.length === 0 && (
            <p className="rounded-lg border border-edge bg-panel px-4 py-8 text-center text-sm text-quiet">
              No line in that input parsed as {domain} telemetry
              {trace.skipped > 0 && ` (${trace.skipped} skipped)`}.
            </p>
          )}
        </section>
      )}
    </div>
  );
}
