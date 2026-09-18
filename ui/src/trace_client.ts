// The two calls the page makes. Relative URLs, because the page is served from the same origin
// as the API (FastAPI mounts it at /ui) and Vite's dev server proxies them to a running
// `talos serve`.

import type { DemoChain, Trace } from "./trace_types";

/** The API's error bodies are `{detail: ...}`; anything else is reported as the raw status. */
async function failureOf(response: Response): Promise<string> {
  try {
    const body = await response.json();
    const detail = body?.detail;
    if (typeof detail === "string") return detail;
    if (detail) return JSON.stringify(detail);
  } catch {
    // A non-JSON body (a proxy error page, say) tells us nothing the status does not.
  }
  return `${response.status} ${response.statusText}`;
}

export async function fetchChains(): Promise<DemoChain[]> {
  const response = await fetch("/trace/chains");
  if (!response.ok) throw new Error(await failureOf(response));
  return response.json();
}

export async function runTrace(domain: string, log: string): Promise<Trace> {
  const response = await fetch("/trace", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, log }),
  });
  if (!response.ok) throw new Error(await failureOf(response));
  return response.json();
}
