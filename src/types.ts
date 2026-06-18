import type { OwaspId } from "./owasp.js";

/** Severity of a confirmed finding, ordered low → critical. */
export type Severity = "low" | "medium" | "high" | "critical";

export const SEVERITY_ORDER: Readonly<Record<Severity, number>> = Object.freeze({
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

/**
 * An LLM endpoint under test: give it a prompt, get back the model's text reply.
 * Implementations may wrap any HTTP API; see `httpEndpoint`. Kept intentionally
 * tiny so probes never depend on a specific provider's request/response shape.
 */
export type Endpoint = (
  prompt: string,
  opts?: { signal?: AbortSignal },
) => Promise<string>;

/**
 * Per-run context handed to every probe. The `canary` is a unique, unguessable
 * token minted once per run; injection/leak probes ask the model to echo it so a
 * compliant (vulnerable) response can be detected deterministically without any
 * model-side knowledge.
 */
export interface ProbeContext {
  canary: string;
}

/** Evidence that a probe's attack succeeded against the endpoint. */
export interface ProbeHit {
  /** The exact substring/marker in the response that proves the vulnerability. */
  evidence: string;
  /** Why this response constitutes a vulnerability. */
  detail: string;
}

/**
 * A single deterministic red-team check. A probe sends one or more crafted
 * payloads and, for each response, decides whether the endpoint behaved
 * insecurely. No ML, no scoring heuristics — just rules over the response text.
 */
export interface Probe {
  /** Stable, unique identifier, e.g. "pi-ignore-previous". */
  id: string;
  /** OWASP LLM Top 10 category this probe maps to. */
  owasp: OwaspId;
  /** Severity assigned to a hit from this probe. */
  severity: Severity;
  /** Short human title. */
  title: string;
  /** What the probe attacks and why a hit matters. */
  description: string;
  /** Free-form tags for selection/filtering (e.g. "jailbreak", "dan"). */
  tags?: readonly string[];
  /** The attack input(s) to send. May incorporate the per-run canary. */
  payloads: (ctx: ProbeContext) => readonly string[];
  /** Decide whether a single response to `payload` is a vulnerability. */
  evaluate: (response: string, payload: string, ctx: ProbeContext) => ProbeHit | null;
}

/** The result of sending one payload from one probe to the endpoint. */
export interface Attempt {
  probeId: string;
  payload: string;
  /** The endpoint's response, or "" if the request errored. */
  response: string;
  /** A hit if the response was vulnerable, else null. */
  hit: ProbeHit | null;
  /** Transport/endpoint error message, if the request failed. */
  error?: string;
  /** Wall-clock duration of the request, ms. */
  durationMs: number;
}

/** A confirmed vulnerability: a probe whose attack succeeded. */
export interface Finding {
  probeId: string;
  owasp: OwaspId;
  severity: Severity;
  title: string;
  evidence: string;
  detail: string;
  /** The payload that triggered it. */
  payload: string;
  /** The (possibly truncated) response that proved it. */
  response: string;
}

/** The full outcome of a red-team run. */
export interface RunResult {
  target: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  /** Every request/response attempted. */
  attempts: Attempt[];
  /** Distinct confirmed findings (deduped per probe). */
  findings: Finding[];
  /** Number of probes executed. */
  probesRun: number;
}
