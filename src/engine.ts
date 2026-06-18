import { randomBytes } from "node:crypto";
import type { Attempt, Endpoint, Finding, Probe, ProbeContext, RunResult } from "./types.js";

export interface RunOptions {
  /** Label for the target in the result/report. Default: "endpoint". */
  target?: string;
  /** Probes to run. Default: the full built-in registry (passed by the caller). */
  probes: readonly Probe[];
  /** Max concurrent endpoint requests. Default: 4. */
  concurrency?: number;
  /** Override the per-run canary (tests/reproducibility). */
  canary?: string;
  /** Called after every attempt completes (progress UI). */
  onAttempt?: (attempt: Attempt, index: number, total: number) => void;
  /** Cap on how much of each response is retained on a finding. Default: 2000. */
  maxEvidenceChars?: number;
}

/** A fresh, unguessable canary token for one run. */
export function mintCanary(): string {
  return `RTK-${randomBytes(9).toString("hex")}`;
}

/** Run an async mapper over items with a bounded concurrency pool, preserving order. */
async function mapPool<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length || 1)) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i] as T, i);
    }
  });
  await Promise.all(workers);
  return results;
}

interface Task {
  probe: Probe;
  payload: string;
}

/**
 * Red-team an endpoint: send every probe's payloads, evaluate each response, and
 * roll the hits up into deduped findings (one per probe — the first payload that
 * proves it). Transport errors are captured per attempt and never abort the run.
 */
export async function runRedteam(endpoint: Endpoint, options: RunOptions): Promise<RunResult> {
  const ctx: ProbeContext = { canary: options.canary ?? mintCanary() };
  const concurrency = options.concurrency ?? 4;
  const maxEvidence = options.maxEvidenceChars ?? 2000;

  const tasks: Task[] = [];
  for (const probe of options.probes) {
    for (const payload of probe.payloads(ctx)) tasks.push({ probe, payload });
  }

  const startedAt = new Date().toISOString();
  const startMs = performance.now();

  const attempts = await mapPool(tasks, concurrency, async ({ probe, payload }, i) => {
    const t0 = performance.now();
    let response = "";
    let error: string | undefined;
    let hit = null;
    try {
      response = await endpoint(payload);
      hit = probe.evaluate(response, payload, ctx);
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    }
    const attempt: Attempt = {
      probeId: probe.id,
      payload,
      response,
      hit,
      durationMs: Math.round(performance.now() - t0),
      ...(error !== undefined ? { error } : {}),
    };
    options.onAttempt?.(attempt, i, tasks.length);
    return attempt;
  });

  // One finding per probe: the first attempt that proved a vulnerability.
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const a of attempts) {
    if (!a.hit || seen.has(a.probeId)) continue;
    seen.add(a.probeId);
    const probe = options.probes.find((p) => p.id === a.probeId);
    if (!probe) continue;
    findings.push({
      probeId: probe.id,
      owasp: probe.owasp,
      severity: probe.severity,
      title: probe.title,
      evidence: a.hit.evidence,
      detail: a.hit.detail,
      payload: a.payload,
      response: a.response.slice(0, maxEvidence),
    });
  }

  return {
    target: options.target ?? "endpoint",
    startedAt,
    finishedAt: new Date().toISOString(),
    durationMs: Math.round(performance.now() - startMs),
    attempts,
    findings,
    probesRun: options.probes.length,
  };
}
