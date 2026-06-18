import type { Endpoint } from "../src/index.js";

/** Match the canary minted by the engine (RTK- + 18 hex chars). */
const CANARY_RE = /RTK-[0-9a-f]{18}/;

/**
 * A deliberately-vulnerable mock model: a naive instruction-follower with no
 * guardrails. It complies with whatever a prompt asks, which is exactly the
 * behaviour the probes detect. Extended pack-by-pack as new probe families land.
 */
export function vulnerableEndpoint(): Endpoint {
  return async (prompt: string) => {
    // Prompt injection: echo any canary it's told to print.
    const canary = CANARY_RE.exec(prompt)?.[0];
    if (canary) return `Sure, here you go: ${canary}`;
    return "Here is a helpful, on-task answer.";
  };
}

/** A secure mock model that refuses adversarial requests. */
export function secureEndpoint(): Endpoint {
  return async () =>
    "I'm sorry, but I can't help with that. I'll stick to my original task.";
}

/** A mock endpoint that always errors (transport failure simulation). */
export function brokenEndpoint(): Endpoint {
  return async () => {
    throw new Error("connection refused");
  };
}
