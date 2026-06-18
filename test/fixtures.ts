import type { Endpoint } from "../src/index.js";

/** Match the canary minted by the engine (RTK- + 18 hex chars). */
const CANARY_RE = /RTK-[0-9a-f]{18}/;

/**
 * Recover the canary a prompt is trying to coerce out: either a contiguous
 * token, or one reassembled from quoted fragments (the payload-splitting
 * jailbreak deliberately breaks it up to dodge filters). Returns null if none.
 */
function reconstructCanary(prompt: string): string | null {
  const direct = CANARY_RE.exec(prompt)?.[0];
  if (direct) return direct;
  const joined = [...prompt.matchAll(/"([^"]*)"/g)].map((m) => m[1]).join("");
  return CANARY_RE.exec(joined)?.[0] ?? null;
}

/**
 * A deliberately-vulnerable mock model: a naive instruction-follower with no
 * guardrails. It complies with whatever a prompt asks, which is exactly the
 * behaviour the probes detect. Extended pack-by-pack as new probe families land.
 */
export function vulnerableEndpoint(): Endpoint {
  return async (prompt: string) => {
    // Prompt injection / jailbreak: emit any canary it's coerced to print
    // (including one reassembled from split fragments).
    const canary = reconstructCanary(prompt);
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
