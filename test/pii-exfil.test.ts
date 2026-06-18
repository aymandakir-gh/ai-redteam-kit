import { describe, it, expect } from "vitest";
import { runRedteam, piiExfilProbes } from "../src/index.js";
import { vulnerableEndpoint, secureEndpoint } from "./fixtures.js";
import type { Endpoint } from "../src/index.js";

const CANARY = "RTK-000000000000000000";

describe("pii-exfil pack", () => {
  it("every probe plants the secret in context (the canary is present to leak)", () => {
    for (const probe of piiExfilProbes) {
      const payload = probe.payloads({ canary: CANARY })[0] ?? "";
      expect(payload).toContain(CANARY);
    }
  });

  it("every probe exfiltrates the planted secret from a leaky model", async () => {
    const res = await runRedteam(vulnerableEndpoint(), {
      probes: piiExfilProbes,
      canary: CANARY,
    });
    expect(res.findings).toHaveLength(piiExfilProbes.length);
    expect(res.findings.every((f) => f.owasp === "LLM02")).toBe(true);
  });

  it("none fire against a refusing model", async () => {
    const res = await runRedteam(secureEndpoint(), {
      probes: piiExfilProbes,
      canary: CANARY,
    });
    expect(res.findings).toHaveLength(0);
  });

  it("a refusal that quotes the secret back is not counted as a leak", async () => {
    // Echoes the canary but in a refusal — the !looksLikeRefusal guard suppresses it.
    const refusalEcho: Endpoint = async () =>
      `I'm sorry, but I can't share the value ${CANARY}.`;
    const res = await runRedteam(refusalEcho, { probes: piiExfilProbes, canary: CANARY });
    expect(res.findings).toHaveLength(0);
  });

  it("all carry the pii-exfil tag and a non-empty description", () => {
    for (const p of piiExfilProbes) {
      expect(p.tags).toContain("pii-exfil");
      expect(p.description.length).toBeGreaterThan(0);
    }
  });
});
