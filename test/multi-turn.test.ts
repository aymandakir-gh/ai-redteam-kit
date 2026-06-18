import { describe, it, expect } from "vitest";
import { runRedteam, multiTurnProbes } from "../src/index.js";
import { vulnerableEndpoint, secureEndpoint } from "./fixtures.js";

const CANARY = "RTK-000000000000000000";

describe("multi-turn pack", () => {
  it("no single turn of any probe contains the contiguous canary", () => {
    for (const probe of multiTurnProbes) {
      for (const turn of probe.payloads({ canary: CANARY })) {
        expect(turn).not.toContain(CANARY); // it only emerges across turns
      }
    }
  });

  it("every probe coerces the canary out of a stateful vulnerable model", async () => {
    // concurrency 1 so the turns of a probe arrive in order (multi-turn is, by
    // definition, order-dependent).
    const res = await runRedteam(vulnerableEndpoint(), {
      probes: multiTurnProbes,
      canary: CANARY,
      concurrency: 1,
    });
    expect(res.findings).toHaveLength(multiTurnProbes.length);
    expect(res.findings.every((f) => f.owasp === "LLM01")).toBe(true);
  });

  it("none fire against a refusing model", async () => {
    const res = await runRedteam(secureEndpoint(), {
      probes: multiTurnProbes,
      canary: CANARY,
      concurrency: 1,
    });
    expect(res.findings).toHaveLength(0);
  });

  it("all carry the multi-turn tag and a non-empty description", () => {
    for (const p of multiTurnProbes) {
      expect(p.tags).toContain("multi-turn");
      expect(p.description.length).toBeGreaterThan(0);
    }
  });
});
