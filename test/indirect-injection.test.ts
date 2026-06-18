import { describe, it, expect } from "vitest";
import { runRedteam, indirectInjectionProbes } from "../src/index.js";
import { vulnerableEndpoint, secureEndpoint } from "./fixtures.js";

const CANARY = "RTK-000000000000000000";

describe("indirect-injection pack", () => {
  it("every probe carries its instruction in data, not a direct user command", () => {
    for (const probe of indirectInjectionProbes) {
      const payload = probe.payloads({ canary: CANARY })[0] ?? "";
      // The instruction is embedded in retrieved/tool content (markers present).
      expect(/\[chunk|TOOL|retrieved|SYSTEM NOTE/i.test(payload)).toBe(true);
    }
  });

  it("every probe coerces the canary out of a model that trusts injected data", async () => {
    const res = await runRedteam(vulnerableEndpoint(), {
      probes: indirectInjectionProbes,
      canary: CANARY,
    });
    expect(res.findings).toHaveLength(indirectInjectionProbes.length);
    expect(res.findings.every((f) => f.owasp === "LLM01")).toBe(true);
  });

  it("none fire against a refusing model", async () => {
    const res = await runRedteam(secureEndpoint(), {
      probes: indirectInjectionProbes,
      canary: CANARY,
    });
    expect(res.findings).toHaveLength(0);
  });

  it("all carry the indirect-injection tag and a non-empty description", () => {
    for (const p of indirectInjectionProbes) {
      expect(p.tags).toContain("indirect-injection");
      expect(p.description.length).toBeGreaterThan(0);
    }
  });
});
