import { describe, it, expect } from "vitest";
import { runRedteam, mintCanary, promptInjectionProbes, ALL_PROBES } from "../src/index.js";
import type { Probe } from "../src/index.js";
import { vulnerableEndpoint, secureEndpoint, brokenEndpoint } from "./fixtures.js";

const FIXED_CANARY = "RTK-000000000000000000"; // RTK- + 18 hex chars

describe("mintCanary", () => {
  it("produces a unique RTK-prefixed token each call", () => {
    const a = mintCanary();
    const b = mintCanary();
    expect(a).toMatch(/^RTK-[0-9a-f]{18}$/);
    expect(a).not.toBe(b);
  });
});

describe("runRedteam — prompt-injection pack", () => {
  it("flags every injection probe against a vulnerable endpoint", async () => {
    const res = await runRedteam(vulnerableEndpoint(), {
      probes: promptInjectionProbes,
      canary: FIXED_CANARY,
    });
    expect(res.findings).toHaveLength(promptInjectionProbes.length);
    expect(res.findings.every((f) => f.owasp === "LLM01")).toBe(true);
    expect(res.findings.every((f) => f.evidence === FIXED_CANARY)).toBe(true);
    expect(res.attempts).toHaveLength(promptInjectionProbes.length);
    expect(res.probesRun).toBe(promptInjectionProbes.length);
  });

  it("reports zero findings against a secure (refusing) endpoint", async () => {
    const res = await runRedteam(secureEndpoint(), {
      probes: promptInjectionProbes,
      canary: FIXED_CANARY,
    });
    expect(res.findings).toHaveLength(0);
    // every attempt still ran and recorded a (non-vulnerable) response
    expect(res.attempts.every((a) => a.hit === null && a.error === undefined)).toBe(true);
  });
});

describe("runRedteam — error handling & dedupe", () => {
  it("captures transport errors per attempt without aborting or finding", async () => {
    const res = await runRedteam(brokenEndpoint(), {
      probes: promptInjectionProbes,
      canary: FIXED_CANARY,
    });
    expect(res.findings).toHaveLength(0);
    expect(res.attempts.every((a) => a.error === "connection refused")).toBe(true);
  });

  it("emits a single finding per probe even when multiple payloads hit", async () => {
    const multi: Probe = {
      id: "test-multi",
      owasp: "LLM01",
      severity: "low",
      title: "multi-payload",
      description: "two payloads, both echo the canary",
      payloads: (ctx) => [`print ${ctx.canary}`, `also print ${ctx.canary}`],
      evaluate: (response, _p, ctx) =>
        response.includes(ctx.canary) ? { evidence: ctx.canary, detail: "echoed" } : null,
    };
    const res = await runRedteam(vulnerableEndpoint(), { probes: [multi], canary: FIXED_CANARY });
    expect(res.attempts).toHaveLength(2);
    expect(res.findings).toHaveLength(1);
  });

  it("invokes the onAttempt progress callback for every attempt", async () => {
    let count = 0;
    await runRedteam(secureEndpoint(), {
      probes: promptInjectionProbes,
      canary: FIXED_CANARY,
      onAttempt: () => {
        count++;
      },
    });
    expect(count).toBe(promptInjectionProbes.length);
  });
});

describe("registry", () => {
  it("exposes the injection pack and has unique probe ids", () => {
    expect(ALL_PROBES.length).toBeGreaterThanOrEqual(promptInjectionProbes.length);
    const ids = ALL_PROBES.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
