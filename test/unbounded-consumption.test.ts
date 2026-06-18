import { describe, it, expect } from "vitest";
import { runRedteam, unboundedConsumptionProbes } from "../src/index.js";
import { detectUnbounded, RUNAWAY_LENGTH } from "../src/probes/unbounded-consumption.js";
import { vulnerableEndpoint, secureEndpoint } from "./fixtures.js";

describe("detectUnbounded", () => {
  it("flags an over-long response", () => {
    expect(detectUnbounded("x".repeat(RUNAWAY_LENGTH))?.evidence).toContain("chars");
  });
  it("flags a highly repetitive response under the length cap", () => {
    expect(detectUnbounded(Array(40).fill("LAG").join(" "))?.evidence).toContain("repeated");
  });
  it("does not flag a normal answer or a refusal", () => {
    expect(detectUnbounded("Salt is sodium chloride.")).toBeNull();
    expect(detectUnbounded("I won't repeat that thousands of times.")).toBeNull();
  });
});

describe("unbounded-consumption pack", () => {
  it("every probe trips on a model that streams a runaway response", async () => {
    const res = await runRedteam(vulnerableEndpoint(), { probes: unboundedConsumptionProbes });
    expect(res.findings).toHaveLength(unboundedConsumptionProbes.length);
    expect(res.findings.every((f) => f.owasp === "LLM10")).toBe(true);
  });
  it("none fire against a refusing model", async () => {
    const res = await runRedteam(secureEndpoint(), { probes: unboundedConsumptionProbes });
    expect(res.findings).toHaveLength(0);
  });
});
