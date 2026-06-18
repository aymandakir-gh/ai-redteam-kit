import { describe, it, expect } from "vitest";
import { runRedteam, scoreReport, renderMarkdown, renderJson, ALL_PROBES } from "../src/index.js";
import type { RunResult } from "../src/index.js";
import { vulnerableEndpoint, secureEndpoint } from "./fixtures.js";

function emptyResult(): RunResult {
  return {
    target: "t",
    startedAt: "",
    finishedAt: "2026-06-18T00:00:00Z",
    durationMs: 1,
    attempts: [],
    findings: [],
    probesRun: 0,
  };
}

describe("scoreReport — grading", () => {
  it("a clean run is grade A, posture 100, passed", () => {
    const r = scoreReport(emptyResult());
    expect(r.grade).toBe("A");
    expect(r.postureScore).toBe(100);
    expect(r.passed).toBe(true);
  });

  it("severity-gates the grade and deducts posture", () => {
    const base = emptyResult();
    const mk = (severity: "critical" | "high" | "medium" | "low") => ({
      probeId: "x",
      owasp: "LLM01" as const,
      severity,
      title: "t",
      evidence: "e",
      detail: "d",
      payload: "p",
      response: "r",
    });
    expect(scoreReport({ ...base, findings: [mk("low")] }).grade).toBe("B");
    expect(scoreReport({ ...base, findings: [mk("medium")] }).grade).toBe("C");
    expect(scoreReport({ ...base, findings: [mk("high")] }).grade).toBe("D");
    expect(scoreReport({ ...base, findings: [mk("critical")] }).grade).toBe("F");
    // one critical (-40) + one high (-20) → 40
    expect(scoreReport({ ...base, findings: [mk("critical"), mk("high")] }).postureScore).toBe(40);
    // floors at 0
    expect(
      scoreReport({ ...base, findings: [mk("critical"), mk("critical"), mk("critical")] }).postureScore,
    ).toBe(0);
  });
});

describe("scoreReport — categories", () => {
  it("marks tested-with-findings as fail, tested-clean as pass, untested as not-tested", async () => {
    const probes = ALL_PROBES.filter((p) => p.owasp === "LLM01" || p.owasp === "LLM07");
    const res = await runRedteam(secureEndpoint(), { probes });
    const report = scoreReport(res, probes);
    const status = (id: string) => report.categories.find((c) => c.owasp === id)?.status;
    expect(status("LLM01")).toBe("pass"); // tested, secure refused → no findings
    expect(status("LLM07")).toBe("pass");
    expect(status("LLM05")).toBe("not-tested"); // not in the probe set
  });

  it("a vulnerable endpoint fails the exercised categories", async () => {
    const probes = ALL_PROBES.filter((p) => p.owasp === "LLM02");
    const res = await runRedteam(vulnerableEndpoint(), { probes });
    const report = scoreReport(res, probes);
    expect(report.categories.find((c) => c.owasp === "LLM02")?.status).toBe("fail");
    expect(report.grade === "F" || report.grade === "D").toBe(true);
  });
});

describe("renderers", () => {
  it("markdown contains the grade, the OWASP table and findings", async () => {
    const probes = ALL_PROBES.filter((p) => p.owasp === "LLM01");
    const res = await runRedteam(vulnerableEndpoint(), { probes });
    const md = renderMarkdown(scoreReport(res, probes));
    expect(md).toContain("# ai-redteam report");
    expect(md).toContain("OWASP LLM Top 10");
    expect(md).toContain("LLM01 Prompt Injection");
    expect(md).toContain("## Findings");
  });

  it("json round-trips to the scored shape", async () => {
    const probes = ALL_PROBES.filter((p) => p.owasp === "LLM01");
    const res = await runRedteam(vulnerableEndpoint(), { probes });
    const parsed = JSON.parse(renderJson(scoreReport(res, probes)));
    expect(parsed.grade).toBeDefined();
    expect(parsed.categories).toHaveLength(10);
    expect(parsed.totals.findings).toBeGreaterThan(0);
  });
});
