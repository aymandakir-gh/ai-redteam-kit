import { describe, it, expect } from "vitest";
import { exitCodeFor, ciSummary, parseArgs, runCli } from "../src/cli.js";
import { scoreReport, runRedteam, ALL_PROBES } from "../src/index.js";
import type { ScoredReport } from "../src/index.js";
import { vulnerableEndpoint, startMockServer } from "./fixtures.js";

function reportWith(severities: Array<"critical" | "high" | "medium" | "low">): ScoredReport {
  return scoreReport({
    target: "t",
    startedAt: "",
    finishedAt: "",
    durationMs: 1,
    attempts: [],
    probesRun: severities.length,
    findings: severities.map((severity, i) => ({
      probeId: `p${i}`,
      owasp: "LLM01" as const,
      severity,
      title: "t",
      evidence: "e",
      detail: "d",
      payload: "p",
      response: "r",
    })),
  });
}

describe("exitCodeFor — fail-on threshold", () => {
  it("defaults to failing on any finding", () => {
    expect(exitCodeFor(reportWith(["low"]))).toBe(1);
    expect(exitCodeFor(reportWith([]))).toBe(0);
  });
  it("only fails at or above the chosen severity", () => {
    expect(exitCodeFor(reportWith(["medium"]), "high")).toBe(0);
    expect(exitCodeFor(reportWith(["high"]), "high")).toBe(1);
    expect(exitCodeFor(reportWith(["critical"]), "high")).toBe(1);
  });
  it("never fails with --fail-on never", () => {
    expect(exitCodeFor(reportWith(["critical"]), "never")).toBe(0);
  });
});

describe("ciSummary", () => {
  it("emits a grep-able PASS/FAIL line with counts", () => {
    const line = ciSummary(reportWith(["critical", "high"]), true);
    expect(line).toContain("ai-redteam: FAIL");
    expect(line).toContain("grade=F");
    expect(line).toContain("critical=1");
    expect(line).toContain("high=1");
  });
});

describe("parseArgs — CI flags", () => {
  it("parses --ci and --fail-on", () => {
    const a = parseArgs(["url", "--ci", "--fail-on", "high"]);
    expect(a.ci).toBe(true);
    expect(a.failOn).toBe("high");
  });
  it("rejects an invalid --fail-on", () => {
    expect(parseArgs(["url", "--fail-on", "bogus"]).error).toMatch(/invalid --fail-on/);
  });
});

describe("runCli — CI mode end-to-end", () => {
  it("passes (exit 0) when findings are below the threshold", async () => {
    const mock = await startMockServer(vulnerableEndpoint());
    try {
      // jb-grandma is a medium-severity finding; --fail-on critical should pass it
      const buf: string[] = [];
      const code = await runCli(
        [mock.url, "--probe", "jb-grandma", "--fail-on", "critical", "--ci"],
        { out: () => {}, err: (s) => buf.push(s) },
      );
      expect(code).toBe(0);
      expect(buf.join("")).toContain("ai-redteam: PASS");
    } finally {
      await mock.close();
    }
  });

  it("fails (exit 1) and prints a CI line for a high finding", async () => {
    const mock = await startMockServer(vulnerableEndpoint());
    try {
      const buf: string[] = [];
      const code = await runCli([mock.url, "--probe", "pi-ignore-previous", "--ci"], {
        out: () => {},
        err: (s) => buf.push(s),
      });
      expect(code).toBe(1);
      expect(buf.join("")).toContain("ai-redteam: FAIL");
    } finally {
      await mock.close();
    }
  });
});

describe("sanity: severities exist in the registry to gate on", () => {
  it("the vulnerable run yields mixed severities", async () => {
    const res = await runRedteam(vulnerableEndpoint(), { probes: ALL_PROBES });
    const sevs = new Set(res.findings.map((f) => f.severity));
    expect(sevs.size).toBeGreaterThan(1);
  });
});
