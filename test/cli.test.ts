import { describe, it, expect } from "vitest";
import { parseArgs, selectProbes, runCli, formatTextReport } from "../src/cli.js";
import { ALL_PROBES } from "../src/index.js";
import { vulnerableEndpoint, secureEndpoint, startMockServer } from "./fixtures.js";

function capture() {
  const buf: string[] = [];
  return { io: { out: (s: string) => buf.push(s), err: (s: string) => buf.push(s) }, text: () => buf.join("") };
}

describe("parseArgs", () => {
  it("parses a URL, headers, model and filters", () => {
    const a = parseArgs([
      "https://api.test/v1",
      "-H",
      "Authorization: Bearer x",
      "--model",
      "gpt-4o",
      "--owasp",
      "LLM01,LLM07",
    ]);
    expect(a.url).toBe("https://api.test/v1");
    expect(a.headers.Authorization).toBe("Bearer x");
    expect(a.model).toBe("gpt-4o");
    expect(a.owasp).toEqual(["LLM01", "LLM07"]);
  });
  it("rejects a malformed header and unknown options", () => {
    expect(parseArgs(["url", "-H", "nope"]).error).toMatch(/invalid header/);
    expect(parseArgs(["--bogus"]).error).toMatch(/unknown option/);
  });
});

describe("selectProbes", () => {
  it("filters by OWASP id, tag and probe id", () => {
    expect(selectProbes(ALL_PROBES, { owasp: ["LLM07"] }).every((p) => p.owasp === "LLM07")).toBe(true);
    expect(selectProbes(ALL_PROBES, { tag: ["jailbreak"] }).length).toBeGreaterThan(0);
    expect(selectProbes(ALL_PROBES, { probe: ["pi-ignore-previous"] })).toHaveLength(1);
  });
});

describe("runCli — meta commands", () => {
  it("--help and --version exit 0", async () => {
    const h = capture();
    expect(await runCli(["--help"], h.io)).toBe(0);
    expect(h.text()).toContain("Usage:");
    const v = capture();
    expect(await runCli(["--version"], v.io)).toBe(0);
    expect(v.text()).toMatch(/\d+\.\d+\.\d+/);
  });
  it("--list prints every probe", async () => {
    const c = capture();
    expect(await runCli(["--list"], c.io)).toBe(0);
    expect(c.text()).toContain("pi-ignore-previous");
    expect(c.text()).toMatch(/\d+ probe\(s\)\./);
  });
  it("missing URL exits 2", async () => {
    const c = capture();
    expect(await runCli([], c.io)).toBe(2);
  });
});

describe("runCli — end-to-end over HTTP", () => {
  it("reports findings (exit 1) against a vulnerable endpoint", async () => {
    const mock = await startMockServer(vulnerableEndpoint());
    try {
      const c = capture();
      const code = await runCli([mock.url], c.io);
      expect(code).toBe(1);
      expect(c.text()).toContain("FINDINGS");
      expect(c.text()).toMatch(/LLM0[127]/);
    } finally {
      await mock.close();
    }
  });

  it("reports no findings (exit 0) against a secure endpoint", async () => {
    const mock = await startMockServer(secureEndpoint());
    try {
      const c = capture();
      const code = await runCli([mock.url], c.io);
      expect(code).toBe(0);
      expect(c.text()).toContain("No findings");
    } finally {
      await mock.close();
    }
  });

  it("emits valid JSON with --format json", async () => {
    const mock = await startMockServer(vulnerableEndpoint());
    try {
      const c = capture();
      await runCli([mock.url, "--format", "json"], c.io);
      const parsed = JSON.parse(c.text());
      expect(parsed.target).toBe(mock.url);
      expect(Array.isArray(parsed.findings)).toBe(true);
      expect(parsed.findings.length).toBeGreaterThan(0);
    } finally {
      await mock.close();
    }
  });

  it("honours --owasp filtering end-to-end", async () => {
    const mock = await startMockServer(vulnerableEndpoint());
    try {
      const c = capture();
      await runCli([mock.url, "--owasp", "LLM07", "--format", "json"], c.io);
      const parsed = JSON.parse(c.text());
      expect(parsed.findings.every((f: { owasp: string }) => f.owasp === "LLM07")).toBe(true);
    } finally {
      await mock.close();
    }
  });
});

describe("formatTextReport", () => {
  it("renders a clean run", () => {
    const text = formatTextReport({
      target: "x",
      startedAt: "",
      finishedAt: "",
      durationMs: 5,
      attempts: [],
      findings: [],
      probesRun: 0,
    });
    expect(text).toContain("No findings");
  });
});
