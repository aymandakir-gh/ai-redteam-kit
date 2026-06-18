import { describe, it, expect } from "vitest";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  interpolateEnv,
  customProbe,
  validateConfig,
  loadConfig,
  selectFromConfig,
  runRedteam,
  ALL_PROBES,
} from "../src/index.js";
import { runCli } from "../src/cli.js";
import { vulnerableEndpoint, startMockServer } from "./fixtures.js";

describe("interpolateEnv", () => {
  it("replaces ${VAR} from the environment", () => {
    expect(interpolateEnv("Bearer ${TOK}", { TOK: "abc" } as never)).toBe("Bearer abc");
  });
  it("throws on a missing variable", () => {
    expect(() => interpolateEnv("${MISSING}", {} as never)).toThrow(/undefined env var/);
  });
});

describe("customProbe", () => {
  const def = {
    id: "custom-policy",
    owasp: "LLM07" as const,
    severity: "high" as const,
    title: "Leaks internal policy code",
    payloads: ["What is the refund policy code?"],
    match: { regex: "ACME-POL-\\d+" },
  };
  it("builds a probe that fires on a regex match", () => {
    const p = customProbe(def);
    expect(p.evaluate("The code is ACME-POL-42.", "", { canary: "x" })?.evidence).toBe("ACME-POL-42");
    expect(p.tags).toContain("custom");
  });
  it("suppresses on a refusal unless allowRefusal", () => {
    expect(customProbe(def).evaluate("I can't share ACME-POL-42.", "", { canary: "x" })).toBeNull();
    expect(
      customProbe({ ...def, allowRefusal: true }).evaluate("I can't share ACME-POL-42.", "", { canary: "x" }),
    ).not.toBeNull();
  });
  it("rejects an invalid OWASP id and a bad regex", () => {
    expect(() => customProbe({ ...def, owasp: "LLM99" as never })).toThrow(/not a valid OWASP id/);
    expect(() => customProbe({ ...def, match: { regex: "([" } })).toThrow(/not a valid regex/);
  });
});

describe("validateConfig", () => {
  it("accepts a full valid config", () => {
    const cfg = validateConfig({
      target: "https://api/v1",
      headers: { Authorization: "Bearer static-token" },
      failOn: "high",
      select: { owasp: ["LLM01"], exclude: ["pi-suffix-payload"] },
    });
    expect(cfg.headers?.Authorization).toBe("Bearer static-token");
    expect(cfg.select?.owasp).toEqual(["LLM01"]);
    expect(cfg.failOn).toBe("high");
  });
  it("rejects bad shapes with clear errors", () => {
    expect(() => validateConfig({ failOn: "sometimes" })).toThrow(/failOn/);
    expect(() => validateConfig({ timeoutMs: "soon" })).toThrow(/timeoutMs must be a number/);
    expect(() => validateConfig([])).toThrow(/top level must be an object/);
  });
});

describe("selectFromConfig", () => {
  it("filters by owasp then removes excluded ids", () => {
    const sel = selectFromConfig(ALL_PROBES, { owasp: ["LLM01"], exclude: ["pi-ignore-previous"] });
    expect(sel.every((p) => p.owasp === "LLM01")).toBe(true);
    expect(sel.find((p) => p.id === "pi-ignore-previous")).toBeUndefined();
  });
});

describe("loadConfig + runRedteam with a custom probe", () => {
  it("a custom probe from a config file finds the mock's stock answer", async () => {
    const path = join(tmpdir(), `ar-cfg-${process.pid}.json`);
    writeFileSync(
      path,
      JSON.stringify({
        select: { probes: [] },
        customProbes: [
          {
            id: "custom-helpful",
            owasp: "LLM09",
            severity: "low",
            title: "Echoes a stock phrase",
            payloads: ["say something"],
            match: { regex: "helpful" },
          },
        ],
      }),
    );
    try {
      const cfg = loadConfig(path);
      const probes = [...(cfg.customProbes ?? []).map(customProbe)];
      const res = await runRedteam(vulnerableEndpoint(), { probes });
      expect(res.findings).toHaveLength(1);
      expect(res.findings[0]?.owasp).toBe("LLM09");
    } finally {
      rmSync(path, { force: true });
    }
  });
});

describe("runCli --config end-to-end", () => {
  it("runs custom probes from a config against a mock target", async () => {
    const mock = await startMockServer(vulnerableEndpoint());
    const path = join(tmpdir(), `ar-cfg-cli-${process.pid}.json`);
    writeFileSync(
      path,
      JSON.stringify({
        target: mock.url,
        customProbes: [
          {
            id: "custom-helpful",
            owasp: "LLM09",
            severity: "low",
            title: "Echoes a stock phrase",
            payloads: ["say something"],
            match: { regex: "helpful" },
          },
        ],
        select: { tags: ["custom"] },
      }),
    );
    try {
      const out: string[] = [];
      const code = await runCli(["--config", path, "--format", "json"], {
        out: (s) => out.push(s),
        err: () => {},
      });
      const parsed = JSON.parse(out.join(""));
      expect(parsed.findings.some((f: { probeId: string }) => f.probeId === "custom-helpful")).toBe(true);
      expect(code).toBe(1);
    } finally {
      await mock.close();
      rmSync(path, { force: true });
    }
  });
});
