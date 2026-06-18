import { describe, it, expect } from "vitest";
import { runRedteam, encodingObfuscationProbes } from "../src/index.js";
import { encoders } from "../src/probes/encoding-obfuscation.js";
import { vulnerableEndpoint, secureEndpoint } from "./fixtures.js";

const CANARY = "RTK-000000000000000000";

describe("encoders", () => {
  it("round-trip the canary so detection stays a substring check", () => {
    expect(Buffer.from(encoders.base64(CANARY), "base64").toString("utf8")).toBe(CANARY);
    expect(encoders.rot13(encoders.rot13(CANARY))).toBe(CANARY);
    expect(Buffer.from(encoders.hex(CANARY), "hex").toString("utf8")).toBe(CANARY);
    expect(encoders.zeroWidth(CANARY).replace(/​/g, "")).toBe(CANARY);
  });
});

describe("encoding-obfuscation pack", () => {
  it("every probe hides the contiguous canary from a raw-prompt filter", () => {
    for (const probe of encodingObfuscationProbes) {
      const [payload] = probe.payloads({ canary: CANARY });
      expect(payload).not.toContain(CANARY); // it's encoded; only a decode reveals it
    }
  });

  it("every probe coerces the canary out of a model that decodes payloads", async () => {
    const res = await runRedteam(vulnerableEndpoint(), {
      probes: encodingObfuscationProbes,
      canary: CANARY,
    });
    expect(res.findings).toHaveLength(encodingObfuscationProbes.length);
    expect(res.findings.every((f) => f.owasp === "LLM01")).toBe(true);
  });

  it("none fire against a refusing model", async () => {
    const res = await runRedteam(secureEndpoint(), {
      probes: encodingObfuscationProbes,
      canary: CANARY,
    });
    expect(res.findings).toHaveLength(0);
  });

  it("all carry the encoding tag and a non-empty description", () => {
    for (const p of encodingObfuscationProbes) {
      expect(p.tags).toContain("encoding");
      expect(p.description.length).toBeGreaterThan(0);
    }
  });
});
