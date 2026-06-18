import { describe, it, expect } from "vitest";
import { runRedteam, jailbreakProbes } from "../src/index.js";
import { vulnerableEndpoint, secureEndpoint } from "./fixtures.js";

const CANARY = "RTK-000000000000000000";

describe("jailbreak pack", () => {
  it("every jailbreak framing coerces the canary out of a vulnerable model", async () => {
    const res = await runRedteam(vulnerableEndpoint(), { probes: jailbreakProbes, canary: CANARY });
    expect(res.findings).toHaveLength(jailbreakProbes.length);
    expect(res.findings.every((f) => f.owasp === "LLM01")).toBe(true);
  });

  it("none fire against a refusing model", async () => {
    const res = await runRedteam(secureEndpoint(), { probes: jailbreakProbes, canary: CANARY });
    expect(res.findings).toHaveLength(0);
  });

  it("the payload-splitting probe never puts the contiguous canary in its prompt", () => {
    const split = jailbreakProbes.find((p) => p.id === "jb-payload-split");
    expect(split).toBeDefined();
    const [payload] = split!.payloads({ canary: CANARY });
    expect(payload).not.toContain(CANARY); // it's fragmented; the model must reassemble it
  });

  it("all jailbreak probes carry the jailbreak tag and a non-empty description", () => {
    for (const p of jailbreakProbes) {
      expect(p.tags).toContain("jailbreak");
      expect(p.description.length).toBeGreaterThan(0);
    }
  });
});
