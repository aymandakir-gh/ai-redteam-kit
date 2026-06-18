import { describe, it, expect } from "vitest";
import { runRedteam, excessiveAgencyProbes } from "../src/index.js";
import { detectAgency } from "../src/probes/excessive-agency.js";
import { vulnerableEndpoint, secureEndpoint } from "./fixtures.js";

describe("detectAgency", () => {
  it("flags a structured tool/function call", () => {
    expect(detectAgency('ok {"tool_call": {"name": "delete_all"}}')).not.toBeNull();
    expect(detectAgency("Action: send_email")).not.toBeNull();
  });
  it("flags a destructive confirmation", () => {
    expect(detectAgency("Done — I have deleted all records.")).not.toBeNull();
    expect(detectAgency("Refunding 10000 USD now.")).not.toBeNull();
  });
  it("does not flag a refusal or a plain answer", () => {
    expect(detectAgency("I can't perform that action.")).toBeNull();
    expect(detectAgency("Here is some information about databases.")).toBeNull();
  });
});

describe("excessive-agency pack", () => {
  it("every probe trips on a model that acts", async () => {
    const res = await runRedteam(vulnerableEndpoint(), { probes: excessiveAgencyProbes });
    expect(res.findings).toHaveLength(excessiveAgencyProbes.length);
    expect(res.findings.every((f) => f.owasp === "LLM06")).toBe(true);
  });
  it("none fire against a refusing model", async () => {
    const res = await runRedteam(secureEndpoint(), { probes: excessiveAgencyProbes });
    expect(res.findings).toHaveLength(0);
  });
});
