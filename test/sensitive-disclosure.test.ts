import { describe, it, expect } from "vitest";
import { runRedteam, sensitiveDisclosureProbes } from "../src/index.js";
import { detectPii, detectDisclosure } from "../src/probes/sensitive-disclosure.js";
import { vulnerableEndpoint, secureEndpoint } from "./fixtures.js";

describe("detectPii", () => {
  it("flags a Luhn-valid card but not an arbitrary 16-digit run", () => {
    expect(detectPii("card 4242 4242 4242 4242")?.type).toBe("credit-card");
    expect(detectPii("order 1234 5678 9012 3456")).toBeNull(); // fails Luhn
  });
  it("flags emails, SSNs and key prefixes", () => {
    expect(detectPii("reach me at a.b@example.com")?.type).toBe("email");
    expect(detectPii("ssn 123-45-6789")?.type).toBe("us-ssn");
    expect(detectPii("key sk-live-aB3dEfGhIjKlMnOpQr")?.type).toBe("openai/stripe-key");
  });
  it("ignores benign text", () => {
    expect(detectPii("The meeting is at 3pm on the 4th.")).toBeNull();
  });
});

describe("detectDisclosure", () => {
  it("does not flag a refusal even if it echoes the request words", () => {
    expect(detectDisclosure("I can't share any email addresses or card numbers.")).toBeNull();
  });
});

describe("sensitive-disclosure pack", () => {
  it("every probe extracts sensitive data from a vulnerable model", async () => {
    const res = await runRedteam(vulnerableEndpoint(), { probes: sensitiveDisclosureProbes });
    expect(res.findings).toHaveLength(sensitiveDisclosureProbes.length);
    expect(res.findings.every((f) => f.owasp === "LLM02")).toBe(true);
  });
  it("none fire against a refusing model", async () => {
    const res = await runRedteam(secureEndpoint(), { probes: sensitiveDisclosureProbes });
    expect(res.findings).toHaveLength(0);
  });
});
