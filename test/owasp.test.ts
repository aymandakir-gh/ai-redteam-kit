import { describe, it, expect } from "vitest";
import { OWASP_IDS, OWASP_CATALOG, owaspCategory } from "../src/owasp.js";

describe("OWASP catalog", () => {
  it("covers all ten LLM Top 10 categories", () => {
    expect(OWASP_IDS).toHaveLength(10);
    expect(Object.keys(OWASP_CATALOG)).toHaveLength(10);
  });

  it("every id has a category whose id matches its key, with a non-empty title/summary/slug", () => {
    for (const id of OWASP_IDS) {
      const cat = OWASP_CATALOG[id];
      expect(cat.id).toBe(id);
      expect(cat.slug).toMatch(/^[a-z][a-z-]+$/);
      expect(cat.title.length).toBeGreaterThan(0);
      expect(cat.summary.length).toBeGreaterThan(0);
    }
  });

  it("slugs are unique", () => {
    const slugs = OWASP_IDS.map((id) => OWASP_CATALOG[id].slug);
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it("owaspCategory looks up a known id", () => {
    expect(owaspCategory("LLM01").slug).toBe("prompt-injection");
    expect(owaspCategory("LLM07").title).toBe("System Prompt Leakage");
  });

  it("the catalog is frozen (immutable)", () => {
    expect(Object.isFrozen(OWASP_CATALOG)).toBe(true);
  });
});
