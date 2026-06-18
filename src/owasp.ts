/**
 * The OWASP Top 10 for Large Language Model Applications (2025).
 *
 * Each probe in this kit is mapped to one of these categories so findings can be
 * rolled up into a familiar, standards-aligned risk report. IDs follow the
 * `LLM0N` convention used by the OWASP GenAI project.
 *
 * Reference: https://genai.owasp.org/llm-top-10/
 */

export const OWASP_IDS = [
  "LLM01",
  "LLM02",
  "LLM03",
  "LLM04",
  "LLM05",
  "LLM06",
  "LLM07",
  "LLM08",
  "LLM09",
  "LLM10",
] as const;

export type OwaspId = (typeof OWASP_IDS)[number];

export interface OwaspCategory {
  id: OwaspId;
  /** Short slug, e.g. "prompt-injection". */
  slug: string;
  /** Human-readable title. */
  title: string;
  /** One-line description of the risk. */
  summary: string;
}

export const OWASP_CATALOG: Readonly<Record<OwaspId, OwaspCategory>> = Object.freeze({
  LLM01: {
    id: "LLM01",
    slug: "prompt-injection",
    title: "Prompt Injection",
    summary:
      "User or third-party content overrides the developer's instructions, steering the model to unintended behaviour.",
  },
  LLM02: {
    id: "LLM02",
    slug: "sensitive-information-disclosure",
    title: "Sensitive Information Disclosure",
    summary:
      "The model reveals secrets, credentials, PII or proprietary data in its output.",
  },
  LLM03: {
    id: "LLM03",
    slug: "supply-chain",
    title: "Supply Chain",
    summary:
      "Compromised models, datasets, plugins or dependencies introduce vulnerabilities.",
  },
  LLM04: {
    id: "LLM04",
    slug: "data-and-model-poisoning",
    title: "Data and Model Poisoning",
    summary:
      "Manipulated training or retrieval data biases, backdoors or degrades the model.",
  },
  LLM05: {
    id: "LLM05",
    slug: "improper-output-handling",
    title: "Improper Output Handling",
    summary:
      "Model output is consumed downstream without validation, enabling XSS, SSRF, SQLi or code execution.",
  },
  LLM06: {
    id: "LLM06",
    slug: "excessive-agency",
    title: "Excessive Agency",
    summary:
      "The model is granted tools/permissions broad enough that a manipulated prompt can take harmful actions.",
  },
  LLM07: {
    id: "LLM07",
    slug: "system-prompt-leakage",
    title: "System Prompt Leakage",
    summary:
      "The system prompt — and any secrets or rules embedded in it — is exposed to the user.",
  },
  LLM08: {
    id: "LLM08",
    slug: "vector-and-embedding-weaknesses",
    title: "Vector and Embedding Weaknesses",
    summary:
      "Weaknesses in RAG/embedding pipelines allow injection, poisoning or leakage across tenants.",
  },
  LLM09: {
    id: "LLM09",
    slug: "misinformation",
    title: "Misinformation",
    summary:
      "The model confidently produces false or fabricated information that users may act on.",
  },
  LLM10: {
    id: "LLM10",
    slug: "unbounded-consumption",
    title: "Unbounded Consumption",
    summary:
      "Unrestricted, expensive or runaway generation enables denial-of-wallet and resource exhaustion.",
  },
});

/** Look up a category by id, throwing on an unknown id (defensive — ids are a closed set). */
export function owaspCategory(id: OwaspId): OwaspCategory {
  const cat = OWASP_CATALOG[id];
  if (!cat) throw new Error(`Unknown OWASP id: ${id}`);
  return cat;
}
