import { readFileSync } from "node:fs";
import { OWASP_IDS } from "./owasp.js";
import type { OwaspId } from "./owasp.js";
import type { FailOn, Probe, Severity } from "./types.js";
import { looksLikeRefusal } from "./probes/helpers.js";

/**
 * Config packs — a JSON file that captures a reusable red-team setup: the
 * endpoint mapping, which probes to run, CI thresholds, and any number of
 * user-defined custom probes (a payload + a regex that flags the response).
 * This makes the kit extensible without writing code.
 */

const SEVERITIES = new Set<Severity>(["low", "medium", "high", "critical"]);
const FAIL_ON = new Set<FailOn>(["low", "medium", "high", "critical", "never"]);

export interface CustomProbeDef {
  id: string;
  owasp: OwaspId;
  severity: Severity;
  title: string;
  description?: string;
  payloads: string[];
  /** A finding is reported when this regex matches a non-refusal response. */
  match: { regex: string; flags?: string };
  /** When true, the regex match counts even if the response looks like a refusal. */
  allowRefusal?: boolean;
  tags?: string[];
}

export interface ProbeSelection {
  owasp?: string[];
  tags?: string[];
  probes?: string[];
  exclude?: string[];
}

export interface Config {
  target?: string;
  headers?: Record<string, string>;
  model?: string;
  timeoutMs?: number;
  concurrency?: number;
  failOn?: FailOn;
  responsePath?: string;
  select?: ProbeSelection;
  customProbes?: CustomProbeDef[];
}

/** Replace `${VAR}` references with environment variables; throws on a missing var. */
export function interpolateEnv(value: string, env: NodeJS.ProcessEnv = process.env): string {
  return value.replace(/\$\{([A-Z0-9_]+)\}/gi, (_m, name: string) => {
    const v = env[name];
    if (v === undefined) throw new Error(`config references undefined env var \${${name}}`);
    return v;
  });
}

function fail(msg: string): never {
  throw new Error(`invalid config: ${msg}`);
}

function asStringArray(v: unknown, where: string): string[] {
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) fail(`${where} must be a string array`);
  return v as string[];
}

/** Turn a custom-probe definition into a runnable {@link Probe}. */
export function customProbe(def: CustomProbeDef): Probe {
  if (!def.id || typeof def.id !== "string") fail("customProbes[].id is required");
  if (!OWASP_IDS.includes(def.owasp)) fail(`customProbes[${def.id}].owasp "${def.owasp}" is not a valid OWASP id`);
  if (!SEVERITIES.has(def.severity)) fail(`customProbes[${def.id}].severity "${def.severity}" is invalid`);
  if (!def.title) fail(`customProbes[${def.id}].title is required`);
  if (!Array.isArray(def.payloads) || def.payloads.length === 0) fail(`customProbes[${def.id}].payloads must be a non-empty array`);
  if (!def.match || typeof def.match.regex !== "string") fail(`customProbes[${def.id}].match.regex is required`);
  let re: RegExp;
  try {
    re = new RegExp(def.match.regex, def.match.flags ?? "i");
  } catch (err) {
    return fail(`customProbes[${def.id}].match.regex is not a valid regex: ${(err as Error).message}`);
  }
  const payloads = [...def.payloads];
  return {
    id: def.id,
    owasp: def.owasp,
    severity: def.severity,
    title: def.title,
    description: def.description ?? `Custom probe ${def.id}`,
    tags: ["custom", ...(def.tags ?? [])],
    payloads: () => payloads,
    evaluate: (response) => {
      if (!def.allowRefusal && looksLikeRefusal(response)) return null;
      const m = re.exec(response);
      return m ? { evidence: m[0], detail: `Custom rule "${def.id}" matched the response.` } : null;
    },
  };
}

/** Validate a parsed config object (after JSON.parse), with clear errors. */
export function validateConfig(raw: unknown): Config {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) fail("top level must be an object");
  const o = raw as Record<string, unknown>;
  const cfg: Config = {};

  if (o.target !== undefined) {
    if (typeof o.target !== "string") fail("target must be a string");
    cfg.target = interpolateEnv(o.target);
  }
  if (o.headers !== undefined) {
    if (typeof o.headers !== "object" || o.headers === null) fail("headers must be an object");
    cfg.headers = {};
    for (const [k, v] of Object.entries(o.headers)) {
      if (typeof v !== "string") fail(`headers.${k} must be a string`);
      cfg.headers[k] = interpolateEnv(v);
    }
  }
  if (o.model !== undefined) {
    if (typeof o.model !== "string") fail("model must be a string");
    cfg.model = o.model;
  }
  if (o.timeoutMs !== undefined) {
    if (typeof o.timeoutMs !== "number") fail("timeoutMs must be a number");
    cfg.timeoutMs = o.timeoutMs;
  }
  if (o.concurrency !== undefined) {
    if (typeof o.concurrency !== "number") fail("concurrency must be a number");
    cfg.concurrency = o.concurrency;
  }
  if (o.failOn !== undefined) {
    if (!FAIL_ON.has(o.failOn as FailOn)) fail(`failOn "${String(o.failOn)}" is invalid (low|medium|high|critical|never)`);
    cfg.failOn = o.failOn as FailOn;
  }
  if (o.responsePath !== undefined) {
    if (typeof o.responsePath !== "string") fail("responsePath must be a string");
    cfg.responsePath = o.responsePath;
  }
  if (o.select !== undefined) {
    if (typeof o.select !== "object" || o.select === null) fail("select must be an object");
    const s = o.select as Record<string, unknown>;
    cfg.select = {};
    if (s.owasp !== undefined) cfg.select.owasp = asStringArray(s.owasp, "select.owasp");
    if (s.tags !== undefined) cfg.select.tags = asStringArray(s.tags, "select.tags");
    if (s.probes !== undefined) cfg.select.probes = asStringArray(s.probes, "select.probes");
    if (s.exclude !== undefined) cfg.select.exclude = asStringArray(s.exclude, "select.exclude");
  }
  if (o.customProbes !== undefined) {
    if (!Array.isArray(o.customProbes)) fail("customProbes must be an array");
    // Build each to validate; store the defs (built again at use site).
    cfg.customProbes = o.customProbes.map((d) => {
      customProbe(d as CustomProbeDef); // throws on invalid
      return d as CustomProbeDef;
    });
  }

  return cfg;
}

/** Read and validate a config pack from disk. */
export function loadConfig(path: string): Config {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new Error(`could not read config file: ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`config file is not valid JSON: ${(err as Error).message}`);
  }
  return validateConfig(parsed);
}

/** Apply a {@link ProbeSelection} to a probe list (OR within a kind, AND across kinds, then exclude). */
export function selectFromConfig(all: readonly Probe[], sel: ProbeSelection | undefined): readonly Probe[] {
  if (!sel) return all;
  const owasp = sel.owasp?.map((s) => s.toUpperCase());
  const tags = sel.tags?.map((s) => s.toLowerCase());
  const probes = sel.probes?.map((s) => s.toLowerCase());
  const exclude = new Set(sel.exclude?.map((s) => s.toLowerCase()));
  return all.filter((p) => {
    if (exclude.has(p.id.toLowerCase())) return false;
    if (owasp && !owasp.includes(p.owasp)) return false;
    if (probes && !probes.includes(p.id.toLowerCase())) return false;
    if (tags && !(p.tags ?? []).some((t) => tags.includes(t.toLowerCase()))) return false;
    return true;
  });
}
