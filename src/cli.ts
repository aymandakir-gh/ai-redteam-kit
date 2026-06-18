#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ALL_PROBES } from "./probes/index.js";
import { httpEndpoint } from "./endpoint.js";
import { runRedteam } from "./engine.js";
import { scoreReport, renderMarkdown, renderJson } from "./report.js";
import { loadConfig, customProbe, selectFromConfig } from "./config.js";
import type { Config } from "./config.js";
import { OWASP_CATALOG } from "./owasp.js";
import type { OwaspId } from "./owasp.js";
import { SEVERITY_ORDER } from "./types.js";
import type { FailOn, Probe, RunResult, Severity } from "./types.js";
import type { ScoredReport } from "./report.js";

export interface CliIo {
  out: (s: string) => void;
  err: (s: string) => void;
}

const defaultIo: CliIo = {
  out: (s) => process.stdout.write(s),
  err: (s) => process.stderr.write(s),
};

function version(): string {
  try {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    return typeof pkg.version === "string" ? pkg.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

const HELP = `ai-redteam — deterministic, zero-ML red-teaming for LLM endpoints

Usage:
  ai-redteam <url> [options]

Options:
  -H, --header <"K: V">   Add a request header (repeatable), e.g. Authorization
      --model <name>      Model name to put in the request body
      --owasp <ids>       Only run these OWASP categories (comma list, e.g. LLM01,LLM07)
      --tag <tags>        Only run probes with these tags (comma list)
      --probe <ids>       Only run these probe ids (comma list)
      --concurrency <n>   Max concurrent requests (default 4)
      --timeout <ms>      Per-request timeout (default 30000)
      --format <fmt>      Output format: text | json | markdown (default text)
      --output <file>     Write the report to a file instead of stdout
      --fail-on <sev>     CI gate: exit non-zero only at/above this severity
                          (low|medium|high|critical|never; default low)
      --ci                Print a one-line grep-able status to stderr
      --config <file>     Load a JSON config pack (endpoint, selection, custom probes)
      --list              List available probes and exit
  -v, --version           Print version and exit
  -h, --help              Show this help and exit

Exit code is non-zero when any finding is reported (useful in CI).
Only test endpoints you are authorised to assess.`;

interface ParsedArgs {
  url?: string;
  headers: Record<string, string>;
  model?: string;
  owasp?: string[];
  tag?: string[];
  probe?: string[];
  concurrency?: number;
  timeout?: number;
  format: "text" | "json" | "markdown";
  output?: string;
  failOn?: FailOn;
  ci: boolean;
  config?: string;
  list: boolean;
  help: boolean;
  version: boolean;
  error?: string;
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const a: ParsedArgs = { headers: {}, format: "text", ci: false, list: false, help: false, version: false };
  const list = (v: string) => v.split(",").map((s) => s.trim()).filter(Boolean);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    const value = () => argv[++i] ?? "";
    switch (arg) {
      case "-h":
      case "--help":
        a.help = true;
        break;
      case "-v":
      case "--version":
        a.version = true;
        break;
      case "--list":
        a.list = true;
        break;
      case "-H":
      case "--header": {
        const h = value();
        const idx = h.indexOf(":");
        if (idx === -1) {
          a.error = `invalid header (expected "Key: Value"): ${h}`;
        } else {
          a.headers[h.slice(0, idx).trim()] = h.slice(idx + 1).trim();
        }
        break;
      }
      case "--model":
        a.model = value();
        break;
      case "--owasp":
        a.owasp = list(value());
        break;
      case "--tag":
        a.tag = list(value());
        break;
      case "--probe":
        a.probe = list(value());
        break;
      case "--concurrency":
        a.concurrency = Number(value());
        break;
      case "--timeout":
        a.timeout = Number(value());
        break;
      case "--format": {
        const raw = value();
        const fmt = raw === "md" ? "markdown" : raw;
        if (fmt !== "text" && fmt !== "json" && fmt !== "markdown") {
          a.error = `invalid --format: ${raw} (use text|json|markdown)`;
        } else {
          a.format = fmt;
        }
        break;
      }
      case "--output":
        a.output = value();
        break;
      case "--ci":
        a.ci = true;
        break;
      case "--config":
        a.config = value();
        break;
      case "--fail-on": {
        const v = value();
        if (v === "low" || v === "medium" || v === "high" || v === "critical" || v === "never") {
          a.failOn = v;
        } else {
          a.error = `invalid --fail-on: ${v} (use low|medium|high|critical|never)`;
        }
        break;
      }
      default:
        if (arg.startsWith("-")) a.error = `unknown option: ${arg}`;
        else if (a.url === undefined) a.url = arg;
        else a.error = `unexpected argument: ${arg}`;
    }
  }
  return a;
}

/** Filter the registry by OWASP id / tag / probe id (case-insensitive). AND across kinds. */
export function selectProbes(
  all: readonly Probe[],
  filters: { owasp?: string[]; tag?: string[]; probe?: string[] },
): readonly Probe[] {
  const owasp = filters.owasp?.map((s) => s.toUpperCase());
  const tag = filters.tag?.map((s) => s.toLowerCase());
  const probe = filters.probe?.map((s) => s.toLowerCase());
  return all.filter((p) => {
    if (owasp && !owasp.includes(p.owasp)) return false;
    if (probe && !probe.includes(p.id.toLowerCase())) return false;
    if (tag && !(p.tags ?? []).some((t) => tag.includes(t.toLowerCase()))) return false;
    return true;
  });
}

const SEV_ICON: Record<Severity, string> = {
  critical: "✖",
  high: "▲",
  medium: "■",
  low: "·",
};

/** Basic human-readable report. The OWASP-scored report arrives in a later release. */
export function formatTextReport(result: RunResult): string {
  const lines: string[] = [];
  lines.push(`ai-redteam — target ${result.target}`);
  lines.push(`Ran ${result.probesRun} probes (${result.attempts.length} requests) in ${result.durationMs}ms`);
  const errors = result.attempts.filter((x) => x.error).length;
  if (errors > 0) lines.push(`${errors} request(s) errored.`);
  lines.push("");
  if (result.findings.length === 0) {
    lines.push("No findings. ✓");
    return lines.join("\n");
  }
  const order: Severity[] = ["critical", "high", "medium", "low"];
  const sorted = [...result.findings].sort(
    (x, y) => order.indexOf(x.severity) - order.indexOf(y.severity),
  );
  lines.push(`FINDINGS (${result.findings.length}):`);
  for (const f of sorted) {
    const cat = OWASP_CATALOG[f.owasp as OwaspId];
    lines.push(`  ${SEV_ICON[f.severity]} [${f.severity.toUpperCase()}] ${f.owasp} ${cat.title}`);
    lines.push(`     ${f.probeId} — ${f.title}`);
    lines.push(`     evidence: ${f.evidence.replace(/\s+/g, " ").slice(0, 120)}`);
  }
  const cats = new Set(result.findings.map((f) => f.owasp));
  lines.push("");
  lines.push(`Result: ${result.findings.length} finding(s) across ${cats.size} OWASP categor${cats.size === 1 ? "y" : "ies"}.`);
  return lines.join("\n");
}

/**
 * The CI gate: exit non-zero when a finding at or above the threshold exists.
 * `"never"` always passes (report-only). Default threshold is `"low"`, so any
 * finding fails the build.
 */
export function exitCodeFor(report: ScoredReport, failOn: FailOn = "low"): number {
  if (failOn === "never") return 0;
  const threshold = SEVERITY_ORDER[failOn];
  const tripped = report.findings.some((f) => SEVERITY_ORDER[f.severity] >= threshold);
  return tripped ? 1 : 0;
}

/** A single grep-able status line for CI logs. */
export function ciSummary(report: ScoredReport, failed: boolean): string {
  const s = report.totals.bySeverity;
  return `ai-redteam: ${failed ? "FAIL" : "PASS"} grade=${report.grade} posture=${report.postureScore} findings=${report.totals.findings} critical=${s.critical} high=${s.high} medium=${s.medium} low=${s.low}`;
}

/** Run the CLI. Returns a process exit code; never throws for expected errors. */
export async function runCli(argv: readonly string[], io: CliIo = defaultIo): Promise<number> {
  const args = parseArgs(argv);

  if (args.help) {
    io.out(HELP + "\n");
    return 0;
  }
  if (args.version) {
    io.out(version() + "\n");
    return 0;
  }
  if (args.error) {
    io.err(`error: ${args.error}\n`);
    return 2;
  }

  // Load the optional config pack (endpoint mapping, selection, custom probes).
  let config: Config = {};
  if (args.config) {
    try {
      config = loadConfig(args.config);
    } catch (err) {
      io.err(`error: ${err instanceof Error ? err.message : String(err)}\n`);
      return 2;
    }
  }
  const registry: readonly Probe[] = [...ALL_PROBES, ...(config.customProbes ?? []).map(customProbe)];

  // CLI selection flags take precedence; otherwise fall back to the config's.
  const cliHasSelection = Boolean(args.owasp || args.tag || args.probe);
  const probesFor = (all: readonly Probe[]) =>
    cliHasSelection ? selectProbes(all, args) : selectFromConfig(all, config.select);

  if (args.list) {
    const probes = probesFor(registry);
    for (const p of probes) {
      io.out(`${p.id.padEnd(26)} ${p.owasp}  [${p.severity}]  ${p.title}\n`);
    }
    io.out(`\n${probes.length} probe(s).\n`);
    return 0;
  }

  const target = args.url ?? config.target;
  if (!target) {
    io.err("error: missing target URL (pass it as an argument or set `target` in --config)\n\n" + HELP + "\n");
    return 2;
  }

  const probes = probesFor(registry);
  if (probes.length === 0) {
    io.err("error: no probes match the given selection\n");
    return 2;
  }

  const timeoutMs = args.timeout ?? config.timeoutMs;
  const concurrency = args.concurrency ?? config.concurrency;
  const failOn = args.failOn ?? config.failOn;

  const endpoint = httpEndpoint({
    url: target,
    headers: { ...config.headers, ...args.headers },
    ...(args.model ?? config.model ? { model: args.model ?? config.model } : {}),
    ...(config.responsePath !== undefined ? { responsePath: config.responsePath } : {}),
    ...(timeoutMs !== undefined && !Number.isNaN(timeoutMs) ? { timeoutMs } : {}),
  });

  const result = await runRedteam(endpoint, {
    target,
    probes,
    ...(concurrency !== undefined && !Number.isNaN(concurrency) ? { concurrency } : {}),
  });

  const report = scoreReport(result, probes);
  let output: string;
  if (args.format === "json") output = renderJson(report);
  else if (args.format === "markdown") output = renderMarkdown(report);
  else output = formatTextReport(result);
  if (args.output) {
    writeFileSync(args.output, output + "\n");
    io.out(`Report written to ${args.output}\n`);
  } else {
    io.out(output + "\n");
  }

  const code = exitCodeFor(report, failOn);
  if (args.ci) io.err(ciSummary(report, code !== 0) + "\n");
  return code;
}

// Entry point when executed directly (not imported).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runCli(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      defaultIo.err(`fatal: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(70);
    },
  );
}
