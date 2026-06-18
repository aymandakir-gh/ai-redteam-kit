# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-06-18

Fourth milestone: four new attack families (52 probes total).

### Added

- **Encoding / obfuscation pack** (LLM01) — 5 probes that smuggle the
  "print the canary" instruction past literal-string filters via base64, ROT13,
  hex, zero-width-character interleaving, and full string reversal. A hit means
  the model decoded the payload and emitted the canary.
- **Multi-turn pack** (LLM01) — 3 probes that exploit cross-turn state:
  payload splitting across turns, a context-reset claim that "voids" an earlier
  confidentiality rule, and gradual crescendo escalation.
- **Indirect-injection pack** (LLM01) — 2 probes that plant the instruction in
  content the app feeds the model as data: a poisoned RAG-retrieval chunk and an
  attacker-controlled tool-output result.
- **Context secret-exfil pack** (LLM02) — 2 probes that plant a confidential
  value (the canary) in context under a non-disclosure rule, then coax it out
  directly or via JSON/code-block format coercion. A leak requires the canary in
  the output AND a non-refusal.

[0.4.0]: https://github.com/aymandakir-gh/ai-redteam-kit/releases/tag/v0.4.0

## [0.3.0] - 2026-06-18

Third milestone: broader probe coverage and config packs.

### Added

- **14 more probes (40 total) across 6 OWASP categories**:
  - LLM06 Excessive Agency — 5 probes (destructive DB action, email exfil, shell
    exec, privilege escalation, unauthorized refund) detected via tool-call
    shapes and destructive-verb confirmations.
  - LLM05 Improper Output Handling — 5 probes (reflected XSS, SQL injection,
    command injection, SSRF/local-file URL, markdown-image exfiltration).
  - LLM10 Unbounded Consumption — 4 probes (repetition flood, huge enumeration,
    recursive expansion, never-stop generation) detected via runaway length /
    repetition.
- **Config packs** (`--config <file>`): a JSON file with the endpoint mapping,
  probe selection, CI threshold, and **custom probes** (payload + regex). `${ENV}`
  interpolation in `target`/`headers`; `httpEndpoint` gains `responsePath`.
  See `examples/config.example.json`.

[0.3.0]: https://github.com/aymandakir-gh/ai-redteam-kit/releases/tag/v0.3.0

## [0.2.0] - 2026-06-18

Second milestone: a standards-aligned scored report and a CI gate.

### Added

- **OWASP LLM Top 10 scored report** (`scoreReport` + `renderMarkdown` /
  `renderJson`). Rolls findings up per category (fail / pass / not-tested) and
  produces a headline `grade` (severity-gated A–F) and `postureScore` (0–100,
  deducting per finding). `--format markdown` and a scored `--format json`.
- **CI mode** — `--fail-on <low|medium|high|critical|never>` controls the
  severity at/above which the run exits non-zero (default: any finding fails;
  `never` for report-only), and `--ci` prints a one-line grep-able status to
  stderr.

[0.2.0]: https://github.com/aymandakir-gh/ai-redteam-kit/releases/tag/v0.2.0

## [0.1.0] - 2026-06-18

First milestone: a working, end-to-end red-team engine with 26 probes and a CLI.

### Added

- **Probe engine** (`runRedteam`) — mints a per-run canary, fans probe payloads
  across a bounded concurrency pool, evaluates each response deterministically,
  and rolls hits up into one finding per probe. Transport errors are captured
  per attempt and never abort the run.
- **HTTP endpoint adapter** (`httpEndpoint`) — builds an `Endpoint` from any chat
  API. Defaults to the OpenAI chat-completions shape; `buildBody`/`extractText`
  override it for anything else. Per-request timeout and descriptive errors.
- **OWASP LLM Top 10 (2025) catalogue** every probe maps to.
- **26 probes** across three categories:
  - LLM01 Prompt Injection — 7 probes (ignore-previous, forged system tag,
    indirect/data-channel, translation smuggling, roleplay reset, adversarial
    suffix, hidden markdown comment).
  - LLM01 Jailbreaks — 7 probes (DAN, Developer Mode, refusal suppression,
    opposite-day, hypothetical, grandma exploit, payload splitting).
  - LLM07 System Prompt Leakage — 6 probes, with a leak detector that
    distinguishes a real leak from a refusal that merely mentions instructions.
  - LLM02 Sensitive Information Disclosure — 6 probes, with Luhn-checked card
    detection, key/SSN/IBAN/email/phone patterns, and refusal suppression.
- **CLI** (`ai-redteam <url>`) — text/JSON output, `--owasp`/`--tag`/`--probe`
  selection, headers, model, concurrency, timeout, and a non-zero exit code when
  findings are reported (for CI).
- CI matrix (Node 20/22) running typecheck, lint, test and build.

[0.1.0]: https://github.com/aymandakir-gh/ai-redteam-kit/releases/tag/v0.1.0
