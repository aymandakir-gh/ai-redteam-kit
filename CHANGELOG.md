# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

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
