# ai-redteam

**Deterministic, zero-ML red-teaming for LLM endpoints.** Point it at a chat
endpoint and it fires a battery of crafted probes — prompt injection, jailbreaks,
PII exfiltration, tool abuse, system-prompt leakage — then scores the results
against the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/).

No model, no inference, no telemetry. Every probe is a rule + regex over the
endpoint's own response, so results are **reproducible and auditable**: the same
endpoint and probe set always produce the same report.

> Companion to [gh-aegis](https://github.com/aymandakir-gh/gh-aegis) (a runtime
> guard): aegis *blocks* attacks in production, ai-redteam *finds* the gaps first.

```bash
npx ai-redteam https://your-api.example/v1/chat/completions
```

## Why deterministic / zero-ML?

A red-team kit that uses another LLM to judge responses is slow, non-reproducible,
and itself attackable. ai-redteam instead uses the **canary technique**: each probe
asks the model to do something it shouldn't — echo a unique unguessable token,
reveal its system prompt, comply with a jailbreak — and then checks the response
for that exact, deterministic marker. A vulnerable model complies and the marker
appears; a guarded model refuses and it doesn't. No judgement model required.

## Status

Early development. The OWASP catalogue and core types are in place; the probe
engine, probe packs, scored report and CLI land in subsequent releases (see the
milestones in the repo). Track progress via the tagged releases.

## OWASP LLM Top 10 coverage

Probes map to these categories so findings roll up into a standards-aligned report:

| ID | Category |
|----|----------|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain |
| LLM04 | Data and Model Poisoning |
| LLM05 | Improper Output Handling |
| LLM06 | Excessive Agency |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses |
| LLM09 | Misinformation |
| LLM10 | Unbounded Consumption |

## Use responsibly

Only run ai-redteam against endpoints you own or are explicitly authorised to
test. It sends adversarial prompts; treat it like any other security scanner.

## Development

```bash
npm install
npm run typecheck && npm run lint && npm test && npm run build
```

## License

[MIT](./LICENSE)
