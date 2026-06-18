import type { Probe } from "../types.js";
import { promptInjectionProbes } from "./prompt-injection.js";
import { jailbreakProbes } from "./jailbreak.js";
import { systemPromptLeakProbes } from "./system-prompt-leak.js";
import { sensitiveDisclosureProbes } from "./sensitive-disclosure.js";
import { excessiveAgencyProbes } from "./excessive-agency.js";

/**
 * The built-in probe registry. Packs are added here as they land; the CLI runs
 * `ALL_PROBES` by default and supports selecting by id, OWASP id, or tag.
 */
export const ALL_PROBES: readonly Probe[] = [
  ...promptInjectionProbes,
  ...jailbreakProbes,
  ...systemPromptLeakProbes,
  ...sensitiveDisclosureProbes,
  ...excessiveAgencyProbes,
];

export {
  promptInjectionProbes,
  jailbreakProbes,
  systemPromptLeakProbes,
  sensitiveDisclosureProbes,
  excessiveAgencyProbes,
};

/** Probe ids must be unique — guard against accidental collisions at module load. */
const ids = ALL_PROBES.map((p) => p.id);
const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
if (dupes.length > 0) {
  throw new Error(`Duplicate probe ids: ${[...new Set(dupes)].join(", ")}`);
}
