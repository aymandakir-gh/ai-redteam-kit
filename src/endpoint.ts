import type { Endpoint } from "./types.js";

export interface HttpEndpointConfig {
  /** The endpoint URL (e.g. an OpenAI-compatible /v1/chat/completions). */
  url: string;
  /** HTTP method. Default: POST. */
  method?: string;
  /** Extra headers (e.g. Authorization). Merged over the JSON content-type default. */
  headers?: Record<string, string>;
  /** Model name placed in the default request body. Ignored if `buildBody` is set. */
  model?: string;
  /**
   * Build the request body from a prompt. Default: OpenAI chat-completions
   * shape `{ model, messages: [{ role: "user", content: prompt }] }`.
   */
  buildBody?: (prompt: string) => unknown;
  /**
   * Extract the assistant's text from the parsed JSON response. Default: try a
   * list of common response shapes (OpenAI, Anthropic-ish, plain `{response}`).
   */
  extractText?: (json: unknown) => string;
  /** Per-request timeout in ms. Default: 30000. */
  timeoutMs?: number;
}

function defaultBody(model: string | undefined) {
  return (prompt: string): unknown => ({
    ...(model !== undefined ? { model } : {}),
    messages: [{ role: "user", content: prompt }],
  });
}

/** Pull a string out of an unknown value at a dot path, or undefined. */
function atPath(obj: unknown, path: string): string | undefined {
  let cur: unknown = obj;
  for (const key of path.split(".")) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[key.replace(/\[(\d+)\]$/, "")];
    const idx = key.match(/\[(\d+)\]$/);
    if (idx) {
      if (!Array.isArray(cur)) return undefined;
      cur = cur[Number(idx[1])];
    }
  }
  return typeof cur === "string" ? cur : undefined;
}

const DEFAULT_PATHS = [
  "choices[0].message.content",
  "choices[0].text",
  "message.content",
  "content",
  "output_text",
  "response",
  "text",
];

function defaultExtract(json: unknown): string {
  if (typeof json === "string") return json;
  for (const p of DEFAULT_PATHS) {
    const v = atPath(json, p);
    if (typeof v === "string") return v;
  }
  throw new Error(
    "Could not locate assistant text in the response. Pass `extractText` to map your endpoint's shape.",
  );
}

/**
 * Build an {@link Endpoint} that POSTs to an HTTP chat API. Defaults to the
 * OpenAI chat-completions request/response shape; override `buildBody` and
 * `extractText` for any other API. Throws a descriptive error on non-2xx,
 * timeout, or an unparseable/locating failure so the engine can record it.
 */
export function httpEndpoint(cfg: HttpEndpointConfig): Endpoint {
  const method = cfg.method ?? "POST";
  const buildBody = cfg.buildBody ?? defaultBody(cfg.model);
  const extractText = cfg.extractText ?? defaultExtract;
  const timeoutMs = cfg.timeoutMs ?? 30000;

  return async (prompt, opts) => {
    const timer = new AbortController();
    const t = setTimeout(() => timer.abort(new Error("request timed out")), timeoutMs);
    const signal = opts?.signal
      ? AbortSignal.any([opts.signal, timer.signal])
      : timer.signal;
    try {
      const res = await fetch(cfg.url, {
        method,
        headers: { "content-type": "application/json", ...cfg.headers },
        body: JSON.stringify(buildBody(prompt)),
        signal,
      });
      const raw = await res.text();
      if (!res.ok) {
        throw new Error(`endpoint returned HTTP ${res.status}: ${raw.slice(0, 300)}`);
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        // Some endpoints return plain text — treat the body as the answer.
        return raw;
      }
      return extractText(parsed);
    } finally {
      clearTimeout(t);
    }
  };
}
