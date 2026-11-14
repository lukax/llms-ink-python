# Changelog

## 0.6.0 — 2026-11-14

- Optional `llms-ink-guard wrap --policy FILE -- COMMAND`: deny outgoing tool calls unless the local policy matches the exact command, reviewed tool-definition hash and argument object.
- Load and validate permissions before starting the model or server; hold an immutable snapshot for the connection. Hide unapproved definitions from discovery. Model results and server annotations cannot grant permissions.
- `policy-check` validates permissions without running a server; `tool-hash` fingerprints a reviewed tool object from stdin.
- Reject ambiguous JSON, unsupported call extensions and malformed discovery. Payload-free denial events; no automatic approval, wildcards or live policy edits.
- Classifier/model unchanged. The published 0.4.0 InjecAgent evaluation missed all 1,054 attacks; this action boundary is separate from content detection and does not sandbox the server or cover native host tools.

## 0.5.0 — 2026-11-14

- Explicit hosted `inspect(text)` with immutable, digest-bound receipts and pilot revision validation.
- Flagged and incomplete scans remain `withhold`; malformed receipts fail closed.
- Required key, encoded request/response limits, redirect refusal and no automatic retries.
- No changes to default retrieval, loaders or local guard behavior.

## 0.4.0 — 2026-11-14

- Experimental local MCP result guard: optional `[guard]` dependencies, pinned model setup/status, text scanning and a bounded stdio wrapper.
- `llms-ink-mcp --guard` inspects llms.ink responses before delivery; the default bridge remains unchanged.
- Cancellation, structured payloads, discovery changes and model/transport failure checks; explicit text-only and protocol limits.
- Built with Llama. Model weights are separately licensed and downloaded only by `setup`.

## 0.3.0 — 2026-11-14

- `Client.check_text(text, base=None, links=False)`: parses and checks llms.txt text (`POST /api/v0/check`).
- `CheckResult.parsed` (`Parsed`, `ParsedSection`, `ParsedLink`): title, summary, details and sections with their
  links, from both `check()` and `check_text()`.
- `CheckResult.site`/`url` are Optional (None for text without `base`); `llms_full` is None when not checked.

## 0.2.0 — 2026-11-14

- Stdio MCP server that forwards to https://llms.ink/mcp with your optional `LLMS_INK_KEY`, for Hermes Agent and
  other clients that launch local commands: `uvx --from llms-ink llms-ink-mcp` or `python -m llms_ink mcp`.

## 0.1.0 — 2026-11-14

- `Client.llms(url, mode, fresh)` and `Client.check(url)` for the llms.ink JSON API, standard library only.
- Optional API key from `key=` or `LLMS_INK_KEY`, sent as `Authorization: Bearer`.
- Typed errors from problem details: `InvalidKey`, `RateLimited`, `QuotaExceeded` (with `retry_after`), `LlmsInkError`.
- `llms_ink.langchain.LlmsInkLoader` (`[langchain]`) and `llms_ink.llama_index.LlmsInkReader` (`[llama-index]`).
- `python -m llms_ink <url> [--full] [--fresh] [--json]`.
