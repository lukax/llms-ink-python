# Changelog

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
