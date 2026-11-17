# Changelog

## 0.16.0 — 2026-11-17

- The local guard scans what hidden text says: Unicode tag characters are read as the ASCII they encode, runs of variation selectors as the UTF-8 bytes they encode, and zero-width characters, direction controls and fillers are removed before the rules and the model run. Instructions hidden in or split by invisible characters no longer bypass them. Receipts carry `policyRevision` `"3"`; `contentDigest` still covers the original text.
- The hosted Inspect service and its `llms-ink-inspect-1` receipts are unchanged.

## 0.15.0 — 2026-11-16

- Add action-request rules to the local guard: content asking its reader to send data or money to an outside email, IBAN or website, act on "my" accounts or files, change a password or operate a device is quarantined with reason `action_request`, whatever the model score. Receipts carry `policyRevision` `"2"`.
- InjecAgent base attacks: 255 of 459 held-out cases now quarantined (previously 0 of 1,054). Enron business email: 54 of 3,866 quarantined (previously 46). Results and gaps: https://llms.ink/guard/#action-rules.
- The hosted Inspect service and its `llms-ink-inspect-1` receipts are unchanged.

## 0.14.0 — 2026-11-15

- Add opt-in owner-bound session lifetimes: `session-create --host-bound` refuses attachment until an authenticated owner watcher connects. `session-watch` ties that binding to an idle host stdin pipe; disconnect, EOF, unexpected input, expiry or owner revocation invalidates all attached authority.
- Keep the existing fixed TTL and refuse watcher replacement or automatic renewal. Ordinary unbound sessions retain their existing behavior. Session credentials cannot bind or broaden authority.
- Revoke under the dispatch lock before waiting for connection-registry cleanup. Bound total socket handlers to 40, including at most 16 watchers and eight MCP connections.
- Cover both protocols, pending approvals, independent sessions, premature attachment, watcher termination and delayed registry cleanup. This adds no resume, persistent exposure ledger, isolation or detector-policy change.

## 0.13.0 — 2026-11-15

- Add opt-in `container-run` for reviewed offline stdio servers: explicit image/profile/daemon binding, a non-root read-only container, no host mounts or network, fixed resource limits and no automatic image pulls. The image must contain a trusted `/usr/local/bin/python3` interpreter.
- Separate container ownership from the attached Docker client. A host guardian removes and verifies its container on connection loss; an in-container PID-1 deadline stops descendants if the guardian dies. Private, durable leases support explicit `container-recover` without replaying actions or touching active sessions.
- Refuse new launches past unresolved leases, changed daemons, image-declared volumes or unsupported effective settings. Ambiguous creation and daemon failures remain unconfirmed until recovery can establish cleanup. Clear Docker client configuration during creation to prevent automatic forwarding of proxy credentials.
- Include an offline text-statistics MCP example and Linux container lifecycle release checks. Existing gateway review binds the full runtime command; exact permissions and per-call approval remain separate. Default host execution, model policy and hosted inspection are unchanged.

## 0.12.0 — 2026-11-14

- Add terminal `gateway-init`: explicitly approve launching one stdio server, discover its tools without calling them, stop the discovery group, select exact argument files, then review and exclusively publish a new private configuration. Launch and permission approval use separate fresh challenges.
- Add read-only `doctor` with human/JSON output for dependencies, pinned model files, configuration, executable availability and optional running-service digest comparison. It reports unverified host coverage explicitly and never starts a model/server, downloads assets or changes sessions.
- Keep terminal waits interruptible with bounded polling and nonblocking reads, restoring descriptor flags on exit. This also applies to existing permission reviews.
- Preserve immutable running scopes, separate per-call approval and existing model/inspection policy. Guided setup is not process isolation or an automatic desktop integration.

## 0.11.1 — 2026-11-14

- Serialize local model cleanup when inspection failure and service shutdown overlap. Force-stop and reap stopped workers within the same lifecycle lock; close the pipe even if cleanup fails.
- Include the owner review workflow below. The v0.11.0 tag failed its Linux Python 3.13 shutdown check and was not published to PyPI. The failed tag remains unchanged.

## 0.11.0 — 2026-11-14

- Add `gateway-propose` for one exact argument object on an existing reviewed tool. Proposals bind the current configuration digest and cannot be loaded as active gateway configurations. No model or server starts.
- Add `gateway-review`: show complete command, definition, existing arguments and proposed addition as escaped JSON in an owner terminal. A fresh typed challenge within 120 seconds writes a new owner-only configuration atomically; Enter, EOF, timeout, interruption, stale inputs and existing destinations refuse publication.
- Keep running connections and sessions immutable. The owner must explicitly start a new gateway or service with the approved file; per-action approvals remain mandatory. No argument normalization, new server/tool grants, automatic scope expansion or same-user process isolation.

## 0.10.0 — 2026-11-14

- Add an experimental authenticated local session service over private Unix sockets. Owner credentials issue/revoke session capabilities; session credentials can only attach MCP connections. Credentials stay in exclusive owner-only files and never enter tool requests or upstream command arguments.
- Share one local model and one approval queue per explicitly issued session. Separate sessions remain isolated; exact permissions and fresh host approval remain mandatory for every call. Support legacy and modern client modes.
- Recheck session authority, approval expiry and cancellation immediately before the first nonblocking dispatch byte. Revoke all session connections on expiry, owner revocation or an observed upstream transport failure. Bound socket authentication, concurrency and stalled writes.
- Add metadata-only session status, restart invalidation, owned-process cleanup and stopped-model shutdown checks. This is not automatic desktop-chat identification, persistent exposure state, a same-user process sandbox or a hosted team service.

## 0.9.0 — 2026-11-14

- Add explicit `gateway --client-protocol 2026-07-28` for modern stdio clients, with per-request metadata, server discovery and MRTR form approvals. The configured upstream servers still use MCP 2025-11-25.
- Bind each random continuation to the stored exact call, permission ceiling, reviewed definition and original expiry. Refuse tampering, replay, cross-connection state, missing per-call capabilities and unsupported execution extensions.
- Preserve cancellation before dispatch, result inspection, shared approval limits and POSIX process cleanup. Suppress legacy reverse requests and upstream-supplied continuation fields.
- Add real subprocess, real-model CLI and official MCP Go SDK 1.8.0 interoperability checks. Host responses remain trusted; this does not prove human presence or add authenticated cross-connection sessions.

## 0.8.0 — 2026-11-14

- Experimental POSIX `gateway --config FILE`: aggregate up to eight reviewed legacy stdio servers behind one local inspection runtime, exact permissions and mandatory one-use host approval. Tool names are prefixed with the configured server identity.
- Pin complete upstream definitions, command arguments and exact calls in an owner-controlled configuration. Validate the frozen configuration again before starting servers; support bounded upstream pagination without exposing partial discovery.
- Share one pending approval across the aggregate connection. Server disconnects, declared tool-list changes, changed reviewed definitions, misrouted replies and transport failures stop the connection. Host-supplied session metadata cannot grant authority.
- Stop owned POSIX process groups on gateway shutdown. Bound stalled writes and initialization; make POSIX transport readers stoppable so a closed server does not leave an input thread blocking interpreter exit.
- Drop arbitrary top-level JSON-RPC response extensions from the existing wrapper; only the inspected result/error body is delivered.
- This is one aggregate connection, not an authenticated shared service or a claim of conversation-wide coverage. Native tools, remote HTTP servers, Windows gateway support, modern MCP and executable sandboxing remain outside scope. The detector and hosted receipt contract are unchanged.

## 0.7.0 — 2026-11-14

- Experimental `wrap --policy FILE --require-approval`: request one-use host form approval before each exact policy-permitted call. No approval can broaden the policy.
- Bind each pending action to immutable call bytes and the reviewed tool definition. Declines, invalid replies, timeout, cancellation, disconnect and definition changes do not dispatch the call; replayed replies cannot authorize another action.
- Require form elicitation on MCP 2025-06-18 or 2025-11-25. One pending form, 60-second deadline and an 8 KiB complete review bound. No automatic grant, remember-choice option or upstream elicitation passthrough.
- Discard only validated MCP progress tokens and Claude Code correlation IDs before exact-policy dispatch. Unknown call metadata and task extensions still fail.
- Host responses are trusted, not proof of human presence; host hooks can auto-answer. Native tools, server startup, other connections and modern MCP revisions remain outside this boundary. Classifier, hosted Inspect and existing default modes are unchanged.

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
