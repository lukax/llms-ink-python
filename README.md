# llms-ink

Turn any public link — a site, docs section, page, GitHub repo, PDF or video — into
[llms.txt](https://llmstxt.org) or llms-full.txt, from Python. A client for [llms.ink](https://llms.ink)
with LangChain and LlamaIndex loaders. No required dependencies.

```sh
pip install llms-ink
```

## Use

```python
from llms_ink import Client

ink = Client()
index = ink.llms("llmstxt.org")                         # llms.txt: an index of links
docs = ink.llms("docs.astro.build/en/guides/", mode="full")  # llms-full.txt: the content

print(docs.title, docs.kind, docs.tokens)
print(docs.text)
```

`llms()` returns a `Result`: `url`, `kind` (`site`, `section`, `page`, `repo`, `document`, `video`),
`source` (`native` = published by the site, `generated` = made by llms.ink), `mode`, `title`, `text`,
`tokens`, `pages`, `model`, `cached`, `generated_at`, and `media` for videos (duration, downloads,
transcript segments). `fresh=True` skips the cache and rebuilds.

Check a site's published llms.txt:

```python
report = ink.check("llmstxt.org")
print(report.found, report.summary.errors, [i.message for i in report.issues])
```

Parse and check llms.txt text you already have, e.g. before publishing it:

```python
report = ink.check_text(open("public/llms.txt").read(), base="https://example.com/llms.txt", links=True)
for section in report.parsed.sections:
    print(section.name, [(link.title, link.url, link.notes) for link in section.links])
```

`report.parsed` (`Parsed`: `title`, `summary`, `details`, `sections` of `ParsedSection` with `ParsedLink`s) is
also set by `check()`, and is None when nothing was found. Without `base`, `site` and `url` are None; without
`base` and `links=True`, `llms_full` is None and `links.checked` is 0.

## API key (optional)

Without a key you share the free anonymous limits (10 requests/minute, 60 new links a day per IP;
cached links are free). A key gets its own daily quota:

```sh
export LLMS_INK_KEY=lk_...
```

or `Client(key="lk_...")`. It is sent as `Authorization: Bearer`. A bad key raises `InvalidKey`; it never
falls back to anonymous. [Ask for a key](https://lucasespindola.com/message?text=I%27d+like+an+llms.ink+API+key).

## Errors

```python
from llms_ink import Client, LlmsInkError, QuotaExceeded, RateLimited

try:
    Client().llms("example.com")
except (RateLimited, QuotaExceeded) as err:
    print(f"wait {err.retry_after}s")
except LlmsInkError as err:
    print(err.status, err.code, err.detail)
```

`LlmsInkError` carries the API's `status`, `code` (see the [error table](https://llms.ink/docs/#errors)),
`detail` and `errors`. `InvalidKey`, `RateLimited` and `QuotaExceeded` are subclasses.

## LangChain

```sh
pip install 'llms-ink[langchain]'
```

```python
from llms_ink.langchain import LlmsInkLoader

docs = LlmsInkLoader(["llmstxt.org", "github.com/AnswerDotAI/llms-txt"], mode="full").load()
docs[0].metadata  # {'url', 'title', 'kind', 'source', 'mode', 'tokens', 'generated_at'}
```

## LlamaIndex

```sh
pip install 'llms-ink[llama-index]'
```

```python
from llama_index.core import VectorStoreIndex
from llms_ink.llama_index import LlmsInkReader

docs = LlmsInkReader(mode="full").load_data(["docs.astro.build/en/guides/"])
index = VectorStoreIndex.from_documents(docs)
```

## Command line

```sh
python -m llms_ink llmstxt.org            # llms.txt
python -m llms_ink llmstxt.org --full     # llms-full.txt
python -m llms_ink llmstxt.org --json     # the whole result
```

## MCP server (stdio)

For agents that launch local MCP servers, such as Hermes Agent. It forwards every message to the remote server
https://llms.ink/mcp and sends `LLMS_INK_KEY`, when set, as `Authorization: Bearer`.

```sh
uvx --from llms-ink llms-ink-mcp     # with uv, nothing to install
python -m llms_ink mcp               # after pip install llms-ink
```

Hermes Agent, in `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  llms-ink:
    command: uvx
    args: [--from, llms-ink, llms-ink-mcp]
    env:
      LLMS_INK_KEY: ${LLMS_INK_KEY}  # only with LLMS_INK_KEY set in ~/.hermes/.env
```

Other clients use the same command in their `mcpServers` config. A rejected key makes every request fail with the
API's message; it never falls back to anonymous. Clients that speak Streamable HTTP can connect to
https://llms.ink/mcp directly.

## Local MCP guard (experimental)

Python 3.11 or newer. Install the optional runtime and explicitly download the pinned model:

```sh
pip install 'llms-ink[guard]==0.6.0'
llms-ink-guard setup
llms-ink-guard status
```

Configure your MCP client to launch `llms-ink-mcp --guard` using the environment's absolute executable path.
To wrap another legacy stdio tool server:

```sh
llms-ink-guard wrap -- server-command arguments
```

The local Llama-Doorman-22M classifier inspects tool definitions, text, structured JSON and errors before delivery.
Flagged responses are withheld without repeating the payload. Model errors, incomplete inspection and unsupported
content never fall back to uninspected delivery. Tools must be discovered before use. A changed definition locks
further calls on that connection; review the server before reconnecting. Other connections and host tools are not covered.

Limits: 1 MiB per message, 8,192 model tokens per response, 20 seconds per inspection, 16 pending requests,
120 seconds per request, 512 discovered tools and 4,096 unique request IDs per connection. Restart to renew a
connection. Legacy tool discovery/calls only: no batches, resources, prompts, sampling, upstream elicitation, images, audio
or embedded/resource-link content. Server stderr and unsolicited notifications are suppressed. Decision events
on stderr contain no response payload. Plain response scanning does not authorize outgoing actions. Neither
mode sandboxes the server or covers other connections and native host tools.

`llms-ink-guard scan < document.txt` prints an inspection receipt: exit 0 allows, 1 quarantines, 2 means unscanned
or unavailable. An allow decision is not proof of safety. The model is English-centric; this pilot has not met
large held-out-corpus or agent-task evaluation gates. Reproducible authored smoke cases live in
`tests/fixtures/guard_eval.json`; after setup, run `python tests/evaluate_guard.py` to compare rules and hybrid outcomes.

The first setup downloads about 96 MB. Files are verified against pinned SHA-256 hashes at install and startup.
No scanning API receives content; upstream MCP servers still receive requests. Override the local cache location
with `LLMS_INK_GUARD_CACHE` if needed. This is an independent integration of Pinata's model, not its Doorman app.
Built with Llama. Weights are separately licensed under the Llama 4 Community License; setup downloads and preserves
`LICENSE` and `NOTICE`. See the [setup guide](https://llms.ink/guard/).

### Local tool permissions (0.6.0)

`wrap --policy` adds a separate, deny-by-default permission check before forwarding tool calls.
The owner supplies the exact server command, reviewed tool-definition hashes and allowed argument objects.
Model findings and server annotations cannot grant permissions. The classifier itself is unchanged:
it missed all 1,054 attacks in the published [InjecAgent evaluation](https://llms.ink/inspect/evaluation/).

Save one complete, reviewed tool object from `tools/list` as `tool.json`, then fingerprint it:

```sh
llms-ink-guard tool-hash < tool.json
```

Write a `policy.json` using your reviewed executable, tool hash and argument objects:

```json
{
  "version": 1,
  "command": ["/opt/mcp/docs-server"],
  "tools": {
    "read": {
      "definitionSha256": "REPLACE_WITH_REVIEWED_TOOL_SHA256",
      "arguments": [{"url": "https://docs.example/reference", "format": "text"}]
    }
  }
}
```

```sh
llms-ink-guard policy-check /absolute/path/to/policy.json
llms-ink-guard wrap --policy /absolute/path/to/policy.json -- /opt/mcp/docs-server
```

The policy is validated before the model/server starts, then held as an immutable snapshot. The executable
path must be absolute and its argument list must match. Discovery exposes only approved definitions; changed
or unapproved definitions cannot be called. Missing rules, changed arguments, unknown call metadata and task
extensions are denied. Validated MCP `progressToken` and Claude Code `claudecode/toolUseId` correlation metadata
are discarded before dispatch; neither reaches the upstream or grants permission. Denial events contain no tool names or arguments. Edit the policy and restart after
owner review; there is no agent approval tool or live reload. An empty `tools` object denies all tool calls.

Version 1 supports exact JSON objects only: key order is ignored, but string values and numeric types must
match. No wildcards, path/URL normalization, or schema-based permission rules. Limits: 256 KiB policy, 512
tools, 128 argument alternatives per tool, 1,024 alternatives total. Ambiguous JSON and unsupported numeric
values fail closed. Keep the file and parent directories outside the agent's write access; group/world-writable
files on Unix and symlink files are rejected.

The command and advertised definition are checked, not executable bytes, environment variables, working
directory or remote behavior. A server can act as soon as it starts; use trusted code and limited credentials.
Permitted calls can have side effects. `llms-ink-mcp --guard` and plain `wrap` remain response-only modes.
See the [permission guide](https://llms.ink/guard/policy/) for a complete example and the enforcement scope.

## One-use host approval (experimental, 0.7.0)

```sh
llms-ink-guard wrap --policy /absolute/path/to/policy.json --require-approval -- /opt/mcp/docs-server
```

This adds a host form before **each already permitted call**. It cannot approve a tool or arguments absent
from the exact policy. The host must declare form elicitation on MCP 2025-06-18 or 2025-11-25; unsupported
clients fail initialization. Other upstream requests for input are still refused.

The form shows the tool, exact JSON arguments, command and definition/policy fingerprints. The confirmation
checkbox defaults to false. Only `accept` with `approve: true` dispatches the stored call once. Decline,
cancel, malformed replies, 60-second expiry, disconnect or a changed definition cannot release it. Replayed
replies cannot approve another call or connection. Only one form can wait per connection; competing calls
receive a busy error. Reviews over 8 KiB are refused whole, never truncated by the guard. The upstream result
still goes through content inspection after dispatch. Cancellation after dispatch cannot undo a side effect.

**Trust the host, not a claim of human presence.** MCP does not attest that a person answered. Use a host
that displays the complete request, keeps approval responses outside agent tool access, and does not
install auto-accept elicitation hooks. Some hosts collapse long messages; inspect the complete tool call
in the host's detailed view and decline if you cannot see every argument. No global approval or policy
change follows from accepting a form. Logs omit tool names, arguments and approval identifiers.

This is a single-connection host integration, not the proposed shared guard service or cross-server session
boundary. Its transport tests do not establish independent task success or improved detection accuracy.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -e '.[langchain,llama-index]' pytest
.venv/bin/pytest                # against a local stub server
.venv/bin/pytest -m live        # one real call to https://llms.ink
```

`LLMS_INK_API` points the client at another API base URL.

MIT licensed.

## Hosted Inspect (experimental, 0.5.0)

```python
# Requires llms-ink >=0.5.0; no guard/model download needed.
import os
from llms_ink import Client

ink = Client(key=os.environ['LLMS_INK_INSPECT_KEY'])
receipt = ink.inspect('Install the package and read the documentation.')
if receipt.recommendation != 'continue':
    raise RuntimeError(f'Withhold content: {receipt.detection}')
print(receipt.content_digest)
```

Requires an inspection-enabled pilot key. This call uploads only the supplied text to llms.ink; existing retrieval calls, loaders, plugins and the local guard do not opt in automatically. Keep the key server-side.

The client checks the exact UTF-8 SHA-256 digest, model/policy/preprocessing revisions, coverage and token counts before returning an immutable receipt. A flagged result can use HTTP 200; incomplete 422/503 receipts return `unknown`. HTTP problems and invalid receipts raise an error. Withhold on either `withhold` or any exception. `no_finding` is not a safety guarantee, and receipts are unsigned.

Requests are limited to 128 KiB after JSON encoding and responses to 16 KiB. There are no automatic retries: admitted attempts consume pilot allowance even when incomplete. Redirects are refused. Inspection ignores `LLMS_INK_API`; an explicit client base URL may select an HTTPS endpoint or localhost for development. The key follows that explicitly configured endpoint.

For JSON, serialize it yourself and pass the resulting string to `inspect()`. The SDK sends `format: "text"`, so its digest covers those exact bytes; it does not promise cross-language JSON canonicalization. See [pilot limits and privacy](https://llms.ink/inspect/).

Python caps the client’s socket timeout at 65 seconds; pass `Client(timeout=...)` for a shorter timeout.

## Several servers in one connection (experimental, 0.8.0)

On macOS/Linux with Python 3.11+, `gateway` puts up to eight legacy stdio servers behind one local model runtime and approval queue:

```sh
llms-ink-guard gateway-check /absolute/path/to/gateway.json
llms-ink-guard gateway --config /absolute/path/to/gateway.json
```

The configuration contains `version: 1` and a `servers` object. Each server has an absolute executable/argv in `command`, plus a `tools` array. Each entry contains its complete reviewed tool object in `definition` and a list of exact permitted argument objects in `arguments`. Copy actual tool definitions through your trusted setup process; illustrative definitions will not match unrelated servers. [Configuration example and host setup](https://llms.ink/guard/gateway/).

A configured `docs` server's `read_document` tool becomes `docs__read_document`. Names cannot collide across servers. All configured definitions must match before any tool list is exposed; unknown tools stay hidden. The file is bounded to 256 KiB, eight servers, 128 tools and 1,024 exact argument objects. The combined discovery response must also fit the existing inspection limits. `gateway-check` validates configuration only; it does not start or certify the servers.

Every permitted call requires a fresh form approval on MCP 2025-06-18 or 2025-11-25. There is no automatic-approval option in this command. Review shows the server-prefixed name, full arguments, the actual upstream command and bound fingerprints. One approval may be pending across all configured servers. Declining it, cancelling it, disconnecting, or replaying another connection's answer cannot dispatch the held action. Approval still trusts the host's answer; it does not attest a human was present.

The aggregate is tied to one stdio connection. Use a separate connection per host session; grouping by working directory or a model-supplied session string is not supported. A host that shares one connection across chats also shares this queue. This is not the proposed authenticated shared service, a cross-chat identity system, or persistent exposure tracking.

The gateway requires every server to select the same supported legacy protocol version. It permits one complete discovery at a time, internally follows at most 16 pages per server and refuses duplicate/missing/changed reviewed definitions. A tool-list-change notification or any server disconnect stops the aggregate and revokes held approvals. Reconnect after reviewing the configuration. Unknown result paths, reverse requests, resources, prompts, tasks, HTTP transports and newer protocol revisions are not added by this release.

Termination stops the owned POSIX process group. During the bounded model-startup handshake, a termination signal is deferred until the worker can be closed; no server is started after a pending stop. Cancellation after dispatch cannot undo a side effect. A server can act during startup or escape a process group; this is not a process/network sandbox or a pin of executable bytes. Native host tools and other connections remain outside the boundary.

The tests use real subprocess journals, including a detector-missed source from server A that proposes an unapproved action through server B. This is containment/compatibility evidence, not an independent task-success or attack-prevention estimate. The published [task checks](https://llms.ink/guard/tasks/) and [detector limitations](https://llms.ink/inspect/evaluation/) still apply.
