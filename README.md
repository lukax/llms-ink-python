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

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -e '.[langchain,llama-index]' pytest
.venv/bin/pytest                # against a local stub server
.venv/bin/pytest -m live        # one real call to https://llms.ink
```

`LLMS_INK_API` points the client at another API base URL.

MIT licensed.
