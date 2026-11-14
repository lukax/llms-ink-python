"""python -m llms_ink <url> [--full] [--fresh] [--json]: prints llms.txt (or llms-full.txt) for a link.

python -m llms_ink mcp: runs the stdio MCP server (see llms_ink.mcp)."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .client import Client
from .errors import LlmsInkError, QuotaExceeded, RateLimited


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["mcp"]:
        from .mcp import main as mcp

        return mcp(argv[1:])
    parser = argparse.ArgumentParser(
        prog="python -m llms_ink",
        description="Print llms.txt for any link: a site, docs section, page, GitHub repo, PDF or video.",
        epilog="`python -m llms_ink mcp` runs a stdio MCP server instead. Uses LLMS_INK_KEY as the API key when set (optional).",
    )
    parser.add_argument("url", help="any public link, e.g. llmstxt.org")
    parser.add_argument("--full", action="store_true", help="llms-full.txt (the content) instead of the index")
    parser.add_argument("--fresh", action="store_true", help="skip the cache and rebuild")
    parser.add_argument("--json", action="store_true", help="the whole API result as JSON")
    parser.add_argument("--version", action="version", version=f"llms-ink {__version__}")
    args = parser.parse_args(argv)

    try:
        result = Client().llms(args.url, mode="full" if args.full else "llms", fresh=args.fresh)
    except LlmsInkError as err:
        message = err.detail
        if isinstance(err, (RateLimited, QuotaExceeded)) and err.retry_after is not None:
            message += f" Try again in {err.retry_after}s."
        print(f"llms-ink: {message}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.raw, indent=2, ensure_ascii=False))
    else:
        sys.stdout.write(result.text if result.text.endswith("\n") else result.text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
