"""LangChain document loader: ``pip install 'llms-ink[langchain]'``.

    >>> from llms_ink.langchain import LlmsInkLoader
    >>> docs = LlmsInkLoader(["docs.astro.build/en/guides/"], mode="full").load()
"""

from __future__ import annotations

from typing import Iterator, Optional, Sequence, Union

try:
    from langchain_core.document_loaders import BaseLoader
    from langchain_core.documents import Document
except ImportError as err:  # pragma: no cover
    raise ImportError("LlmsInkLoader needs langchain-core: pip install 'llms-ink[langchain]'") from err

from .client import MODES, Client, _metadata


class LlmsInkLoader(BaseLoader):
    """One Document per link: llms.txt (``mode='llms'``) or llms-full.txt (``mode='full'``) as
    ``page_content``, with metadata ``url``, ``title``, ``kind``, ``source``, ``mode``, ``tokens`` and
    ``generated_at``. ``key`` defaults to ``LLMS_INK_KEY``; pass ``client`` to reuse one."""

    def __init__(
        self,
        urls: Union[str, Sequence[str]],
        mode: str = "llms",
        *,
        fresh: bool = False,
        key: Optional[str] = None,
        client: Optional[Client] = None,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be 'llms' or 'full', not {mode!r}")
        self.urls = [urls] if isinstance(urls, str) else list(urls)
        self.mode = mode
        self.fresh = fresh
        self.client = client or Client(key)

    def lazy_load(self) -> Iterator[Document]:
        for url in self.urls:
            result = self.client.llms(url, mode=self.mode, fresh=self.fresh)
            yield Document(page_content=result.text, metadata=_metadata(result))
