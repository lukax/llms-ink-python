"""LlamaIndex reader: ``pip install 'llms-ink[llama-index]'``.

    >>> from llms_ink.llama_index import LlmsInkReader
    >>> docs = LlmsInkReader(mode="full").load_data(["docs.astro.build/en/guides/"])
"""

from __future__ import annotations

from typing import Iterator, List, Optional, Union

try:
    from llama_index.core import Document
    from llama_index.core.readers.base import BaseReader
except ImportError as err:  # pragma: no cover
    raise ImportError("LlmsInkReader needs llama-index-core: pip install 'llms-ink[llama-index]'") from err

from .client import MODES, Client, _metadata


class LlmsInkReader(BaseReader):
    """One Document per link: llms.txt (``mode='llms'``) or llms-full.txt (``mode='full'``) as text, with
    metadata ``url``, ``title``, ``kind``, ``source``, ``mode``, ``tokens`` and ``generated_at``.
    ``key`` defaults to ``LLMS_INK_KEY``; pass ``client`` to reuse one."""

    def __init__(
        self,
        mode: str = "llms",
        *,
        fresh: bool = False,
        key: Optional[str] = None,
        client: Optional[Client] = None,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be 'llms' or 'full', not {mode!r}")
        self.mode = mode
        self.fresh = fresh
        self.client = client or Client(key)

    def lazy_load_data(self, urls: Union[str, List[str]], mode: Optional[str] = None) -> Iterator[Document]:
        """Documents for ``urls``; ``mode`` overrides the reader's for this call."""
        for url in [urls] if isinstance(urls, str) else urls:
            result = self.client.llms(url, mode=mode or self.mode, fresh=self.fresh)
            yield Document(text=result.text, metadata=_metadata(result))

    def load_data(self, urls: Union[str, List[str]], mode: Optional[str] = None) -> List[Document]:
        return list(self.lazy_load_data(urls, mode))
