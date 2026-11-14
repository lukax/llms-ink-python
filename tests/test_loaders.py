import pytest

from llms_ink import Client, QuotaExceeded

from .conftest import FULL, GOOD_KEY, LLMS

METADATA = {
    "url": "https://llmstxt.org/",
    "title": "llms.txt",
    "kind": "site",
    "source": "native",
    "mode": "full",
    "tokens": 42,
    "generated_at": "2026-11-14T00:00:00.000Z",
}


def test_langchain_loader(stub):
    from langchain_core.document_loaders import BaseLoader
    from langchain_core.documents import Document

    from llms_ink.langchain import LlmsInkLoader

    loader = LlmsInkLoader(["llmstxt.org", "youtu.be/x"], mode="full")
    assert isinstance(loader, BaseLoader)
    docs = loader.load()
    assert [type(d) for d in docs] == [Document, Document]
    assert docs[0].page_content == FULL
    assert docs[0].metadata == METADATA
    assert docs[1].metadata["kind"] == "video"
    assert [r["query"]["url"] for r in stub.requests] == ["llmstxt.org", "youtu.be/x"]


def test_langchain_loader_takes_one_url_a_key_and_a_client(stub):
    from llms_ink.langchain import LlmsInkLoader

    docs = list(LlmsInkLoader("llmstxt.org", key=GOOD_KEY).lazy_load())
    assert docs[0].page_content == LLMS
    assert docs[0].metadata["mode"] == "llms"
    assert stub.last["headers"]["Authorization"] == f"Bearer {GOOD_KEY}"
    client = Client()
    assert LlmsInkLoader("x", client=client).client is client
    with pytest.raises(ValueError):
        LlmsInkLoader("x", mode="index")


def test_langchain_loader_raises_api_errors(stub):
    from llms_ink.langchain import LlmsInkLoader

    with pytest.raises(QuotaExceeded):
        LlmsInkLoader(["quota.test"]).load()


def test_llama_index_reader(stub):
    from llama_index.core import Document
    from llama_index.core.readers.base import BaseReader

    from llms_ink.llama_index import LlmsInkReader

    reader = LlmsInkReader(mode="full")
    assert isinstance(reader, BaseReader)
    docs = reader.load_data(["llmstxt.org"])
    assert [type(d) for d in docs] == [Document]
    assert docs[0].text == FULL
    assert docs[0].metadata == METADATA
    assert [d.text for d in reader.load_data("llmstxt.org", mode="llms")] == [LLMS]
    assert stub.last["query"]["mode"] == "llms"


def test_llama_index_reader_key_and_fresh(stub):
    from llms_ink.llama_index import LlmsInkReader

    list(LlmsInkReader(fresh=True, key=GOOD_KEY).lazy_load_data(["llmstxt.org"]))
    assert stub.last["query"] == {"url": "llmstxt.org", "mode": "llms", "fresh": "1"}
    assert stub.last["headers"]["Authorization"] == f"Bearer {GOOD_KEY}"
