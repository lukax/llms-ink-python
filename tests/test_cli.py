import json
import os
import subprocess
import sys

from llms_ink.__main__ import main

from .conftest import FULL, LLMS


def test_prints_llms_txt(stub, capsys):
    assert main(["llmstxt.org"]) == 0
    assert capsys.readouterr().out == LLMS
    assert stub.last["query"] == {"url": "llmstxt.org", "mode": "llms"}


def test_full_and_fresh(stub, capsys):
    assert main(["llmstxt.org", "--full", "--fresh"]) == 0
    assert capsys.readouterr().out == FULL
    assert stub.last["query"] == {"url": "llmstxt.org", "mode": "full", "fresh": "1"}


def test_json(stub, capsys):
    assert main(["llmstxt.org", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["generatedAt"] == "2026-11-14T00:00:00.000Z"


def test_errors_go_to_stderr_with_exit_1(stub, capsys):
    assert main(["quota.test"]) == 1
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err == "llms-ink: Daily quota of new links used up. Try again in 3600s.\n"


def test_runs_as_a_module(stub):
    env = {**os.environ, "LLMS_INK_API": stub.base_url}
    env.pop("LLMS_INK_KEY", None)
    ok = subprocess.run([sys.executable, "-m", "llms_ink", "llmstxt.org"], env=env, capture_output=True, text=True)
    assert (ok.returncode, ok.stdout) == (0, LLMS)
    bad = subprocess.run([sys.executable, "-m", "llms_ink", "login.test"], env=env, capture_output=True, text=True)
    assert (bad.returncode, bad.stderr) == (1, "llms-ink: That page needs a login.\n")
    usage = subprocess.run([sys.executable, "-m", "llms_ink"], env=env, capture_output=True, text=True)
    assert usage.returncode == 2
