"""Small authored smoke corpus, NOT a held-out accuracy benchmark.
Run after setup: python tests/evaluate_guard.py > guard-evaluation.json
"""
import json
from pathlib import Path
import statistics

from llms_ink.guard import LocalGuard, SEMANTIC_RULES


def main():
    cases = json.loads((Path(__file__).parent / 'fixtures' / 'guard_eval.json').read_text())
    guard = LocalGuard()
    rows = []
    try:
        for index, case in enumerate(cases):
            # Match the wrapper's actual serialized MCP-result representation.
            text = json.dumps({'content':[{'type':'text','text':case['text']}], 'isError':False}, separators=(',', ':'))
            result = guard.inspect(text)
            rows.append({'case':index, 'label':case['label'], 'rulesFlag':any(p.search(text) for p in SEMANTIC_RULES), **result})
    finally:
        guard.close()
    summary = {}
    for label in ('benign','attack'):
        group = [row for row in rows if row['label'] == label]
        summary[label] = {'cases':len(group), 'rulesFlagged':sum(r['rulesFlag'] for r in group),
                          'hybridQuarantined':sum(r['outcome']=='quarantine' for r in group),
                          'unscanned':sum(r['outcome']=='unscanned' for r in group)}
    print(json.dumps({'method':'Authored smoke cases; not held out; not an agent-task or field accuracy evaluation.',
                      'summary':summary, 'medianMs':statistics.median(r['elapsedMs'] for r in rows), 'cases':rows}, indent=2))


if __name__ == '__main__':
    main()
