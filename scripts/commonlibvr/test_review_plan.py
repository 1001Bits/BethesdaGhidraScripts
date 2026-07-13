#!/usr/bin/env python3
"""Unit tests for review_plan (LLM-review queue decision logic).

Run: python -m pytest test_review_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import review_plan as rp  # noqa: E402


def test_is_review_worthy():
    # size-only with consensus -> worth a human's naming call
    assert rp.is_review_worthy(named=False, total=4, votes=3) == (True, 'size-only-consensus')
    # already auto-applied a concrete type -> nothing to ask
    assert rp.is_review_worthy(named=True, total=9, votes=9) == (False, 'auto-applied')
    # single weak observation -> let discovery firm it up first
    assert rp.is_review_worthy(named=False, total=1, votes=1) == (False, 'too-weak')
    # threshold is inclusive
    assert rp.is_review_worthy(named=False, total=2, votes=1)[0]


def test_review_rank_orders_strongest_first():
    rows = [('a', 2, 1), ('b', 9, 4), ('c', 5, 5)]
    rows.sort(key=lambda r: rp.review_rank(r[1], r[2]), reverse=True)
    assert [r[0] for r in rows] == ['b', 'c', 'a']


def test_parse_decision():
    assert rp.parse_decision('') is None
    assert rp.parse_decision(None) is None
    assert rp.parse_decision('skip') is None
    assert rp.parse_decision('  SKIP ') is None
    assert rp.parse_decision('?') is None
    assert rp.parse_decision('TBD') is None
    assert rp.parse_decision('Actor *') == 'Actor *'
    assert rp.parse_decision('  BSTArray<RE::TESForm *>  ') == 'BSTArray<RE::TESForm *>'


if __name__ == '__main__':
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith('test_') and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print('PASS', fn.__name__)
        except Exception:
            failed += 1; print('FAIL', fn.__name__); traceback.print_exc()
    print('\n{}/{} passed'.format(len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
