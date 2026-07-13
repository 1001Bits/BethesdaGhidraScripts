#!/usr/bin/env python3
"""Unit tests for review_triage_plan (unlock-surface triage of the review queue).

Run: python -m pytest test_review_triage_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import review_triage_plan as tp  # noqa: E402


# dependency graph: A and B dereference KEY; C dereferences A. KEY is the keystone.
STATE = {
    'KEY': {'refs': []},
    'A': {'refs': ['KEY']},
    'B': {'refs': ['KEY']},
    'C': {'refs': ['A']},
    'LEAF': {'refs': ['Nothing']},
}
UNKNOWNS = {'KEY': 1, 'A': 5, 'B': 3, 'C': 2, 'LEAF': 4}


def test_build_dependents_inverts_refs():
    dep = tp.build_dependents(STATE)
    assert dep['KEY'] == {'A', 'B'}
    assert dep['A'] == {'C'}


def test_unlock_closure_is_transitive():
    dep = tp.build_dependents(STATE)
    # KEY's dependents: A, B (direct), C (via A) + KEY itself
    assert tp.unlock_closure('KEY', dep) == {'KEY', 'A', 'B', 'C'}
    # LEAF: nothing depends on it
    assert tp.unlock_closure('LEAF', dep) == {'LEAF'}


def test_unlock_score_weights_by_unknowns():
    dep = tp.build_dependents(STATE)
    w, n = tp.unlock_score('KEY', dep, UNKNOWNS)
    assert n == 4                          # KEY,A,B,C
    assert w == 1 + 5 + 3 + 2              # their unknown counts
    w2, n2 = tp.unlock_score('LEAF', dep, UNKNOWNS)
    assert n2 == 1 and w2 == 4             # only itself


def test_triage_orders_keystone_first():
    fields = [{'class': 'LEAF', 'offset': 0x10, 'is_pointer': True, 'votes': 9},
              {'class': 'KEY', 'offset': 0x20, 'is_pointer': False, 'votes': 1}]
    ranked = tp.triage(fields, STATE, UNKNOWNS)
    assert ranked[0]['class'] == 'KEY'     # higher unlock beats higher votes
    assert ranked[0]['unlock_score'] == 11 and ranked[0]['dependents'] == 4


def test_pointer_breaks_tie_within_same_class():
    fields = [{'class': 'A', 'offset': 0x8, 'is_pointer': False, 'votes': 2},
              {'class': 'A', 'offset': 0x10, 'is_pointer': True, 'votes': 2}]
    ranked = tp.triage(fields, STATE, UNKNOWNS)
    assert ranked[0]['offset'] == 0x10     # pointer (anchor) first
    assert ranked[0]['unlock_score'] == ranked[1]['unlock_score']


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
