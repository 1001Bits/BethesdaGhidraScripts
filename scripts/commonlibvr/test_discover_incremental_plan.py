#!/usr/bin/env python3
"""Unit tests for discover_incremental_plan (incremental discovery dirty-set logic).

Run: python -m pytest test_discover_incremental_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import discover_incremental_plan as ip  # noqa: E402


def test_base_type():
    assert ip.base_type('TESBoundObject *64') == 'TESBoundObject'
    assert ip.base_type('TESFaction*') == 'TESFaction'
    assert ip.base_type('uint32') == 'uint32'
    assert ip.base_type('') == ''
    assert ip.base_type(None) == ''


def test_cold_when_no_prior_state():
    dirty, reason = ip.compute_dirty({}, {'Crime'})
    assert dirty is None and reason == 'cold'


def test_noop_when_nothing_changed():
    prior = {'Crime': {'refs': ['TESBoundObject']}}
    dirty, reason = ip.compute_dirty(prior, set())
    assert dirty == set() and reason == 'noop'


def test_incremental_self_and_deref():
    # TESBoundObject changed -> itself re-mines (self-deepen) AND Crime, which
    # dereferences TESBoundObject, re-mines. PlayerCharacter (refs something else)
    # stays clean.
    prior = {
        'TESBoundObject': {'refs': ['TESForm']},
        'Crime': {'refs': ['TESBoundObject', 'TESFaction']},
        'PlayerCharacter': {'refs': ['TESObjectREFR']},
    }
    dirty, reason = ip.compute_dirty(prior, {'TESBoundObject'})
    assert reason == 'incremental'
    assert dirty == {'TESBoundObject', 'Crime'}
    assert 'PlayerCharacter' not in dirty


def test_changed_class_dirty_even_without_prior_record():
    # a class in `changed` is always dirty (self-deepen), even if it had no refs yet
    prior = {'A': {'refs': []}}
    dirty, _ = ip.compute_dirty(prior, {'B'})
    assert 'B' in dirty


def test_many_changed_forces_cold():
    prior = {'A': {'refs': ['X']}}
    changed = set('c%d' % i for i in range(50))
    dirty, reason = ip.compute_dirty(prior, changed, full_threshold=10)
    assert dirty is None and reason == 'many-changed'


def test_merge_state_carries_forward_unmined():
    prior = {'A': {'refs': ['X']}, 'B': {'refs': ['Y']}}
    mined = {'B': {'refs': ['Y', 'Z']}}        # B re-mined with richer refs
    out = ip.merge_state(prior, mined)
    assert out['A'] == {'refs': ['X']}          # untouched class preserved
    assert out['B'] == {'refs': ['Y', 'Z']}     # mined class overwritten


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
