"""Unit tests for the pure improvement planners (ctor_plan, globals_plan,
string_anchor_match).  No Ghidra required -- run with::

    python scripts/core/test_enrichment_plans.py
    # or: pytest scripts/core/test_enrichment_plans.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ctor_plan
import globals_plan
import string_anchor_match as sam


# --------------------------------------------------------------------------
# ctor_plan
# --------------------------------------------------------------------------
def test_is_ctor():
    assert ctor_plan.is_ctor('TESObjectWEAP::TESObjectWEAP', 'TESObjectWEAP')
    assert ctor_plan.is_ctor('Crime_ctor', 'Crime')
    assert ctor_plan.is_ctor('RE::Actor::constructor', 'Actor')
    # negatives
    assert not ctor_plan.is_ctor('DoActor', 'Actor')          # 'ctor' substring only
    assert not ctor_plan.is_ctor('TESObjectWEAP::GetName', 'TESObjectWEAP')
    assert not ctor_plan.is_ctor('', 'Actor')


def test_field_label():
    assert ctor_plan.field_label('a_object') == 'object'
    assert ctor_plan.field_label('p_count') == 'count'
    assert ctor_plan.field_label('param_3') is None or \
        ctor_plan.field_label('param_3') == '3'   # param_ prefix stripped -> '3' digit
    # noise names drop
    assert ctor_plan.field_label('this') is None
    assert ctor_plan.field_label('a_') is None
    assert ctor_plan.field_label('') is None
    assert ctor_plan.field_label(None) is None
    # real name survives
    assert ctor_plan.field_label('a_interval') == 'interval'


def test_best_ctor():
    assert ctor_plan.best_ctor([('a', 0), ('b', 5), ('c', 3)]) == 'b'
    assert ctor_plan.best_ctor([('a', 2), ('b', 2)]) == 'a'        # tie -> first
    assert ctor_plan.best_ctor([('a', 0), ('b', 0)]) is None       # none assign
    assert ctor_plan.best_ctor([]) is None


# --------------------------------------------------------------------------
# globals_plan
# --------------------------------------------------------------------------
def test_aggregate_and_confidence():
    obs = [
        (0x1000, 'PlayerCharacter', 'FUN_a'),
        (0x1000, 'PlayerCharacter', 'FUN_b'),
        (0x2000, 'TESDataHandler', 'FUN_c'),         # single site -> medium
        (0x3000, 'Actor', 'FUN_d'),                  # competing
        (0x3000, 'Actor', 'FUN_e'),
        (0x3000, 'TESObjectREFR', 'FUN_f'),          # minority
    ]
    agg = globals_plan.aggregate_global_types(obs)
    assert agg[0x1000]['type'] == 'PlayerCharacter'
    assert globals_plan.global_confidence(agg[0x1000]) == 'high'   # 2 sites, 1 class
    assert globals_plan.global_confidence(agg[0x2000]) == 'medium'  # 1 site
    # 0x3000: Actor 2 of 3 -> majority but competing -> medium
    assert agg[0x3000]['type'] == 'Actor'
    assert globals_plan.global_confidence(agg[0x3000]) == 'medium'


def test_globals_low_confidence_even_split():
    obs = [(0x9000, 'A', 'c1'), (0x9000, 'B', 'c2')]
    agg = globals_plan.aggregate_global_types(obs)
    assert globals_plan.global_confidence(agg[0x9000]) == 'low'


def test_to_rows_orders_high_first():
    obs = [
        (0x2000, 'TESDataHandler', 'c'),                      # medium
        (0x1000, 'PlayerCharacter', 'a'), (0x1000, 'PlayerCharacter', 'b'),  # high
    ]
    rows = globals_plan.to_rows(globals_plan.aggregate_global_types(obs))
    assert rows[0][0] == 0x1000 and rows[0][2] == 'high'


# --------------------------------------------------------------------------
# string_anchor_match
# --------------------------------------------------------------------------
def test_timer_name():
    assert sam.timer_name('TthkbWorld::step') == 'hkbWorld::step'
    assert sam.timer_name('LtBSOffsetAnimationGenerator::generate') == \
        'BSOffsetAnimationGenerator::generate'
    assert sam.timer_name('hkbWorld::step') is None          # no Lt/Tt prefix
    assert sam.timer_name('Tt has a space here') is None


def test_message_name():
    assert sam.message_name(
        'BGSSaveLoadManager::CopySaveGamesFromHost failed to read header') == \
        'BGSSaveLoadManager::CopySaveGamesFromHost'
    assert sam.message_name('GFxDrawText::Display is called without') == \
        'GFxDrawText::Display'
    # hk* excluded, too-short message excluded, deep nesting excluded
    assert sam.message_name('hkThing::foo bar baz qux') is None
    assert sam.message_name('A::b two') is None              # <3 words after
    assert sam.message_name('short') is None


def test_telemetry_name():
    assert sam.telemetry_name('bnet::Telemetry::Log', {'bnet'}) == 'bnet::Telemetry::Log'
    assert sam.telemetry_name('hkCachedHashMap::Elem', {'bnet'}) is None  # ns not allowed
    assert sam.telemetry_name('bnet::X', set()) is None      # empty allowlist


def test_resolve_consensus():
    # one function, one consistent name, name unique -> applied
    by_func = {0x10: ('fA', {'Foo::bar'}), 0x20: ('fB', {'Baz::qux'})}
    plan, ambiguous = sam.resolve(by_func)
    assert (0x10, 'Foo::bar') in plan and (0x20, 'Baz::qux') in plan
    assert not ambiguous


def test_resolve_ambiguous():
    # same name from two functions -> ambiguous, not guessed
    by_func = {0x10: ('fA', {'Foo::bar'}), 0x20: ('fB', {'Foo::bar'})}
    plan, ambiguous = sam.resolve(by_func)
    assert not plan and 'Foo::bar' in ambiguous
    # one function, two names -> ambiguous
    by_func2 = {0x30: ('fC', {'A::b', 'C::d'})}
    plan2, ambiguous2 = sam.resolve(by_func2)
    assert not plan2 and ambiguous2


def _run():
    n = 0
    for name, fn in sorted(globals().items()):
        if name.startswith('test_') and callable(fn):
            fn()
            print('  ok', name)
            n += 1
    print('%d tests passed' % n)


if __name__ == '__main__':
    _run()
