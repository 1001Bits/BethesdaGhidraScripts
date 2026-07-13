#!/usr/bin/env python3
"""Unit tests for vt_audit_plan (VT accepted-match signature sanity check).

Run: python -m pytest test_vt_audit_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vt_audit_plan as ap  # noqa: E402


def _p(params=2, ret='int', cats=None, size=100, inparams=0, name='f', has_sig=True):
    return {'name': name, 'params': params, 'ret_cat': ret,
            'param_cats': cats if cats is not None else ['ptr', 'int'],
            'size': size, 'inparams': inparams, 'has_sig': has_sig}


def test_identical_is_ok():
    v, r = ap.audit_match(_p(), _p())
    assert v == 'OK' and r == []


def test_cross_version_drift_is_lenient():
    # VR takes one extra arg, an int slot is a ptr in the other runtime, slightly bigger body
    src = _p(params=2, cats=['ptr', 'int'], size=100)
    dst = _p(params=3, cats=['ptr', 'ptr', 'int'], size=130)
    v, r = ap.audit_match(src, dst)
    assert v == 'OK', r


def test_prototype_mismatch_alone_is_not_suspect():
    # cross-version recovery noise: differing prototypes but no code-level signal -> OK
    assert ap.audit_match(_p(params=2), _p(params=5))[0] == 'OK'
    assert ap.audit_match(_p(ret='float'), _p(ret='int'))[0] == 'OK'
    assert ap.audit_match(_p(cats=['ptr', 'float']), _p(cats=['ptr', 'int']))[0] == 'OK'


def test_prototype_diff_appears_as_context_when_strong_fires():
    # a strong signal (size) triggers; the prototype diff is reported as supporting context
    src = _p(params=2, ret='float', size=50)
    dst = _p(params=5, ret='int', size=500)
    v, r = ap.audit_match(src, dst)
    assert v == 'SUSPECT'
    assert any('size' in x for x in r)
    assert any('param-count' in x for x in r) and any('return' in x for x in r)


def test_int_ptr_compatible():
    v, r = ap.audit_match(_p(cats=['ptr', 'int']), _p(cats=['int', 'ptr']))
    assert v == 'OK', r


def test_size_blowup_flagged():
    v, r = ap.audit_match(_p(size=50), _p(size=500))
    assert v == 'SUSPECT' and any('size' in x for x in r)


def test_leaked_incoming_params_flagged():
    # dst body uses 3 incoming-register params the prototype never declared
    v, r = ap.audit_match(_p(inparams=0), _p(inparams=3))
    assert v == 'SUSPECT' and any('incoming-reg' in x for x in r)


def test_small_leak_tolerated():
    v, r = ap.audit_match(_p(inparams=0), _p(inparams=1))
    assert v == 'OK', r


def test_void_vs_nonvoid_alone_is_not_suspect():
    # void-vs-ptr return alone is recovery noise without a code-level signal
    v, r = ap.audit_match(_p(ret='void', params=0, cats=[]), _p(ret='ptr', params=0, cats=[]))
    assert v == 'OK', r


def test_unapplied_side_not_flagged_on_prototype():
    # correct match, but the dst twin has no recovered signature yet (default void())
    src = _p(params=3, ret='ptr', cats=['ptr', 'int', 'int'], size=120, has_sig=True)
    dst = _p(params=0, ret='void', cats=[], size=110, has_sig=False)
    v, r = ap.audit_match(src, dst)
    assert v == 'OK', r


def test_unapplied_side_still_flags_size_and_leak():
    # prototype checks suppressed, but a real code-level signal still fires
    src = _p(params=3, ret='ptr', cats=['ptr', 'int', 'int'], size=50, inparams=0, has_sig=True)
    dst = _p(params=0, ret='void', cats=[], size=600, inparams=4, has_sig=False)
    v, r = ap.audit_match(src, dst)
    assert v == 'SUSPECT' and any('size' in x for x in r) and any('incoming-reg' in x for x in r)
