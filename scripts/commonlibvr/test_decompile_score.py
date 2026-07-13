#!/usr/bin/env python3
"""Unit tests for decompile_score (signature-conflict decompile quality).

Run: python -m pytest test_decompile_score.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decompile_score as ds  # noqa: E402


# A "bad" decompile: raw offset derefs, undefined types, casts -> high penalty.
BAD = """
undefined8 FUN_140abc(longlong param_1)
{
  /* WARNING: Could not recover jumptable */
  int iVar1;
  iVar1 = *(int *)(param_1 + 0x18);
  *(undefined4 *)(param_1 + 0x20) = extraout_EDX;
  if (in_EAX != 0) {
    return *(undefined8 *)(param_1 + 0x8);
  }
  return (undefined8)(uint)iVar1;
}
"""

# A "good" decompile of the same function: typed this, named fields, no raw deref.
GOOD = """
void Actor::ClearData(Actor *this)
{
  this->processManager->reset();
  this->flags = 0;
  return;
}
"""


def test_score_bad_higher_than_good():
    sb = ds.score_decompile(BAD)
    sg = ds.score_decompile(GOOD)
    assert sb is not None and sg is not None
    assert sb > sg


def test_score_none_on_empty():
    assert ds.score_decompile('') is None
    assert ds.score_decompile(None) is None


def test_counts_each_marker():
    txt = "undefined4 x; undefined8 y;"            # 2 undefined
    assert ds.score_decompile(txt) == 2 * ds._W_UNDEFINED
    txt2 = "a = *(int *)(p + 0x10);"               # 1 raw deref + 1 cast
    assert ds.score_decompile(txt2) == ds._W_RAW_DEREF + ds._W_CAST


def test_choose_candidate_when_clearly_better():
    winner, se, sc = ds.choose_better(BAD, GOOD)
    assert winner == 'candidate'
    assert se > sc


def test_choose_existing_on_tie():
    # identical text -> no margin -> keep incumbent
    winner, se, sc = ds.choose_better(GOOD, GOOD)
    assert winner == 'existing'
    assert se == sc


def test_choose_existing_within_margin():
    # candidate only marginally better than a high-penalty incumbent -> keep existing
    existing = "undefined " * 100              # score 300
    candidate = "undefined " * 98              # score 294, diff 6 < 10% of 300 (=30)
    winner, se, sc = ds.choose_better(existing, candidate)
    assert winner == 'existing'


def test_choose_candidate_over_margin_fraction():
    existing = "undefined " * 100              # score 300
    candidate = "undefined " * 80              # score 240, diff 60 >= 30
    winner, se, sc = ds.choose_better(existing, candidate)
    assert winner == 'candidate'


def test_min_margin_boundary():
    # existing=6 (two undefined4), candidate=3 (one): diff=3, needed=max(3, 0.6)=3,
    # 3 >= 3 -> candidate just clears the floor.
    winner, se, sc = ds.choose_better("undefined4 a; undefined4 b;", "undefined4 a;")
    assert (se, sc) == (6, 3)
    assert winner == 'candidate'
    # one token better (diff=3 vs needed=3 still ok); two undefined vs two -> tie keeps existing
    winner2, _, _ = ds.choose_better("undefined4 a;", "undefined4 a;")
    assert winner2 == 'existing'


def test_inparam_dominates_identical_body():
    # Regression for the 56/60 close-call miss: existing is a void(void) stub whose
    # only real defect is an undeclared incoming param (in_RCX); candidate recovered
    # the param. The large shared body must NOT swamp that signature signal -- the
    # candidate must win even though both share the same noisy hashmap walk.
    body = "\n".join("  *(undefined8 *)(p + 0x%X) = 0;" % (i * 8) for i in range(20))
    existing = "void f(void)\n{\n  if (in_RCX != 0) {\n%s\n  }\n}" % body
    candidate = "void f(TESNPC *this)\n{\n  if (this != 0) {\n%s\n  }\n}" % body
    winner, se, sc = ds.choose_better(existing, candidate)
    assert se - sc == ds._W_INPARAM      # the only difference is the recovered param
    assert winner == 'candidate'


def test_inparam_weighted_above_generic_artifact():
    # an undeclared incoming param costs more than a benign extraout_ artifact
    assert ds.score_decompile("in_RCX") == ds._W_INPARAM
    assert ds.score_decompile("extraout_RAX") == ds._W_ARTIFACT
    assert ds._W_INPARAM > ds._W_ARTIFACT


def test_candidate_none_keeps_existing():
    winner, se, sc = ds.choose_better(GOOD, '')
    assert winner == 'existing'
    assert sc is None


def test_existing_none_takes_candidate():
    winner, se, sc = ds.choose_better('', GOOD)
    assert winner == 'candidate'
    assert se is None


if __name__ == '__main__':
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith('test_') and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print('PASS', fn.__name__)
        except Exception:
            failed += 1
            print('FAIL', fn.__name__)
            traceback.print_exc()
    print('\n{}/{} passed'.format(len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
