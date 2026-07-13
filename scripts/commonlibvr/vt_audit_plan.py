"""Pure (Ghidra-free) sanity check for ACCEPTED Version Tracking matches.

`version_track.py` AUDIT only catches accepted matches whose DESTINATION ADDRESS
disagrees with CommonLib's ground truth -- and only for symbols CommonLib knows.
It says nothing about whether two matched functions actually LOOK like the same
function. Ghidra's auto-correlators (and bulk "accept all") happily accept matches
whose signatures don't line up, which then poison cross-version name/sig propagation.

This module scores a (src, dst) accepted match for STRUCTURAL consistency from two
cheap profiles the Ghidra glue builds (signature shape + a decompile of each). It is
deliberately LENIENT -- cross-version functions legitimately differ a little (VR
sometimes takes one extra arg; a pointer param may be a VR-only type) -- so it flags
only CLEAR mismatches, and it only REPORTS (never auto-rejects).

The strongest signal is the decompiler's own: an undeclared incoming-register
reference (`in_RCX`/`in_ECX`/...) means the applied signature failed to account for a
parameter the body uses -- i.e. "the relevant parameters are NOT in the decompile."
If the dst leaks materially more of those than the src, the prototype doesn't fit the
dst function and the match is suspect. We reuse decompile_score._inparam_count for it.

A profile dict (per side):
  {'name', 'params': int, 'ret_cat': str, 'param_cats': [str], 'size': int,
   'inparams': int, 'has_sig': bool}
where *_cat is one of: 'void' 'int' 'ptr' 'float' 'struct', and `has_sig` is True only
when that side has a real APPLIED prototype (signature source != DEFAULT). Prototype
comparison (param count / return / param class) is only meaningful when BOTH sides have
one -- otherwise the mismatch is just "this side's signature hasn't been recovered yet"
(e.g. SE has `Ret f(This*, a, b)` but the AE twin is still the bare `undefined f(void)`),
which is NOT a bad match. Those un-applied cases dominated an early run (52k "param 3 vs
0" on correctly-named twins), so the prototype checks are gated on both-applied; the
size and decompile-leak checks (which compare the actual code, not the prototype) always
run.
"""
import os

# tolerances -- tuned to flag only clear mismatches, not cross-version drift.
PARAM_COUNT_TOL = int(os.environ.get('VT_AUDIT_PARAM_TOL', '1'))   # VR may take +1 arg
SIZE_RATIO = float(os.environ.get('VT_AUDIT_SIZE_RATIO', '4.0'))   # body-size blowup
INPARAM_TOL = int(os.environ.get('VT_AUDIT_INPARAM_TOL', '1'))     # leaked-reg slack

# Return/param category compatibility. Integers and pointers share the 8-byte
# register class and are routinely interchangeable across versions / weak typing,
# so treat them as compatible; float and struct-by-value are distinct ABI classes;
# void must match void.
_COMPAT = {
    frozenset(('int', 'ptr')): True,
    frozenset(('int',)): True, frozenset(('ptr',)): True,
    frozenset(('float',)): True, frozenset(('void',)): True,
    frozenset(('struct',)): True,
}


def _compatible(a, b):
    if a == b:
        return True
    return _COMPAT.get(frozenset((a, b)), False)


def audit_match(src, dst):
    """Return (verdict, reasons). 'SUSPECT' only on a STRONG signal that compares the
    actual CODE -- a >SIZE_RATIO body-size blowup, or the dst decompile leaking incoming-
    register params its prototype never declared (prototype does not fit the function).
    Prototype param/return DIFFERENCES are deliberately NOT a trigger: cross-version
    analysis recovers slightly different prototypes (return undefined-vs-void, a param
    count off by one) on plenty of CORRECT matches, so they're pure noise alone -- they
    are appended only as supporting context WHEN a strong signal already fired."""
    strong = []

    lo, hi = sorted((max(src['size'], 0), max(dst['size'], 0)))
    if lo > 0 and hi / float(lo) > SIZE_RATIO:
        strong.append('size %d vs %d (%.1fx)' % (src['size'], dst['size'], hi / float(lo)))

    # the real check: dst body uses params the applied signature didn't declare
    if dst['inparams'] - src['inparams'] > INPARAM_TOL:
        strong.append('dst leaks %d incoming-reg params (src %d) -- prototype does not fit dst'
                      % (dst['inparams'], src['inparams']))

    if not strong:
        return 'OK', []

    # supporting context: prototype differences (only meaningful when both applied)
    context = []
    if src.get('has_sig', True) and dst.get('has_sig', True):
        if abs(src['params'] - dst['params']) > PARAM_COUNT_TOL:
            context.append('param-count %d vs %d' % (src['params'], dst['params']))
        if not _compatible(src['ret_cat'], dst['ret_cat']):
            context.append('return %s vs %s' % (src['ret_cat'], dst['ret_cat']))
        for i, (a, b) in enumerate(zip(src['param_cats'], dst['param_cats'])):
            if not _compatible(a, b):
                context.append('param%d %s vs %s' % (i, a, b))
    return 'SUSPECT', strong + context
