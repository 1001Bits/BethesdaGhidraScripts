"""Pure (Ghidra-free) planning logic for CommonLib-driven Version Tracking.

CommonLib's RELOCATION_ID(se, ae) / VariantID(se, ae, vr) give the EXACT address
of each symbol in every runtime, so we have ground-truth cross-version
correspondence (unlike Ghidra's heuristic correlators). This module decides, per
symbol, whether an existing VT association already encodes that correspondence
(confirmed), encodes a DIFFERENT one (conflict -- a correlator error to review),
or is absent (seed -- inject an exact accepted match).

Kept separate from the Ghidra driver so the decision logic is unit-testable.
"""


def plan_vt(expected, existing_accepted):
    """Classify each id-derived cross-version pair against existing accepted VT.

    expected         : {src_off: (dst_off, kind)}  -- kind is 'func' or 'label'
    existing_accepted: {src_off: dst_off}           -- current ACCEPTED dst per src

    Returns {'confirmed': [...], 'conflict': [...], 'seed': [...]}:
      confirmed [(src, dst, kind)]      an accepted match already maps src->dst
      conflict  [(src, dst, got, kind)] src is accepted to `got` != our dst
      seed      [(src, dst, kind)]      src has no accepted match -> inject ours
    """
    confirmed, conflict, seed = [], [], []
    for src, (dst, kind) in expected.items():
        got = existing_accepted.get(src)
        if got is None:
            seed.append((src, dst, kind))
        elif got == dst:
            confirmed.append((src, dst, kind))
        else:
            conflict.append((src, dst, got, kind))
    return {'confirmed': confirmed, 'conflict': conflict, 'seed': seed}


def build_expected(symbols, src_key, dst_key):
    """Build {src_off: (dst_off, kind)} from generated SYMBOLS for one session.

    src_key/dst_key are the per-runtime offset fields ('s'=SE, 'a'=AE, 'v'=VR).
    Only symbols that have BOTH offsets are included. A function symbol ('func')
    maps to kind 'func'; everything else (RTTI/vtable/data labels) to 'label'.
    Later duplicates for the same src_off do not overwrite the first (stable).
    """
    expected = {}
    for s in symbols:
        so, do = s.get(src_key), s.get(dst_key)
        if not so or not do:
            continue
        if so in expected:
            continue
        kind = 'func' if s.get('t') == 'func' else 'label'
        expected[so] = (do, kind)
    return expected
