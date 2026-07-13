"""Pure (Ghidra-free) logic for Ghidra -> CommonLib write-back detection.

The pipeline imports CommonLib INTO Ghidra. This closes the other half: detect
what the Ghidra program knows that CommonLib does not, so RE done in Ghidra (or
carried by a runtime's PDB) can flow back to CommonLib as the canonical source.

For each CommonLib symbol we compare its name/signature against the live Ghidra
function at the symbol's address and classify the delta. Kept Ghidra-free so the
classification is unit-testable; the driver supplies the live values.
"""

import re

# Names Ghidra uses for an un-RE'd function -- carry no information.
_GENERIC_PREFIXES = ('FUN_', 'sub_', 'thunk_FUN_', 'j_FUN_')
# Address suffix(es) the classes phase appends to disambiguate overloaded leaves
# in a namespace, e.g. Dispel_14053E380 or GetMagnitude_14053E120_140540EA0.
# Stripped before comparing names so it is not mistaken for a real difference.
_DUP_SUFFIX = re.compile(r'(?:_[0-9A-Fa-f]{6,})+$')


def is_generic(name):
    """True if the name is a Ghidra placeholder (FUN_/sub_/...) or empty."""
    if not name:
        return True
    return name.startswith(_GENERIC_PREFIXES)


def _leaf(name):
    if not name:
        return name
    return _DUP_SUFFIX.sub('', name.split('::')[-1])


def classify_delta(commonlib_name, ghidra_name, ghidra_is_generic,
                   commonlib_sig, ghidra_sig, ghidra_sig_source):
    """Classify one symbol's Ghidra-vs-CommonLib delta. Returns a kind string:

      MISSING_IN_GHIDRA  CommonLib named it but Ghidra is still generic
                         (our apply missed it -- a QA gap, not a write-back)
      NAME_DELTA         both have real names and the leaf names differ
                         (Ghidra/PDB knows a different name -> write-back candidate)
      SIG_DELTA          names agree but the signatures differ AND Ghidra's came
                         from a trusted source (USER_DEFINED/IMPORTED) -> candidate
      MATCH              nothing to report

    Only USER_DEFINED/IMPORTED Ghidra signatures are trusted for SIG_DELTA --
    an analyzer guess is not evidence CommonLib is wrong.
    """
    if ghidra_is_generic:
        return 'MISSING_IN_GHIDRA'
    if _leaf(commonlib_name) != _leaf(ghidra_name):
        return 'NAME_DELTA'
    if (commonlib_sig and ghidra_sig and commonlib_sig != ghidra_sig
            and ghidra_sig_source in ('USER_DEFINED', 'IMPORTED')):
        return 'SIG_DELTA'
    return 'MATCH'


def summarize(deltas):
    """Count deltas by kind. deltas is an iterable of kind strings."""
    out = {}
    for k in deltas:
        out[k] = out.get(k, 0) + 1
    return out
