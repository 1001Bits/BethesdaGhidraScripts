"""Pure (Ghidra-free) decompiler-quality scoring for signature conflict resolution.

When a CommonLib signature conflicts with an existing USER_DEFINED/IMPORTED one,
the enrich apply does NOT blindly trust the incumbent: it decompiles the function
with each signature and keeps whichever produces cleaner C. This module holds the
scoring + decision logic so it is unit-testable without a Ghidra session.

Lower score = better. The markers penalised all indicate weak/raw typing that a
correct struct/parameter signature removes:
  - ``undefined`` / ``undefinedN``      untyped returns, locals, fields
  - ``*(T *)(base + 0xNN)``             raw offset deref -> struct type missing
  - C casts ``(uint *)`` etc.           type laundering the decompiler had to insert
  - ``unaff_`` / ``in_`` / ``extraout_`` artifacts from a wrong arg/return shape
  - ``/* WARNING`` decompiler warnings   recovery failures
"""
import re

# Penalty weights: how strongly each marker signals a worse decompile.
# _W_INPARAM is the heaviest because an undeclared incoming-register reference
# (in_RCX/in_ECX/...) is the strongest sign the SIGNATURE itself is wrong -- a
# param the prototype failed to declare. Without this weight a `void f(void)` PDB
# stub scores almost identically to a correct `Ret f(This*, args)` when the body
# is large (the raw-offset noise dominates), so the real fix gets rejected by the
# margin. Weighting signature-failure high keeps it visible. (Lesson from the
# 56/60 close-call corrections; see test_decompile_score.)
_W_UNDEFINED = 3
_W_RAW_DEREF = 4
_W_CAST = 1
_W_INPARAM = 8
_W_ARTIFACT = 2
_W_WARNING = 5

_RE_UNDEFINED = re.compile(r'\bundefined\d*\b')
# *(type *)(something + 0xNN)  -- untyped base+offset memory access
_RE_RAW_DEREF = re.compile(r'\*\s*\([^()]*\*\)\s*\([^()]*\+\s*0x[0-9a-fA-F]+\)')
_RE_CAST = re.compile(
    r'\(\s*(?:u?int\d*|u?long\d*|u?char|u?short|undefined\d*|code|byte|word|dword|qword)'
    r'\s*\**\s*\)')
# Undeclared incoming-register param: a parameter the signature failed to recover.
_RE_INPARAM = re.compile(r'\bin_(?:R[A-D]X|R[89]|R[SD]I|E[A-D]X|stack)\w*')
# Other decompiler artifacts (not a clean signature signal: appear with good sigs too).
_RE_ARTIFACT = re.compile(r'\b(?:unaff_|extraout_|unique0x|register0x)\w*')
_RE_WARNING = re.compile(r'/\*\s*WARNING')


def score_decompile(c_text):
    """Penalty score for a decompiled function body (lower is better).

    Returns None when there is no text to score (decompile failed/empty), so the
    caller can fall back rather than treat 'no output' as a perfect score of 0.
    """
    if not c_text:
        return None
    return (
        _W_UNDEFINED * len(_RE_UNDEFINED.findall(c_text))
        + _W_RAW_DEREF * len(_RE_RAW_DEREF.findall(c_text))
        + _W_CAST * len(_RE_CAST.findall(c_text))
        + _W_INPARAM * len(_RE_INPARAM.findall(c_text))
        + _W_ARTIFACT * len(_RE_ARTIFACT.findall(c_text))
        + _W_WARNING * len(_RE_WARNING.findall(c_text))
    )


def _inparam_count(c_text):
    return len(_RE_INPARAM.findall(c_text)) if c_text else 0


def choose_better(existing_text, candidate_text, margin_frac=0.10, min_margin=3):
    """Pick 'existing' or 'candidate' for the function signature.

    Decision order:
      1. Undeclared incoming params (in_RCX/...) are a SIGNATURE-LEVEL defect: the
         prototype is literally missing a parameter. Whichever side declares more
         of them wins outright, independent of body size -- a large noisy body must
         not dilute "this signature dropped a param" down below the margin (the
         exact failure that wrongly kept 56/60 close calls; see test_decompile_score).
      2. Otherwise compare total penalty with a margin biased toward the incumbent:
         candidate wins only if it beats existing by max(min_margin, margin_frac *
         existing). This keeps hand-curated/PDB sigs on ties and absorbs noise.

    Returns (winner, existing_score, candidate_score); scores may be None.
    """
    se = score_decompile(existing_text)
    sc = score_decompile(candidate_text)
    if sc is None:
        return ('existing', se, sc)
    if se is None:
        return ('candidate', se, sc)
    ie, ic = _inparam_count(existing_text), _inparam_count(candidate_text)
    if ie != ic:
        return ('candidate' if ic < ie else 'existing', se, sc)
    needed = max(min_margin, int(margin_frac * se))
    winner = 'candidate' if (se - sc) >= needed else 'existing'
    return (winner, se, sc)
