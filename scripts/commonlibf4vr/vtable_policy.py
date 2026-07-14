"""Fail-closed vtable-emission policy for the CommonLibF4VR (true-VR) parse.

The powerof3 F4 policy (``scripts/commonlibf4/parse_commonlib_types.py``)
permits vtable emission for the OG runtime only, and it is right to: CommonLibF4
models flatscreen Fallout 4, so its header vtables are OG's.  Fallout 4 VR
inserts a virtual at slot 0xD1 -- everything after shifts by +1 -- so emitting
OG-shaped vtables as VR would place method slots that are confidently wrong.
Its only route to VR was the legacy ``shift_f4_vr.json`` map, which the policy
also (rightly) rejects as unvalidated.

This parse compiles CommonLibF4VR with ``-DENABLE_FALLOUT_VR=1``, so ``RE/``
resolves to the VR-exclusive layout: the fork models VR's inserted virtuals with
``FALLOUT_REL_VR_VIRTUAL`` and pins VR member offsets with ``static_assert``s
verified against ``Fallout4VR.exe``.  The AST *is* VR, and no shift map is
involved because nothing needs shifting.

VR therefore earns a chance to be emitted -- not a free pass.  It must still
show the evidence every other runtime shows: the hand-verified anchors CSV,
which ``anchor_verifier.verify_or_exit`` checks against the generated slots and
hard-exits on any real mismatch.  If CommonLibF4VR is wrong about VR, generation
fails loudly instead of misnaming thousands of virtual methods.
"""

from __future__ import annotations

import os

# The one runtime this parse models (CommonLibF4VR is compiled VR-exclusive).
_NATIVE_RUNTIMES = ('f4_vr',)


def allow_vtable_emission(version, anchor_path, shift_map_path):
    """Return ``(allowed, reason_when_refused)``."""
    if version not in _NATIVE_RUNTIMES:
        return False, ('CommonLibF4VR is parsed VR-exclusive; {} is not modelled '
                       'here (use the CommonLibF4 path)'.format(version))
    if os.path.isfile(shift_map_path):
        # A shift map translates another runtime's slots into this one.  This
        # parse reads VR's own layout, so a map here is stale or contradictory.
        return False, ('shift map present for a natively-parsed runtime: {}'
                       .format(shift_map_path))
    if not os.path.isfile(anchor_path):
        return False, ('no hand-verified vtable anchors for {} at {}'
                       .format(version, anchor_path))
    return True, ''
