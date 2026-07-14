"""Fail-closed vtable-emission policy for the CommonLibVR (true-VR) parse.

The powerof3 policy (``scripts/commonlibsse/vtable_policy.py``) permits vtable
emission for SE and AE only, and it is right to.  That parse compiles *every*
runtime with the SE define set -- its own source says so: "no VR-specific
preprocessor define, so we parse with the SE define set and just attach VR
offsets at script-generation time."  Its header vtables are therefore SE's, and
Skyrim VR inserts two virtuals into ``Actor``, so emitting them as VR would put
method slots that are confidently wrong onto 8,000+ vtables.  Refusing is the
only safe answer available to that parse, and it needs a legacy ``shift_svr``
map to even attempt VR -- which the policy also (rightly) rejects as unvalidated.

This parse differs in exactly the way that matters: each runtime is compiled
with its own ``ENABLE_SKYRIM_*`` define, so ``RE/`` resolves to that runtime's
``EXCLUSIVE_*`` layout and the VR AST *is* canonical VR.  No shift map is
involved, because nothing needs shifting.

That earns VR a chance to be emitted -- not a free pass.  It must still show
the same evidence every other runtime shows: a hand-verified anchors CSV, which
``anchor_verifier.verify_or_exit`` then checks against the generated slots and
hard-exits on any real mismatch.  If CommonLibVR's headers are wrong about VR,
generation fails loudly instead of naming 8,000 vtables' worth of wrong slots.
"""

from __future__ import annotations

import os

# Runtimes this parse models natively (one EXCLUSIVE_* layout each).
_NATIVE_RUNTIMES = ('se', 'ae', 'svr')


def allow_vtable_emission(version, anchors_csv, shift_map_path):
    """Return ``(allowed, reason_when_refused)``."""
    if version not in _NATIVE_RUNTIMES:
        return False, ('CommonLibVR natively models {}; {} is not parsed here'
                       .format('/'.join(_NATIVE_RUNTIMES), version))
    if os.path.isfile(shift_map_path):
        # A shift map means someone is translating another runtime's slots into
        # this one.  This parse reads the runtime's own layout, so a map here is
        # either stale or a contradiction -- refuse rather than guess which.
        return False, ('shift map present for a natively-parsed runtime: {}'
                       .format(shift_map_path))
    if not os.path.isfile(anchors_csv):
        return False, ('no hand-verified vtable anchors for {} at {}'
                       .format(version, anchors_csv))
    return True, ''
