"""Fail-closed policy for Skyrim vtable overlay emission."""

from __future__ import annotations

import os


def allow_vtable_emission(version, anchors_csv, shift_map_path):
    """Allow only exact canonical header variants with required anchors."""
    if version not in ('se', 'ae'):
        return False, ('no exact identity-bound, coverage-valid vtable map '
                       'is shipped for {}'.format(version))
    if os.path.isfile(shift_map_path):
        return False, 'legacy/unbound shift map present for canonical runtime'
    if not os.path.isfile(anchors_csv):
        return False, 'required canonical vtable anchors are missing'
    return True, ''
