"""The supported game builds, and where each one's executable is staged.

This is the single source of truth shared by the launcher (``run.py``) and the
importer-identity check (``importer_binding``), so an error message can name the
exact directory an executable belongs in instead of a ``<game>/<version>``
placeholder.

Each entry: ``(key, game, version_label, exe_subdir, script_name, source)``.
Entries marked ``fork`` are added by this fork on top of doodlum's upstream
(which ships SE/AE + F4 AE only).
"""

from __future__ import annotations

from typing import Optional, Tuple

VERSION_CATALOG = [
    ("se",    "skyrim",    "Skyrim SE 1.5.97",     "skyrim/se",    "CommonLibImport_SE.py",    "upstream"),
    ("ae",    "skyrim",    "Skyrim AE 1.6.1170",   "skyrim/ae",    "CommonLibImport_AE.py",    "upstream"),
    ("ae17104", "skyrim",  "Skyrim AE 1.7.104",    "skyrim/17104", "CommonLibImport_AE_1_7_104.py", "fork"),
    ("svr",   "skyrim",    "Skyrim VR 1.4.15",     "skyrim/vr",    "CommonLibImport_VR.py",    "fork"),
    ("f4og",  "f4",        "Fallout 4 OG 1.10.163","f4/og",        "CommonLibImport_F4_OG.py", "fork"),
    ("f4ng",  "f4",        "Fallout 4 NG 1.10.984","f4/ng",        "CommonLibImport_F4_NG.py", "fork"),
    ("f4ae",  "f4",        "Fallout 4 AE 1.11.191","f4/ae",        "CommonLibImport_F4_AE.py", "upstream"),
    ("f4221", "f4",        "Fallout 4 1.11.221",   "f4/221",       "CommonLibImport_F4_221.py","fork"),
    ("f4240", "f4",        "Fallout 4 1.11.240",   "f4/240",       "CommonLibImport_F4_240.py","fork"),
    ("f4vr",  "f4",        "Fallout 4 VR 1.2.72",  "f4/vr",        "CommonLibImport_F4_VR.py", "fork"),
    ("fnv",   "fnv",       "Fallout NV 1.4.0.525", "fnv/og",       "CommonLibImport_FNV.py",   "fork"),
    ("sf",    "starfield", "Starfield 1.16.236 / 1.16.242 / 1.16.244", "starfield/sf", "CommonLibImport_SF.py",    "fork"),
]


# Alternate importers for a runtime already in the catalog.  CommonLibVR parses
# Skyrim VR with ENABLE_SKYRIM_VR, yielding true VR struct and vtable layouts;
# the powerof3 importer for the same runtime is SE-shaped and emits no vtables.
# Both target the same executable, so they share one catalog entry.
IMPORTER_ALIASES = {
    "CommonLibImport_CLVR_VR.py": "CommonLibImport_VR.py",
    "CommonLibImport_CLF4VR_VR.py": "CommonLibImport_F4_VR.py",
}


def entry_for_importer(script_name: str) -> Optional[Tuple[str, str, str, str, str, str]]:
    """The catalog entry a generated importer belongs to, by file name."""
    script_name = IMPORTER_ALIASES.get(script_name, script_name)
    for entry in VERSION_CATALOG:
        if entry[4] == script_name:
            return entry
    return None


def target_for_importer(script_name: str) -> Optional[Tuple[str, str]]:
    """``(version_label, exe_subdir)`` for an importer, or None if unrecognized."""
    entry = entry_for_importer(script_name)
    return (entry[2], entry[3]) if entry else None


# The ``--only`` selector each game's parser understands, keyed by catalog key.
# Fallout NV and Starfield are single-runtime, so they take no selector.
_ONLY_VERSION = {
    "se": "se", "ae": "ae", "ae17104": "17104", "svr": "vr",
    "f4og": "og", "f4ng": "ng", "f4ae": "ae", "f4221": "221", "f4240": "240", "f4vr": "vr",
    "fnv": None, "sf": None,
}


def generation_target(script_name: str) -> Optional[Tuple[str, Optional[str]]]:
    """``(game, only_version)`` needed to regenerate an importer, or None.

    ``only_version`` restricts the parser to one runtime -- each costs a full
    clang AST cycle, so never rebuild an importer's siblings to fix one.
    """
    entry = entry_for_importer(script_name)
    if entry is None:
        return None
    return (entry[1], _ONLY_VERSION.get(entry[0]))
