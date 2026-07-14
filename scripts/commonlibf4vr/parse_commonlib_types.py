#!/usr/bin/env python3
"""True-VR type/vtable extractor for Fallout 4 VR 1.2.72 (CommonLibF4VR).

Reuses ``scripts/commonlibf4/parse_commonlib_types.py`` (import-safe: its work
is main-guarded, with no top-level side effects) but repoints it at
``extern/CommonLibF4VR`` and parses with ``-DENABLE_FALLOUT_VR=1``, so ``RE/``
resolves to Fallout 4 VR's *exclusive* layout.

Why this exists.  CommonLibF4 (powerof3) models flatscreen Fallout 4 only: its
per-runtime define lists are empty, and its own source says the seam is there so
"a VR-aware overlay can add (e.g.) -DBGS_FALLOUT4_VR=1 and emit a correctly-
shifted vtable layout for F4VR".  This is that overlay.  CommonLibF4VR
(ArthurHub, a fork of alandtse/CommonLibF4) models the divergence for real:
VR-inserted virtuals via FALLOUT_REL_VR_VIRTUAL, and VR member offsets pinned
with static_asserts verified against Fallout4VR.exe.  Parsing it VR-exclusive
yields true VR structs *and* true VR vtable slots -- where the CommonLibF4 path
emits OG-shaped structs and, by policy, no VR vtables at all.

Nothing in scripts/commonlibf4/ is modified; this only overrides module globals
on the imported base parser at runtime (the same additive pattern
scripts/commonlibvr/ uses against the Skyrim parser).

Generated importer: ghidrascripts/CommonLibImport_CLF4VR_VR.py, identity-bound
to the exact Fallout4VR.exe staged under exes/f4/vr/.
"""
import importlib.util
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))    # scripts/commonlibf4vr
SCRIPTS_DIR = os.path.dirname(SCRIPT_DIR)                  # scripts
PROJECT_DIR = os.path.dirname(SCRIPTS_DIR)                 # repo root
F4_DIR = os.path.join(SCRIPTS_DIR, 'commonlibf4')

# Import the shared core + the CommonLibF4 parser as modules (import-safe).
sys.path.insert(0, os.path.join(SCRIPTS_DIR, 'core'))
sys.path.insert(0, F4_DIR)
import parse_commonlib_types as base  # noqa: E402

# ArthurHub's fork keeps the library under CommonLibF4/, and ships REL/ + REX/
# inside its own include tree (no commonlib-shared submodule).
CLF4VR_INCLUDE = os.path.join(
    PROJECT_DIR, 'extern', 'CommonLibF4VR', 'CommonLibF4', 'include')

if not os.path.isdir(CLF4VR_INCLUDE):
    raise SystemExit(
        'CommonLibF4VR is not checked out at {}\n'
        'Run: git submodule update --init --recursive'.format(CLF4VR_INCLUDE))

# Loaded by explicit path, not by name: importing `base` above already put
# commonlibf4's own policy in scope, and a bare `import vtable_policy` would
# resolve to whichever sibling landed in sys.modules first -- an override that
# silently no-ops looks exactly like one that worked.
_policy_spec = importlib.util.spec_from_file_location(
    'clf4vr_vtable_policy', os.path.join(SCRIPT_DIR, 'vtable_policy.py'))
_clf4vr_policy = importlib.util.module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(_clf4vr_policy)

# --- additive overrides on the imported base parser (powerof3 files untouched) ---
base._allow_vtable_emission = _clf4vr_policy.allow_vtable_emission

base.COMMONLIB_INCLUDE = CLF4VR_INCLUDE
base.FALLOUT_H = os.path.join(CLF4VR_INCLUDE, 'RE', 'Fallout.h')
base.RE_INCLUDE = os.path.join(CLF4VR_INCLUDE, 'RE')

# Anchors and refs resolve under this package: its anchors/vr.csv is the VR
# ground truth, and -- unlike scripts/commonlibf4/refs/ -- it holds no legacy
# shift_f4_vr.json, which the vtable policy would (correctly) refuse.
base.SCRIPT_DIR = SCRIPT_DIR

# The parse must be clean, not merely survivable.  Exact vtable slots come from
# clang's -fdump-vtable-layouts pass, which needs a compile that *succeeds*; when
# it fails, slots silently fall back to AST declaration order and land 3-4 places
# off -- wrong in a way only the anchors catch.  So both fixes below exist to get
# a clean parse, and the preflight refuses to continue without one.

# CommonLibF4VR is written for MSVC, which parses template bodies lazily.  Clang
# parses them eagerly under -std=c++23, which surfaces three latent upstream bugs
# (a `a_rhs.storage` typo, static_casts between forward-declared types) that MSVC
# never instantiates.  -fdelayed-template-parsing makes clang behave as the
# library's actual compiler does; it defers only *bodies*, never the member
# declarations layouts are read from.
_MSVC_PARSE_FLAGS = ['-fdelayed-template-parsing']

# One target: VR, parsed VR-exclusive.  The '[]' fallback pool is kept from the
# CommonLibF4 entry -- F4VR's community address-library ID namespace is disjoint
# from meh321's, so an OG/AE fallback would resolve to mislabeled functions.
base.F4_TARGETS = (
    ('f4_vr', 'CommonLibImport_CLF4VR_VR.py', '[]', 'vr.csv',
     ['-DENABLE_FALLOUT_VR=1'] + _MSVC_PARSE_FLAGS),
)

# Two headers are shadowed at parse time.  Both shims are regenerated from the
# submodule on every run -- so they cannot go stale -- and both fail loudly if
# the text they key on disappears, rather than silently doing nothing.
#
# 1. BSAudioManager.h forward-declares a nested type through an incomplete
#    enclosing class:
#
#        struct BSISoundDescriptor::ExtraResolutionData;
#
#    invalid C++ that only MSVC accepts.  It declares no member, so dropping it
#    cannot move a field.  (Patching the submodule instead would leave it dirty,
#    and run.py rightly refuses to generate from dirty submodules.)
#
# 2. Actor.h is missing Fallout 4 VR's inserted virtual.  CommonLibF4VR models
#    VR's *member* shifts (MiddleHighProcessData and friends, pinned by
#    static_asserts against Fallout4VR.exe) but not its *vtable* shift: the
#    FALLOUT_REL_VR_VIRTUAL macro its REL/Common.h defines for exactly this
#    purpose is used nowhere in the library.  So its Actor vtable is flat
#    Fallout 4's, and every slot from 0xD1 on is one place too low.
#
#    scripts/commonlibf4vr/anchors/vr.csv records the truth, read out of the
#    binary: a VR-only virtual sits at 0xD1, and PlayerCharacter's
#    UpdateMotionDrivenState / UpdateNonRenderSafe / ShouldHandleEquipNow land at
#    0xD2 / 0xD5 / 0xD6 rather than 0xD1 / 0xD4 / 0xD5.  Inserting one virtual
#    ahead of UpdateMotionDrivenState reproduces that exactly -- and the anchor
#    verifier is what proves it: the three slots *before* the insertion must stay
#    put while the three *after* move by one, so a misplaced insertion fails.
#    This is the VR-aware overlay scripts/commonlibf4's own comment anticipates.
_INVALID_FORWARD_DECL = 'struct BSISoundDescriptor::ExtraResolutionData;'
_VR_VTABLE_INSERT_BEFORE = 'UpdateMotionDrivenState();'   # Actor's flat slot 0xD1
_VR_VTABLE_INSERT = (
    '#ifdef ENABLE_FALLOUT_VR\n'
    '\t\tvirtual void Unk_VR_0D1();'
    '  // 0D1 - VR-only insertion; see scripts/commonlibf4vr/anchors/vr.csv\n'
    '#endif\n'
)


def _shim_header(shim_root, relative_path, transform):
    """Write a shadowed copy of one upstream header, or die if it has moved on."""
    upstream = os.path.join(CLF4VR_INCLUDE, relative_path)
    with open(upstream, encoding='utf-8') as handle:
        lines = handle.readlines()

    patched = transform(lines)
    if patched is None:
        raise SystemExit(
            '{}\nno longer contains the text its parse-time shim keys on.\n'
            'Upstream has changed: re-check scripts/commonlibf4vr before '
            'generating, because the shim is now a no-op.'.format(upstream))

    target = os.path.join(shim_root, relative_path)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, 'w', encoding='utf-8') as handle:
        handle.write('// Generated at parse time from CommonLibF4VR.\n'
                     '// See scripts/commonlibf4vr/parse_commonlib_types.py.\n')
        handle.writelines(patched)


def _drop_invalid_forward_decl(lines):
    kept = [ln for ln in lines if ln.strip() != _INVALID_FORWARD_DECL]
    return kept if len(kept) != len(lines) else None


def _insert_vr_virtual(lines):
    out = []
    inserted = False
    for line in lines:
        stripped = line.lstrip()
        if (not inserted and stripped.startswith('virtual ')
                and _VR_VTABLE_INSERT_BEFORE in line):
            out.append(_VR_VTABLE_INSERT)
            inserted = True
        out.append(line)
    return out if inserted else None


def _build_header_shims():
    """Return an include dir shadowing the headers this parse must correct."""
    import tempfile

    shim_root = tempfile.mkdtemp(prefix='clf4vr_shim_')
    _shim_header(shim_root, os.path.join('RE', 'Bethesda', 'BSAudioManager.h'),
                 _drop_invalid_forward_decl)
    _shim_header(shim_root, os.path.join('RE', 'Bethesda', 'Actor.h'),
                 _insert_vr_virtual)
    return shim_root


def _preflight_parse(parse_args):
    """Refuse to generate unless clang parses CommonLibF4VR cleanly."""
    import re
    import subprocess
    from clang_types import find_clang_binary

    clang = find_clang_binary()
    result = subprocess.run(
        [clang] + list(parse_args) + ['-fsyntax-only', '-ferror-limit=0',
                                      base.FALLOUT_H.replace('\\', '/')],
        capture_output=True, text=True, encoding='utf-8', errors='replace')
    errors = [line for line in result.stderr.splitlines()
              if re.search(r': error: ', line)]
    if not errors:
        print('  clang parse: clean (exact vtable slots available)')
        return

    print('\nERROR: CommonLibF4VR does not parse cleanly ({} errors):'.format(
        len(errors)))
    for line in errors[:20]:
        print('  ' + line.strip())
    print('\nA parse with errors still yields an AST, but clang\'s vtable-layout\n'
          'dump does not run -- and vtable slots then fall back to declaration\n'
          'order, which is silently wrong.  Refusing to generate.')
    raise SystemExit(1)


def main():
    print('CommonLibF4VR source: {}'.format(CLF4VR_INCLUDE))
    print('Parsing Fallout 4 VR with -DENABLE_FALLOUT_VR=1 (true VR layout)')

    import clang_types

    shim_root = _build_header_shims()
    stub_dir = os.path.join(SCRIPTS_DIR, 'core', '_clang_stubs')

    # The shim must precede the real include dir, so wrap the include-path
    # builder rather than appending (a later -I would never win the lookup).
    _setup_include_paths = clang_types._setup_include_paths

    def _setup_include_paths_with_shims(*args, **kwargs):
        return ['-I' + shim_root] + _setup_include_paths(*args, **kwargs)

    clang_types._setup_include_paths = _setup_include_paths_with_shims
    try:
        _preflight_parse(
            _setup_include_paths_with_shims(CLF4VR_INCLUDE, stub_dir)
            + ['-DENABLE_FALLOUT_VR=1'] + _MSVC_PARSE_FLAGS)
        sys.argv = [sys.argv[0], '--only', 'vr']
        base.main()
    finally:
        clang_types._setup_include_paths = _setup_include_paths


if __name__ == '__main__':
    main()
