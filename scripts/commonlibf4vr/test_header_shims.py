"""The parse-time header shims are load-bearing, so pin their behaviour.

A shim that silently stopped applying would not fail -- it would quietly hand
back flat-Fallout-4 vtable slots, every one of them one place too low from 0xD1
on.  Each shim therefore fails loudly when the text it keys on is gone, and
these tests hold that line.
"""
import importlib.util
import os

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
_CLF4VR_INCLUDE = os.path.join(
    _REPO, 'extern', 'CommonLibF4VR', 'CommonLibF4', 'include')

# Loaded by path: the module name collides with the CommonLibF4/SSE parsers, and
# importing it by name would hand back whichever landed in sys.modules first.
_spec = importlib.util.spec_from_file_location(
    'clf4vr_parser_under_test',
    os.path.join(_HERE, 'parse_commonlib_types.py'))

pytestmark = pytest.mark.skipif(
    not os.path.isdir(_CLF4VR_INCLUDE),
    reason='CommonLibF4VR submodule is not checked out')


def _module():
    module = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(module)
    return module


def test_vr_virtual_is_inserted_ahead_of_the_flat_0xd1_slot():
    clf4vr = _module()
    lines = ['\t\tvirtual void UpdateNoAI(float);  // 0D0\n',
             '\t\tvirtual void                 UpdateMotionDrivenState();  // 0D1\n',
             '\t\tvirtual void PotentiallyFixRagdollState();  // 0D3\n']
    patched = clf4vr._insert_vr_virtual(lines)

    assert patched is not None
    body = ''.join(patched)
    assert 'Unk_VR_0D1' in body
    assert '#ifdef ENABLE_FALLOUT_VR' in body
    # The insertion must land BEFORE the flat 0xD1 slot -- inserting after it
    # would shift the wrong methods and the anchors would (rightly) reject it.
    assert body.index('Unk_VR_0D1') < body.index('UpdateMotionDrivenState')
    # ...and it must not disturb the slot that precedes it.
    assert body.index('UpdateNoAI') < body.index('Unk_VR_0D1')


def test_vr_virtual_insertion_fails_loudly_if_upstream_renames_the_slot():
    clf4vr = _module()
    assert clf4vr._insert_vr_virtual(['\t\tvirtual void SomethingElse();\n']) is None


def test_invalid_forward_declaration_is_dropped():
    clf4vr = _module()
    lines = ['class BSGameSound;\n',
             '\tstruct BSISoundDescriptor::ExtraResolutionData;\n',
             'class BSMultisound;\n']
    patched = clf4vr._drop_invalid_forward_decl(lines)

    assert patched == ['class BSGameSound;\n', 'class BSMultisound;\n']


def test_forward_declaration_shim_fails_loudly_once_upstream_fixes_it():
    clf4vr = _module()
    assert clf4vr._drop_invalid_forward_decl(['class BSGameSound;\n']) is None


def test_upstream_still_needs_both_shims():
    """If upstream fixes either, the shim must be removed -- not left lying."""
    clf4vr = _module()

    actor = os.path.join(_CLF4VR_INCLUDE, 'RE', 'Bethesda', 'Actor.h')
    with open(actor, encoding='utf-8') as handle:
        assert clf4vr._insert_vr_virtual(handle.readlines()) is not None, (
            'CommonLibF4VR now models the VR virtual at Actor 0xD1; drop the '
            'overlay in scripts/commonlibf4vr instead of inserting it twice')

    audio = os.path.join(_CLF4VR_INCLUDE, 'RE', 'Bethesda', 'BSAudioManager.h')
    with open(audio, encoding='utf-8') as handle:
        assert clf4vr._drop_invalid_forward_decl(handle.readlines()) is not None, (
            'CommonLibF4VR fixed the invalid forward declaration; drop the shim')
