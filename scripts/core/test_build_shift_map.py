import build_shift_map
import vtable_matcher
from vtable_layout import BinaryLayout, SlotEntry


def _layout(label, count):
    layout = BinaryLayout(label)
    table = layout.upsert('Actor', 0x1000)
    for index in range(count):
        table.add(SlotEntry(index, 0x2000 + index,
                            'Actor::Fn%d' % index, ''))
    return layout


def test_quality_gate_rejects_empty_and_sparse_maps():
    ref = _layout('ref', 10)
    empty = BinaryLayout('empty')
    shift = vtable_matcher.build_shift_map(ref, empty)
    reasons = build_shift_map._quality_reasons(ref, empty, shift)
    assert any('empty' in reason for reason in reasons)
    assert any('matched' in reason for reason in reasons)


def test_quality_gate_accepts_well_aligned_map():
    ref = _layout('ref', 10)
    target = _layout('target', 10)
    shift = vtable_matcher.build_shift_map(ref, target)
    assert build_shift_map._quality_reasons(ref, target, shift) == []
