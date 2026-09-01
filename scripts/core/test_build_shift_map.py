import struct

import build_shift_map
import vtable_matcher
from vtable_layout import BinaryLayout, SlotEntry, save_csv


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


def _v5(rvas):
    return (struct.pack('<I', 5) + struct.pack('<4I', 1, 16, 236, 0) +
            b'Starfield'.ljust(64, b'\0') + struct.pack('<Q', 8) +
            struct.pack('<I', len(rvas)) +
            b''.join(struct.pack('<I', rva) for rva in rvas))


def _run_cli(tmp_path, monkeypatch, capsys, ref, target, extra=()):
    ref_csv = tmp_path / 'ref.csv'
    tgt_csv = tmp_path / 'tgt.csv'
    save_csv(ref, str(ref_csv))
    save_csv(target, str(tgt_csv))
    argv = ['build_shift_map.py',
            '--ref', str(ref_csv), '--ref-label', 'ref',
            '--target', str(tgt_csv), '--target-label', 'tgt',
            '--out', str(tmp_path / 'out.json')]
    monkeypatch.setattr('sys.argv', argv + list(extra))
    code = build_shift_map.main()
    return code, capsys.readouterr().out


def test_failing_run_still_reports_what_matched(tmp_path, monkeypatch, capsys):
    """A bare percentage is not a diagnosis.

    The breakdown used to print only after the gate passed, so the one run that
    needed explaining -- the failing one -- was the run that explained nothing.
    """
    ref = _layout('ref', 10)
    target = BinaryLayout('tgt')
    table = target.upsert('Actor', 0x9000)
    for index in range(10):
        table.add(SlotEntry(index, 0x8000 + index, 'Other::Fn%d' % index, ''))

    code, out = _run_cli(tmp_path, monkeypatch, capsys, ref, target)

    assert code == 2
    assert 'Refusing to write an unsafe shift map.' in out
    assert 'Matched ref->target slots: 0' in out
    assert 'Unmatched ref slots:       10' in out
    assert out.index('Matched ref->target') < out.index('Refusing')


def test_address_library_ids_match_slots_that_bytes_and_names_cannot(
        tmp_path, monkeypatch, capsys):
    """The real cross-version case: every function moved, no target names."""
    ref = BinaryLayout('ref')
    ref_table = ref.upsert('Actor', 0x140001000)
    target = BinaryLayout('tgt')
    tgt_table = target.upsert('Actor', 0x140009000)
    for index in range(10):
        ref_table.add(SlotEntry(index, 0x140002000 + index * 0x10,
                                'Actor::Fn%d' % index, 'AA BB'))
        # Different address, no name, and a prologue whose bytes moved with it.
        tgt_table.add(SlotEntry(index, 0x140005000 + index * 0x10, '', 'CC DD'))

    ref_bin = tmp_path / 'versionlib-1-16-236-0.bin'
    tgt_bin = tmp_path / 'versionlib-1-16-244-0.bin'
    ref_bin.write_bytes(_v5([0] + [0x2000 + i * 0x10 for i in range(10)]))
    tgt_bin.write_bytes(_v5([0] + [0x5000 + i * 0x10 for i in range(10)]))

    without, _ = _run_cli(tmp_path, monkeypatch, capsys, ref, target)
    assert without == 2          # nothing to match on

    code, out = _run_cli(tmp_path, monkeypatch, capsys, ref, target,
                         ['--ref-versionlib', str(ref_bin),
                          '--target-versionlib', str(tgt_bin)])
    assert code == 0
    assert 'Matched ref->target slots: 10' in out
    assert 'address_library_id           10' in out


def test_wrong_image_base_is_refused_rather_than_mapped(
        tmp_path, monkeypatch, capsys):
    ref = _layout('ref', 10)          # addresses near 0x2000, not 0x140002000
    target = _layout('tgt', 10)
    ref_bin = tmp_path / 'r.bin'
    tgt_bin = tmp_path / 't.bin'
    ref_bin.write_bytes(_v5([0, 0x2000]))
    tgt_bin.write_bytes(_v5([0, 0x5000]))

    code, out = _run_cli(tmp_path, monkeypatch, capsys, ref, target,
                         ['--ref-versionlib', str(ref_bin),
                          '--target-versionlib', str(tgt_bin)])
    assert code == 2
    assert 'does not fit its address library' in out
    assert '--ref-image-base' in out


def test_versionlibs_must_be_supplied_together(tmp_path, monkeypatch, capsys):
    ref = _layout('ref', 10)
    code, out = _run_cli(tmp_path, monkeypatch, capsys, ref, _layout('tgt', 10),
                         ['--ref-versionlib', str(tmp_path / 'nope.bin')])
    assert code == 2
    assert 'must be given together' in out
