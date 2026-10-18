"""Ghidra driver: name + type global game-setting objects by their key's
Hungarian prefix.  Technique adapted from alandtse's CommonLibVR notes.

A setting object (RE::Setting / SettingT<T>) stores a pointer to its key
string (``fJumpHeightMin``) whose first char encodes the value type.
This scans defined strings for Hungarian setting keys, follows the data
xref back to the Setting object that points at each key, names that
object ``setting_<key>``, and types the value union from the prefix.

Per-game geometry (value union @0x8 in all):
  SSE / F4 : key pointer @0x10, struct size 0x18
  Starfield: key pointer @0x18, struct size 0x20  (carries _defaultValue@0x10)
FNV (x86) uses a different settings layout and is skipped.

NON-DESTRUCTIVE: only names DAT_/undefined slots and types the value
slot; never clobbers an existing name/type.  Dry-run default;
BGS_ENRICH_APPLY=go to write.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import settings_match as sm  # noqa: E402

APPLY = os.environ.get('BGS_ENRICH_APPLY', 'dry').lower() == 'go'


def _is_data_addr(mem, addr):
    blk = mem.getBlock(addr)
    return blk is not None and blk.isInitialized() and not blk.isExecute()


def _report_errors(errors):
    print('  %d write(s) FAILED:' % len(errors))
    for line in errors[:20]:
        print('    ' + line)


def run():
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.data import (
        FloatDataType, IntegerDataType, UnsignedIntegerDataType,
        BooleanDataType, CharDataType, ByteDataType, PointerDataType)
    cp = currentProgram  # noqa: F821
    if cp.getDefaultPointerSize() != 8:
        print('settings-harvest (%s): x86 program -- skipped (FNV settings '
              'layout differs)' % cp.getName())
        return

    name_is_sf = 'starfield' in cp.getName().lower()
    NAME_OFF = 0x18 if name_is_sf else 0x10
    VALUE_OFF = 0x8

    listing = cp.getListing()
    rm = cp.getReferenceManager()
    fm = cp.getFunctionManager()
    mem = cp.getMemory()
    st = cp.getSymbolTable()
    af = cp.getAddressFactory().getDefaultAddressSpace()

    _TYPE = {'float': FloatDataType(), 'int': IntegerDataType(),
             'uint': UnsignedIntegerDataType(), 'bool': BooleanDataType(),
             'char': CharDataType(), 'byte': ByteDataType()}

    named = typed = scanned = skipped = 0
    candidates = {}
    di = listing.getDefinedData(True)
    while di.hasNext():
        d = di.next()
        tn = d.getDataType().getName().lower()
        if 'char' not in tn and 'string' not in tn:
            continue
        v = d.getValue()
        if v is None:
            continue
        key = sm.setting_key(str(v).strip())
        if key is None:
            continue
        scanned += 1
        vt = sm.value_type(key)
        for ref in rm.getReferencesTo(d.getAddress()):
            frm = ref.getFromAddress()
            if (fm.getFunctionContaining(frm) is not None or
                    not ref.getReferenceType().isData() or
                    not _is_data_addr(mem, frm)):
                continue
            base_off = frm.getOffset() - NAME_OFF
            base = af.getAddress(base_off)
            base_block = mem.getBlock(base)
            if (base_block is None or not base_block.isWrite() or
                    not base_block.contains(base.add(NAME_OFF + 7))):
                continue
            # Require a data vtable and an executable first virtual target.
            try:
                vptr = mem.getLong(base) & 0xFFFFFFFFFFFFFFFF
                vtable = af.getAddress(vptr)
                if not _is_data_addr(mem, vtable):
                    continue
                first = af.getAddress(mem.getLong(vtable) & 0xFFFFFFFFFFFFFFFF)
                code_block = mem.getBlock(first)
                if code_block is None or not code_block.isExecute():
                    continue
            except Exception:
                continue
            candidates.setdefault(base_off, set()).add((key, vt))

    errors = []

    def value_conflict(va, width):
        """Anything real inside [va, va+width)?  Checked per byte: looking at
        one data item and then clearing a RANGE destroyed typed neighbours."""
        for delta in range(width):
            location = va.add(delta)
            if listing.getInstructionContaining(location) is not None:
                return True
            existing = listing.getDefinedDataContaining(location)
            if (existing is not None and not
                    existing.getDataType().getName().startswith('undefined')):
                return True
        return False

    had_parent_transaction = (
        APPLY and cp.getCurrentTransactionInfo() is not None)
    tx = cp.startTransaction('settings-harvest') if APPLY else None
    success = False
    try:
        for base_off, evidence in candidates.items():
            # Multiple keys claiming one object is ambiguous; never first-win.
            if len(evidence) != 1:
                skipped += 1
                continue
            key, vt = next(iter(evidence))
            base = af.getAddress(base_off)
            if not APPLY:
                named += 1
                if vt:
                    typed += 1
                continue
            wanted = 'setting_' + key
            try:
                sym = st.getPrimarySymbol(base)
                # Any DEFAULT-source name (DAT_/PTR_/LAB_/...) is a placeholder;
                # everything else is somebody's name and is kept.
                if sym is None or sym.getSource() == SourceType.DEFAULT:
                    st.createLabel(base, wanted, SourceType.ANALYSIS)
                    named += 1
                elif sym.getName() == wanted:
                    named += 1
            except Exception as exc:  # noqa: BLE001
                errors.append('name %s @ %s: %s' % (wanted, base, exc))
            if vt:
                valt, width = vt
                va = base.add(VALUE_OFF)
                if value_conflict(va, width):
                    skipped += 1
                    continue
                dt = PointerDataType() if valt == 'ptr' else _TYPE.get(valt)
                if dt is not None:
                    try:
                        listing.clearCodeUnits(va, va.add(width - 1), False)
                        if listing.createData(va, dt) is None:
                            raise RuntimeError('createData returned no data')
                        typed += 1
                    except Exception as exc:  # noqa: BLE001
                        errors.append('type %s @ %s: %s' % (wanted, va, exc))
        # Decide BEFORE ending the transaction: a pass in which every write
        # failed is rolled back, never committed and then reported as failed.
        if errors and not (named or typed):
            _report_errors(errors)
            raise RuntimeError(
                'settings-harvest: every write failed (%d errors)' % len(errors))
        success = True
    finally:
        if tx is not None:
            committed = bool(cp.endTransaction(tx, success))
            if success and not had_parent_transaction and not committed:
                raise RuntimeError('settings-harvest transaction did not commit')

    print('settings-harvest (%s): %s  (game=%s, key@0x%X)'
          % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN',
             'SF' if name_is_sf else 'SSE/F4', NAME_OFF))
    print('  setting keys scanned=%d  candidates=%d  %s=%d  '
          'values-typed=%d ambiguous/skipped=%d'
          % (scanned, len(candidates), 'named' if APPLY else 'would-name',
             named, typed, skipped))
    if errors:
        # A silent ``except: pass`` here once hid a pass in which EVERY write
        # failed while the summary still looked healthy.
        _report_errors(errors)
    if not APPLY:
        print('  set BGS_ENRICH_APPLY=go to apply.')


from pyghidra_result import completion_line, script_program  # noqa: E402

if script_program(globals()) is not None:
    run()
    # Positive proof of execution; launchers fail closed without it.
    print(completion_line('settings_harvest'))
