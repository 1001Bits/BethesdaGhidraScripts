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
            if (base_block is None or not base_block.isWritable() or
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
            try:
                sym = st.getPrimarySymbol(base)
                wanted = 'setting_' + key
                if sym is None or sym.getName().startswith('DAT_'):
                    st.createLabel(base, wanted, SourceType.ANALYSIS)
                    named += 1
                elif sym.getName() == wanted:
                    named += 1
            except Exception:
                pass
            if vt:
                valt, width = vt
                va = base.add(VALUE_OFF)
                ex = listing.getDefinedDataContaining(va)
                if (ex is not None and
                        (ex.getAddress() != va or
                         not ex.getDataType().getName().startswith('undefined'))):
                    skipped += 1
                    continue
                dt = PointerDataType() if valt == 'ptr' else _TYPE.get(valt)
                if dt is not None:
                    try:
                        listing.clearCodeUnits(va, va.add(width - 1), False)
                        listing.createData(va, dt)
                        typed += 1
                    except Exception:
                        pass
        success = True
    finally:
        if tx is not None:
            cp.endTransaction(tx, success)

    print('settings-harvest (%s): %s  (game=%s, key@0x%X)'
          % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN',
             'SF' if name_is_sf else 'SSE/F4', NAME_OFF))
    print('  setting keys scanned=%d  candidates=%d  %s=%d  '
          'values-typed=%d ambiguous/skipped=%d'
          % (scanned, len(candidates), 'named' if APPLY else 'would-name',
             named, typed, skipped))
    if not APPLY:
        print('  set BGS_ENRICH_APPLY=go to apply.')


run()
