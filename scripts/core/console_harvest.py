"""Ghidra driver: name console/script command handler functions from the
engine's SCRIPT_FUNCTION / CommandInfo table.  Technique adapted from
alandtse's CommonLibVR notes.

Each command record stores ``functionName`` (char*), a short alias, a
help string, and an ``executeFunction`` pointer.  This locates the
command table as a dense run of such records (name->ASCII, execute->
.text, fixed stride) and renames each handler to ``Cmd_<functionName>``.

Per-game record geometry:
  x64 (Skyrim/F4)   stride 0x50: name@0, short@8,  help@0x18, execute@0x30
  x64 (Starfield)   stride 0x58: name@0, short@8,  help@0x18, execute@0x30
  x86 (FNV)         stride 0x28: name@0, short@4,  help@0x0C, execute@0x18

NON-DESTRUCTIVE: only renames FUN_/sub_ handlers; never clobbers an
existing name.  Dry-run default; BGS_ENRICH_APPLY=go to write.
"""
import os
import re

APPLY = os.environ.get('BGS_ENRICH_APPLY', 'dry').lower() == 'go'
# A command name is a short bare identifier ("GetActorValue", "AddItem").
_NAME_RE = re.compile(r'^[A-Za-z_]\w{1,63}$')
_MIN_RUN = 24          # a real command table has hundreds of entries


def run():
    from ghidra.program.model.symbol import SourceType
    cp = currentProgram  # noqa: F821
    ps = cp.getDefaultPointerSize()
    name_is_sf = 'starfield' in cp.getName().lower()
    if ps == 8:
        stride = 0x58 if name_is_sf else 0x50
        name_off, exec_off = 0x0, 0x30
    else:
        stride = 0x28
        name_off, exec_off = 0x0, 0x18

    mem = cp.getMemory()
    fm = cp.getFunctionManager()
    listing = cp.getListing()
    st = cp.getSymbolTable()
    af = cp.getAddressFactory().getDefaultAddressSpace()
    text = mem.getBlock('.text')
    if text is None:
        print('console-harvest (%s): no .text block' % cp.getName())
        return
    text_lo = text.getStart().getOffset()
    text_hi = text_lo + text.getSize()

    def _ptr(addr):
        try:
            if ps == 8:
                v = mem.getLong(addr) & 0xFFFFFFFFFFFFFFFF
            else:
                v = mem.getInt(addr) & 0xFFFFFFFF
            return v
        except Exception:
            return None

    # Candidate name-field slots: a command record's name field is a data
    # pointer TO a short ASCII identifier string.  Rather than scan every
    # data slot (millions of reads), start from defined identifier strings
    # and follow their data xrefs back to the slot that points at them --
    # those slots are the table's name fields.
    rm = cp.getReferenceManager()
    listing2 = cp.getListing()
    cand = {}                       # name-field-slot offset -> name
    di = listing2.getDefinedData(True)
    while di.hasNext():
        d = di.next()
        tn = d.getDataType().getName().lower()
        if 'char' not in tn and 'string' not in tn:
            continue
        v = d.getValue()
        if v is None:
            continue
        nm = str(v).strip()
        if not _NAME_RE.match(nm):
            continue
        for ref in rm.getReferencesTo(d.getAddress()):
            slot = ref.getFromAddress()
            blk = mem.getBlock(slot)
            if blk is None or not blk.isInitialized() or blk.isExecute():
                continue
            # the record starts at the name field (name_off==0 all games)
            base = af.getAddress(slot.getOffset() - name_off)
            ev = _ptr(base.add(exec_off))
            if ev is not None and text_lo <= ev < text_hi:
                cand[base.getOffset()] = nm
    if not cand:
        print('console-harvest (%s): no command-table candidates' % cp.getName())
        return

    # Longest run of candidates exactly `stride` apart.
    best_start = best_len = 0
    for start in sorted(cand):
        if start - stride in cand:
            continue                 # not a run start
        n = 0
        o = start
        while o in cand:
            n += 1
            o += stride
        if n > best_len:
            best_len, best_start = n, start
    if best_len < _MIN_RUN:
        print('console-harvest (%s): longest run only %d (<%d) -- no table'
              % (cp.getName(), best_len, _MIN_RUN))
        return

    planned = {}
    o = best_start
    for _ in range(best_len):
        ad = af.getAddress(o)
        nm = cand[o]
        ev = _ptr(ad.add(exec_off))
        o += stride
        if ev is not None:
            planned.setdefault(ev, set()).add(nm)

    renamed = already = no_func = ambiguous = 0
    tx = cp.startTransaction('console-harvest') if APPLY else None
    success = False
    try:
        for ev, names in planned.items():
            if len(names) != 1:
                ambiguous += 1
                continue
            nm = next(iter(names))
            f = fm.getFunctionAt(af.getAddress(ev))
            if f is None:
                no_func += 1
                continue
            cur = f.getName()
            if not (cur.startswith('FUN_') or cur.startswith('sub_')):
                already += 1
                continue
            if APPLY:
                try:
                    f.setName('Cmd_' + nm, SourceType.ANALYSIS)
                    renamed += 1
                except Exception:
                    pass
            else:
                renamed += 1
        success = True
    finally:
        if tx is not None:
            cp.endTransaction(tx, success)

    print('console-harvest (%s): %s  table@0x%X x%d (stride 0x%X)'
          % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN',
             best_start, best_len, stride))
    print('  %s=%d  already-named=%d  no-func=%d  ambiguous=%d'
          % ('renamed' if APPLY else 'would-rename', renamed, already,
             no_func, ambiguous))


run()
