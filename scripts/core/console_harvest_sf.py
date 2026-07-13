"""Ghidra driver: name Starfield console/script command handlers from the
engine's CODE-BASED command registration.

Starfield dropped the static CommandInfo[] table that older Bethesda games
use (and that console_harvest.py keys on).  Instead each command is
registered by a call:

    LEA  R9,  [execFunc]      ; arg4  -- the command's execute handler
    MOV  R8,  ...             ; arg3  -- help/flags
    LEA  RDX, [nameString]    ; arg2  -- the command name (e.g. "PlaceAtMe")
    MOV  RCX, commandObject   ; arg1
    CALL <registerCommand>

This harvester finds those sites by anchoring on the name-string LEAs
(LEA RDX,[ident]) and, in a small instruction window, pairs the RDX name
with the R9 execute function, then renames the handler to Cmd_<name>.

To suppress false positives it only accepts a (name,exec) pair whose CALL
target is a *shared* register function (one reached by many such sites).

NON-DESTRUCTIVE: only renames FUN_/sub_ handlers; never clobbers an
existing name.  Dry-run default; BGS_ENRICH_APPLY=go to write.
Knobs: BGS_SFCMD_MINSHARE (min sites per register fn, default 8).
"""
import os
import re

APPLY = os.environ.get('BGS_ENRICH_APPLY', 'dry').lower() == 'go'
MIN_SHARE = int(os.environ.get('BGS_SFCMD_MINSHARE', '4'))
_NAME_RE = re.compile(r'^[A-Za-z_]\w{1,63}$')
WINDOW_BACK = 6           # instrs before the name LEA to look for LEA R9
WINDOW_FWD = 6            # instrs after to find the CALL


def run():
    from ghidra.program.model.symbol import SourceType
    cp = currentProgram  # noqa: F821
    if cp.getDefaultPointerSize() != 8:
        print('sf-console (%s): not x64 -- skip' % cp.getName())
        return
    mem = cp.getMemory()
    fm = cp.getFunctionManager()
    listing = cp.getListing()
    rm = cp.getReferenceManager()
    af = cp.getAddressFactory().getDefaultAddressSpace()
    text = mem.getBlock('.text')
    if text is None:
        print('sf-console (%s): no .text' % cp.getName())
        return
    tlo = text.getStart().getOffset()
    thi = tlo + text.getSize()

    def cstr(va, maxlen=72):
        try:
            a = af.getAddress(va)
            bs = bytearray(maxlen)
            n = mem.getBytes(a, bs)
            out = []
            for i in range(n):
                ch = bs[i] & 0xFF
                if ch == 0:
                    break
                if ch < 0x20 or ch > 0x7E:
                    return None
                out.append(chr(ch))
            return ''.join(out) if out else None
        except Exception:
            return None

    def lea_target(ins):
        """If ins is LEA reg,[addr] return (regName, toAddr) else (None,None)."""
        if ins is None or ins.getMnemonicString() != 'LEA':
            return None, None
        reg = ins.getRegister(0)
        if reg is None:
            return None, None
        for ref in ins.getReferencesFrom():
            return reg.getName(), ref.getToAddress().getOffset()
        return reg.getName(), None

    def writes_reg(ins, name):
        if ins is None:
            return False
        try:
            return any(getattr(obj, 'getName', lambda: '')() == name
                       for obj in ins.getResultObjects())
        except Exception:
            return False

    # Anchor on name strings: iterate code refs to defined identifier strings.
    candidates = []           # (name, exec_func_addr, call_target_addr)
    di = listing.getDefinedData(True)
    seen_names = 0
    while di.hasNext():
        d = di.next()
        tn = d.getDataType().getName().lower()
        if 'char' not in tn and 'string' not in tn:
            continue
        v = d.getValue()
        if v is None:
            continue
        name = str(v).strip()
        if not _NAME_RE.match(name):
            continue
        saddr = d.getAddress()
        for ref in rm.getReferencesTo(saddr):
            fr = ref.getFromAddress()
            blk = mem.getBlock(fr)
            if blk is None or not blk.isExecute():
                continue
            ins = listing.getInstructionAt(fr)
            if ins is None or ins.getMnemonicString() != 'LEA':
                continue
            reg = ins.getRegister(0)
            if reg is None or reg.getName() != 'RDX':   # name is arg2 (RDX)
                continue
            seen_names += 1
            owner = fm.getFunctionContaining(fr)
            if owner is None:
                continue
            # find the CALL forward and LEA R9 (exec) in the window
            exec_fn = None
            call_tgt = None
            cur = ins
            for _ in range(WINDOW_FWD):
                cur = cur.getNext()
                if cur is None or fm.getFunctionContaining(cur.getAddress()) != owner:
                    break
                if cur.getMnemonicString() == 'CALL':
                    for ref2 in cur.getReferencesFrom():
                        target = ref2.getToAddress()
                        block = mem.getBlock(target)
                        if (ref2.getReferenceType().isCall() and block is not None
                                and block.isExecute()
                                and fm.getFunctionAt(target) is not None):
                            call_tgt = target.getOffset()
                    break
                if writes_reg(cur, 'RDX') or writes_reg(cur, 'R9'):
                    call_tgt = None
                    break
                flow = cur.getFlowType()
                if flow.isJump() or flow.isTerminal():
                    break
            # scan back for LEA R9,[func]
            cur = ins
            for _ in range(WINDOW_BACK):
                cur = cur.getPrevious()
                if cur is None or fm.getFunctionContaining(cur.getAddress()) != owner:
                    break
                rn, ta = lea_target(cur)
                if (rn == 'R9' and ta is not None and tlo <= ta < thi
                        and fm.getFunctionAt(af.getAddress(ta)) is not None):
                    exec_fn = ta          # R9 must point at a real function entry
                    break
                if writes_reg(cur, 'R9'):
                    break
                flow = cur.getFlowType()
                if flow.isJump() or flow.isTerminal() or flow.isCall():
                    break
            if exec_fn is not None and call_tgt is not None:
                candidates.append((name, exec_fn, call_tgt))

    # keep only pairs whose register fn is shared across many sites
    from collections import Counter
    share = Counter(c[2] for c in candidates)
    reg_fns = {a for a, n in share.items() if n >= MIN_SHARE}
    good = [c for c in candidates if c[2] in reg_fns]
    print('sf-console (%s): %d name-LEA sites, %d (name,exec) pairs, '
          '%d via %d shared register fns'
          % (cp.getName(), seen_names, len(candidates), len(good), len(reg_fns)))
    for a, n in share.most_common(6):
        print('   register fn @%X used by %d sites' % (a, n))

    by_exec = {}
    for name, exec_fn, call_target in good:
        by_exec.setdefault(exec_fn, set()).add((name, call_target))

    renamed = already = no_func = ambiguous = 0
    tx = cp.startTransaction('sf-console') if APPLY else None
    success = False
    try:
        for exec_fn, evidence in by_exec.items():
            names = {name for name, _ in evidence}
            if len(names) != 1:
                ambiguous += 1
                continue
            name = next(iter(names))
            f = fm.getFunctionAt(af.getAddress(exec_fn))
            if f is None:
                no_func += 1
                continue
            cur = f.getName()
            if not (cur.startswith('FUN_') or cur.startswith('sub_')
                    or cur.startswith('thunk_')):
                already += 1
                continue
            if APPLY:
                try:
                    f.setName('Cmd_' + name, SourceType.ANALYSIS)
                    renamed += 1
                except Exception:
                    pass
            else:
                renamed += 1
        success = True
    finally:
        if tx is not None:
            cp.endTransaction(tx, success)

    print('  %s=%d  already-named=%d  no-func=%d  ambiguous=%d'
          % ('renamed' if APPLY else 'would-rename', renamed, already,
             no_func, ambiguous))
    for name, exec_fn, _ in good[:15]:
        print('   Cmd_%-26s -> %X' % (name, exec_fn))


run()
