#!/usr/bin/env python3
"""DIAGNOSTIC: bit-width-aware structural scan for Havok hkClass reflection
descriptors (records that carry per-member byte offsets).  READ-ONLY.

Handles x64 (Skyrim/F4) and x86 (FNV) layouts.  Reports whether the
offset-bearing reflection survives in the binary -- the older 32-bit
games may differ from the proven-stripped x64 retail builds.

x64 (ptr=8): hkClass sizeof 0x50  name@0 objSize@0x10 members@0x28 num@0x30
             hkClassMember sizeof 0x28  name@0 type@0x18 offset@0x1E
x86 (ptr=4): hkClass sizeof 0x28  name@0 objSize@0x08 members@0x18 num@0x1C
             hkClassMember sizeof 0x18  name@0 type@0x0C offset@0x12

Usage: python scripts/core/havok_probe.py --project-dir C:/GhidraProjects
       --project-name Fallout/F4VR --program-path /FalloutNV.exe
"""
import argparse
import os
import struct
from pathlib import Path

REPO_DIR   = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))
TYPE_MAX = 36


def probe(program):
    import jpype
    ps = program.getDefaultPointerSize()
    be = program.getLanguage().isBigEndian()
    en = '>' if be else '<'
    if ps == 8:
        C_SIZE, C_OBJ, C_MEM, C_NUM = 0x50, 0x10, 0x28, 0x30
        M_SIZE, M_TYPE, M_OFF = 0x28, 0x18, 0x1E
    else:
        C_SIZE, C_OBJ, C_MEM, C_NUM = 0x28, 0x08, 0x18, 0x1C
        M_SIZE, M_TYPE, M_OFF = 0x18, 0x0C, 0x12
    PW = ps
    PF = en + ('Q' if ps == 8 else 'I')

    mem = program.getMemory()
    ByteArray = jpype.JArray(jpype.JByte)
    blocks = []
    for blk in mem.getBlocks():
        if not blk.isInitialized():
            continue
        size = blk.getSize()
        start = blk.getStart().getOffset()
        raw = bytearray(size)
        ok = True
        for c in range(0, size, 1 << 20):
            n = min(1 << 20, size - c)
            buf = ByteArray(n)
            try:
                blk.getBytes(blk.getStart().add(c), buf, 0, n)
            except Exception:
                ok = False
                break
            raw[c:c + n] = bytes(buf)
        if ok:
            blocks.append((start, start + size, raw, blk.isExecute()))
    blocks.sort()

    def fb(va):
        for s, e, raw, ex in blocks:
            if s <= va < e:
                return s, e, raw, ex
        return None

    def uptr(va):
        b = fb(va)
        return struct.unpack_from(PF, b[2], va - b[0])[0] if b and va + PW <= b[1] else None

    def u(va, w):
        b = fb(va)
        if b is None or va + w > b[1]:
            return None
        o = va - b[0]
        return {1: b[2][o], 2: struct.unpack_from(en + 'H', b[2], o)[0],
                4: struct.unpack_from(en + 'I', b[2], o)[0]}[w]

    def ident(va, maxlen=128):
        b = fb(va)
        if b is None or b[3]:
            return None
        s, e, raw, _ = b
        i = va - s
        out = []
        while i < len(raw) and raw[i] != 0 and len(out) < maxlen:
            ch = raw[i]
            if ch < 0x20 or ch > 0x7E:
                return None
            out.append(chr(ch))
            i += 1
        if not out:
            return None
        nm = ''.join(out)
        return nm if (nm[0].isalpha() or nm[0] == '_') else None

    def valid_members(mp, nmem, objsize):
        b = fb(mp)
        if b is None or b[3]:
            return False
        for i in (0, nmem - 1, nmem // 2):
            ma = mp + i * M_SIZE
            if ident(uptr(ma) or 0) is None:
                return False
            t = u(ma + M_TYPE, 1)
            o = u(ma + M_OFF, 2)
            if t is None or t >= TYPE_MAX or o is None or o > objsize:
                return False
        return True

    n_scanned = n_hkstr = 0
    full = []
    for s, e, raw, ex in blocks:
        if ex:
            continue
        for off in range(0, len(raw) - C_SIZE, PW):
            name_ptr = struct.unpack_from(PF, raw, off)[0]
            if name_ptr == 0:
                continue
            nm = ident(name_ptr)
            if nm is None:
                continue
            n_scanned += 1
            if nm.startswith(('hk', 'bhk')):
                n_hkstr += 1
            base = s + off
            objsize = u(base + C_OBJ, 4)
            nmem = u(base + C_NUM, 4)
            if objsize is None or not (0 < objsize <= 0x40000):
                continue
            if nmem is None or not (0 < nmem <= 2048):
                continue
            members = uptr(base + C_MEM)
            if members and valid_members(members, nmem, objsize):
                full.append((base, nm, objsize, members, nmem))

    print("=" * 60)
    print("%s  (ptr=%d-bit)" % (program.getName(), ps * 8))
    print("  name-identifier slots:        %d" % n_scanned)
    print("  of which hk*/bhk*-named:      %d" % n_hkstr)
    print("  hkClass WITH members (USEFUL):%d" % len(full))
    print("  total member fields:          %d" % sum(r[4] for r in full))
    print("=" * 60)
    full.sort(key=lambda r: -r[4])
    for base, nm, objsize, mp, nmem in full[:20]:
        print("    %-40s size=0x%-5X members=%d" % (nm[:40], objsize, nmem))
    for base, nm, objsize, mp, nmem in full[:2]:
        print("  --- %s ---" % nm)
        for i in range(min(nmem, 16)):
            ma = mp + i * M_SIZE
            print("      +0x%-4X type=%-2d %s"
                  % (u(ma + M_OFF, 2) or 0, u(ma + M_TYPE, 1) or -1,
                     ident(uptr(ma) or 0)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', default="Fallout/F4VR")
    ap.add_argument('--program-path', default="/FalloutNV.exe")
    args = ap.parse_args()
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()
    pdir, pname = args.project_dir, args.project_name
    if "/" in pname:
        pdir = pdir + "/" + pname.rsplit("/", 1)[0]
        pname = pname.rsplit("/", 1)[1]
    with pyghidra.open_project(pdir, pname, create=False) as project:
        root = project.getProjectData().getRootFolder()
        match = []

        def walk(folder, prefix=""):
            for f in folder.getFiles():
                if prefix + "/" + f.getName() == args.program_path:
                    match.append(f)
            for sub in folder.getFolders():
                walk(sub, prefix + "/" + sub.getName())
        walk(root)
        if not match:
            print("not found:", args.program_path)
            return
        consumer = java.lang.Object()
        # okToUpgrade=True: PPC debug build may need a minor language upgrade;
        # done in-memory, not persisted (we never save).
        program = match[0].getDomainObject(consumer, True, False, monitor)
        try:
            probe(program)
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
