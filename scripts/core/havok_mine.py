"""Ghidra driver / verifier: scan for Havok hkClass reflection descriptors
with per-member byte offsets.  READ-ONLY.

CONCLUSION (proven 2026-06 across 3 architectures AND a debug build):
Bethesda builds do NOT contain the offset-bearing Havok reflection --
  Fallout4.exe 1.10.163 (x64 retail) ...... 0 hkClass-with-members
  SkyrimSE.exe 1.5.97   (x64 retail) ...... 0
  FalloutNV.exe         (x86 retail) ...... 0
  Fallout_Debug.exe     (PPC BE DEBUG) .... 0   <- rules out release-strip
The debug build (which keeps symbols) having 0 too proves this is a
BUILD-CONFIG choice (Havok compiled with reflection/serialization
metadata disabled), not a release-time strip.  What survives in every
build is the class/member NAME pool plus ``const char*[]`` name-pointer
tables (and hkVariant attribute records); the ``hkClass`` /
``hkClassMember`` objects carrying ``m_objectSize`` and per-member
``m_offset`` are never present.  There is no in-binary source for
authoritative havok field offsets in any Bethesda title.
(Cross-arch verifier: scripts/core/havok_probe.py.)

EVIDENCE (reproducible with this scanner):
  * Structural scan below finds 0 hkClass-with-members in either binary
    despite 17k-27k name-pointing data slots.  The SDK-confirmed layout
    is correct (see below) -- the records simply are not present.
  * Decisive referrer test: a member-name string such as
    "enforcedDuration" has exactly two referrers, both inside 8-byte
    name-pointer tables; an hkClassMember record (0x28 stride) would add
    a third.  It does not exist.  Class-name strings (e.g. "hkpRigidBody")
    likewise have a single referrer -- the name table -- where a real
    static hkClass object would add its m_name referrer.

The only remaining route to havok field TYPES is the Havok 2014 SDK
headers (for example, a locally configured Havok SDK include tree), parsed into Ghidra
structs.  That is a separate, partial-coverage effort: the SDK ships
Physics2012 + Common but not the hkb*/hknp* gameplay headers, and offset
computation requires compiling the (template/SIMD/alignment-macro heavy)
tree -- out of scope for binary-derived improvement.

This file is kept as a VERIFIER: if a future build (or a debug/editor
binary) is suspected to ship reflection, run it -- a nonzero
"hkClass (>=1 members)" count means the metadata is present and the
emitted CSV gives authoritative field offsets for the whole havok
subsystem.  It is deliberately NOT in the default improvement sweep.

Layout (Havok 2014.x x64 ABI, from the SDK headers
Source/Common/Base/Reflection/{hkClass,hkClassMember}.h -- CONFIRMED):
  hkClass        sizeof 0x50: name@0x00 objectSize@0x10(i32)
                 declaredMembers@0x28(ptr) numDeclaredMembers@0x30(i32)
  hkClassMember  sizeof 0x28: name@0x00 type@0x18(u8) offset@0x1E(u16)

Knob: BGS_HAVOK_CSV (output path for the member CSV, written only if any
class-with-members is found).
"""
import csv
import os
import struct

TYPE_MAX = 36          # hkClassMember::TYPE_MAX (2014.x)
HKMEMBER_SIZE = 0x28
HKCLASS_OBJSIZE, HKCLASS_MEMBERS, HKCLASS_NUMMEMBERS = 0x10, 0x28, 0x30
HKMEMBER_NAME, HKMEMBER_TYPE, HKMEMBER_OFFSET = 0x00, 0x18, 0x1E

_HK_TYPE = {
    0: 'void', 1: 'bool', 2: 'char', 3: 'i8', 4: 'u8', 5: 'i16', 6: 'u16',
    7: 'i32', 8: 'u32', 9: 'i64', 10: 'u64', 11: 'float', 12: 'hkVector4',
    13: 'hkQuaternion', 14: 'hkMatrix3', 15: 'hkRotation', 16: 'hkQsTransform',
    17: 'hkMatrix4', 18: 'hkTransform', 20: 'ptr', 21: 'funcptr',
    22: 'hkArray', 23: 'hkInplaceArray', 24: 'enum', 25: 'struct',
    26: 'hkSimpleArray', 28: 'hkVariant', 29: 'char*', 30: 'ulong',
    31: 'flags', 32: 'half', 33: 'hkStringPtr', 34: 'hkRelArray',
}


def run():
    import jpype
    cp = currentProgram  # noqa: F821
    if cp.getDefaultPointerSize() != 8:
        print('havok-mine (%s): x86 -- skipped (havok ABI here is x64)'
              % cp.getName())
        return
    mem = cp.getMemory()
    ByteArray = jpype.JArray(jpype.JByte)
    out_csv = os.environ.get('BGS_HAVOK_CSV') or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'refs',
        'havok_members_%s.csv' % cp.getName().replace('.', '_'))

    # Cache initialized blocks' raw bytes for fast random cross-block reads.
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

    def u(va, w):
        b = fb(va)
        if b is None or va + w > b[1]:
            return None
        o = va - b[0]
        if w == 8:
            return struct.unpack_from('<Q', b[2], o)[0]
        if w == 4:
            return struct.unpack_from('<I', b[2], o)[0]
        if w == 2:
            return struct.unpack_from('<H', b[2], o)[0]
        return b[2][o]

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
            ma = mp + i * HKMEMBER_SIZE
            if ident(u(ma + HKMEMBER_NAME, 8) or 0) is None:
                return False
            t = u(ma + HKMEMBER_TYPE, 1)
            o = u(ma + HKMEMBER_OFFSET, 2)
            if t is None or t >= TYPE_MAX or o is None or o > objsize:
                return False
        return True

    n_scanned = 0
    full = []                           # (base, name, objsize, members, nmem)
    for s, e, raw, ex in blocks:
        if ex:
            continue
        for off in range(0, len(raw) - 0x50, 8):
            name_ptr = struct.unpack_from('<Q', raw, off)[0]
            if name_ptr == 0:
                continue
            nm = ident(name_ptr)
            if nm is None:
                continue
            n_scanned += 1
            base = s + off
            objsize = u(base + HKCLASS_OBJSIZE, 4)
            nmem = u(base + HKCLASS_NUMMEMBERS, 4)
            if objsize is None or not (0 < objsize <= 0x40000):
                continue
            if nmem is None or not (0 < nmem <= 2048):
                continue
            members = u(base + HKCLASS_MEMBERS, 8)
            if members and valid_members(members, nmem, objsize):
                full.append((base, nm, objsize, members, nmem))

    rows = []
    for base, cname, objsize, members, nmem in full:
        for i in range(nmem):
            ma = members + i * HKMEMBER_SIZE
            mn = ident(u(ma + HKMEMBER_NAME, 8) or 0)
            if mn is None:
                continue
            mt = u(ma + HKMEMBER_TYPE, 1)
            mo = u(ma + HKMEMBER_OFFSET, 2)
            if mo is None or mo > objsize:
                continue
            rows.append((cname, '0x%X' % mo,
                         _HK_TYPE.get(mt, 'hkType%d' % (mt or 0)), mn,
                         str(objsize)))

    print('havok-mine (%s): %d name slots, %d hkClass-with-members, %d fields'
          % (cp.getName(), n_scanned, len(full), len(rows)))
    if not full:
        print('  -> reflection member-offset metadata NOT present in this '
              'build (expected for retail -- see module docstring).')
        return

    rows.sort(key=lambda r: (r[0], int(r[1], 16)))
    if not os.path.isdir(os.path.dirname(out_csv)):
        os.makedirs(os.path.dirname(out_csv))
    with open(out_csv, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['hkclass', 'offset', 'type', 'member', 'object_size'])
        for r in rows:
            w.writerow(r)
    print('  -> reflection PRESENT; wrote %s' % out_csv)


run()
