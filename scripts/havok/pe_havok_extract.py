#!/usr/bin/env python3
"""Extract Havok reflection (hkClass/hkClassMember) directly from a Havok
*toolchain* binary by structurally scanning for LIVE C++ hkClass objects.

Retail games strip the offset-bearing reflection; toolchain builds keep
it.  This parses the PE, maps sections at the preferred image base,
structurally locates live hkClass records (name->ident, sane objectSize,
a valid hkClassMember array), walks the parent chain to flatten inherited
members, and emits the same JSON shape as build_layouts.py.

FINDING (Havok 7.1 Content Tools, 2026-06): the HavokContentTools DLLs/
EXE embed their reflection as a SERIALIZED Havok packfile (magic
0x57E0E057 / "hkPackfile", with name-based class references), NOT as live
C++ hkClass objects -- so this live-object scan finds 0 there.  The class
names + member/dependency lists are present, but per-member byte offsets
are not recoverable without a full Havok-packfile parser.  The Content
Tools also ship no compilable headers (it is the exporter, not the SDK).
=> For FNV (Havok 7.1) the practical best source remains the Havok 6.6
SDK *headers* compiled via build_layouts.py (one major version off; exact
for stable classes).  A full Havok 7.1 SDK *source* tree (with Source/
headers) would yield exact 7.1 layouts via the same clang pipeline.

This tool still works on any toolchain binary that keeps LIVE reflection.

x86 layout (4-byte pointers):
  hkClass        name@0x00 objectSize@0x08 declaredMembers@0x18 numMembers@0x1C
  hkClassMember  name@0x00 class@0x04 type@0x0C(u8) offset@0x12(u16) sizeof 0x18

Usage:
  python scripts/havok/pe_havok_extract.py DLL [DLL2 ...] --out NAME.json
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path


def _sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


REFS = Path(__file__).resolve().parent / "refs"
TYPE_MAX = 40
_HK_TYPE = {
    0: 'void', 1: 'hkBool', 2: 'hkChar', 3: 'hkInt8', 4: 'hkUint8',
    5: 'hkInt16', 6: 'hkUint16', 7: 'hkInt32', 8: 'hkUint32', 9: 'hkInt64',
    10: 'hkUint64', 11: 'hkReal', 12: 'hkVector4', 13: 'hkQuaternion',
    14: 'hkMatrix3', 15: 'hkRotation', 16: 'hkQsTransform', 17: 'hkMatrix4',
    18: 'hkTransform', 19: 'zero', 20: 'ptr', 21: 'funcptr', 22: 'hkArray',
    23: 'hkInplaceArray', 24: 'enum', 25: 'struct', 26: 'hkSimpleArray',
    27: 'hkHomogeneousArray', 28: 'hkVariant', 29: 'char*', 30: 'hkUlong',
    31: 'flags', 32: 'hkHalf', 33: 'hkStringPtr', 34: 'hkRelArray',
}
# member.type -> a token apply_structs maps to a Ghidra type/size
_SCALAR_TOK = {
    1: 'hkBool', 2: 'hkChar', 3: 'hkInt8', 4: 'hkUint8', 5: 'hkInt16',
    6: 'hkUint16', 7: 'hkInt32', 8: 'hkUint32', 9: 'hkInt64', 10: 'hkUint64',
    11: 'hkReal', 30: 'hkUlong', 32: 'hkHalf', 33: 'hkStringPtr',
}
_IDENT = re.compile(r'^[A-Za-z_][\w:<>, \*]*$')


def load_pe(path):
    data = open(path, 'rb').read()
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew + 4] == b'PE\x00\x00', "not a PE"
    nsec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt = e_lfanew + 0x18
    magic = struct.unpack_from('<H', data, opt)[0]
    is64 = magic == 0x20b
    image_base = (struct.unpack_from('<Q', data, opt + 0x18)[0] if is64
                  else struct.unpack_from('<I', data, opt + 0x1C)[0])
    opt_size = struct.unpack_from('<H', data, e_lfanew + 0x14)[0]
    sec_off = opt + opt_size
    secs = []
    for i in range(nsec):
        b = sec_off + i * 0x28
        vsz = struct.unpack_from('<I', data, b + 8)[0]
        va = struct.unpack_from('<I', data, b + 12)[0]
        rsz = struct.unpack_from('<I', data, b + 16)[0]
        rptr = struct.unpack_from('<I', data, b + 20)[0]
        chars = struct.unpack_from('<I', data, b + 36)[0]
        execute = bool(chars & 0x20000000)
        n = min(vsz or rsz, rsz)
        raw = data[rptr:rptr + n]
        secs.append((image_base + va, image_base + va + len(raw), raw, execute))
    secs.sort()
    return image_base, secs, is64


def extractor(secs, ptrsz):
    PF = '<I' if ptrsz == 4 else '<Q'

    def fb(va):
        for s, e, raw, ex in secs:
            if s <= va < e:
                return s, e, raw, ex
        return None

    def uptr(va):
        b = fb(va)
        return struct.unpack_from(PF, b[2], va - b[0])[0] if b and va + ptrsz <= b[1] else None

    def u(va, w):
        b = fb(va)
        if b is None or va + w > b[1]:
            return None
        o = va - b[0]
        return {1: b[2][o], 2: struct.unpack_from('<H', b[2], o)[0],
                4: struct.unpack_from('<I', b[2], o)[0]}[w]

    def cstr(va, maxlen=160):
        b = fb(va)
        if b is None or b[3]:
            return None
        s, e, raw, _ = b
        i = va - s
        out = []
        while i < len(raw) and raw[i] != 0 and len(out) < maxlen:
            c = raw[i]
            if c < 0x20 or c > 0x7E:
                return None
            out.append(chr(c))
            i += 1
        return ''.join(out) if out else None

    def ident(va):
        s = cstr(va)
        return s if (s and _IDENT.match(s)) else None
    return fb, uptr, u, cstr, ident


def scan(path):
    image_base, secs, is64 = load_pe(path)
    ptrsz = 8 if is64 else 4
    C_OBJ, C_MEM, C_NUM, C_PARENT = 0x08, 0x18, 0x1C, 0x04
    M_SIZE, M_TYPE, M_OFF, M_CLASS = 0x18, 0x0C, 0x12, 0x04
    if is64:
        C_OBJ, C_MEM, C_NUM, C_PARENT = 0x10, 0x28, 0x30, 0x08
        M_SIZE, M_TYPE, M_OFF, M_CLASS = 0x28, 0x18, 0x1E, 0x08
    fb, uptr, u, cstr, ident = extractor(secs, ptrsz)

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

    # locate hkClass records: name slot -> ident, sane objsize+members
    classes = {}                          # base_va -> (name, objsize, parent, mp, nmem)
    for s, e, raw, ex in secs:
        if ex:
            continue
        for off in range(0, len(raw) - 0x30, 4 if not is64 else 8):
            name_ptr = struct.unpack_from('<I' if not is64 else '<Q', raw, off)[0]
            if name_ptr == 0:
                continue
            nm = ident(name_ptr)
            if nm is None:
                continue
            base = s + off
            objsize = u(base + C_OBJ, 4)
            nmem = u(base + C_NUM, 4)
            if objsize is None or not (0 < objsize <= 0x40000):
                continue
            if nmem is None or not (0 < nmem <= 2048):
                continue
            mp = uptr(base + C_MEM)
            if mp and valid_members(mp, nmem, objsize):
                parent = uptr(base + C_PARENT)
                classes[base] = (nm, objsize, parent, mp, nmem)

    # flatten: each class = its declared members + all ancestors' members,
    # placed at their absolute offsets.
    def members_of(base):
        nm, objsize, parent, mp, nmem = classes[base]
        out = []
        for i in range(nmem):
            ma = mp + i * M_SIZE
            mn = ident(uptr(ma) or 0)
            if mn is None:
                continue
            mt = u(ma + M_TYPE, 1)
            mo = u(ma + M_OFF, 2)
            if mo is None or mo > objsize:
                continue
            tok = _SCALAR_TOK.get(mt)
            if tok is None:
                if mt in (20, 21):        # pointer/funcptr
                    tgt = uptr(ma + M_CLASS)
                    tn = ident(uptr(tgt)) if tgt else None
                    tok = (tn + ' *') if tn else 'void *'
                elif mt == 25:            # struct (embedded)
                    tgt = uptr(ma + M_CLASS)
                    tn = ident(uptr(tgt)) if tgt else None
                    tok = tn or 'struct'
                else:
                    tok = _HK_TYPE.get(mt, 'hkType%d' % mt)
            out.append((mo, tok, mn))
        return out

    records = {}
    for base, (nm, objsize, parent, mp, nmem) in classes.items():
        fields = {}
        seen_p = set()
        cur = base
        while cur is not None and cur in classes and cur not in seen_p:
            seen_p.add(cur)
            for mo, tok, mn in members_of(cur):
                fields.setdefault(mo, (tok, mn))   # child overrides parent
            cur = classes[cur][2]
        flist = [{'offset': o, 'type': t, 'name': n}
                 for o, (t, n) in sorted(fields.items())]
        # keep the richest definition if name seen twice across DLLs
        prev = records.get(nm)
        if prev is None or len(flist) > len(prev['fields']):
            records[nm] = {'size': objsize, 'align': ptrsz, 'kind': 'class',
                           'vtable': False,
                           'fields': flist}
    return records, ptrsz


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dlls', nargs='+')
    ap.add_argument('--out', default='havok_layouts_71_pe.json')
    ap.add_argument('--havok-version', required=True)
    ap.add_argument('--target', action='append', required=True,
                    help='allowed target executable basename; repeatable')
    args = ap.parse_args()
    merged = {}
    ptrsz = 4
    for d in args.dlls:
        recs, ptrsz = scan(d)
        print("%s: %d hkClass records" % (Path(d).name, len(recs)))
        for k, v in recs.items():
            if k not in merged or len(v['fields']) > len(merged[k]['fields']):
                merged[k] = v
    REFS.mkdir(exist_ok=True)
    out = REFS / args.out
    from layout_schema import make_document
    doc = make_document(merged, pointer_size=ptrsz,
                        havok_version=args.havok_version,
                        targets=args.target,
                        source='in-binary hkClass reflection',
                        input_modules=[{'file': Path(d).name,
                                        'sha256': _sha256(d)}
                                       for d in args.dlls])
    json.dump(doc, open(out, 'w'), indent=1)
    withf = sum(1 for v in merged.values() if v['fields'])
    print("merged %d classes (%d with fields, ptr=%d) -> %s"
          % (len(merged), withf, ptrsz, out))


if __name__ == "__main__":
    main()
