#!/usr/bin/env python3
"""Parse clang's `-fdump-record-layouts` output into structured JSON.

clang emits, for every completed record, a flattened layout with absolute
byte offsets (including inherited base-subobject fields and the vtable
pointer).  We capture, per record: size, align, and the ordered list of
leaf fields as (offset, type, name).  Base-class marker lines and the
vtable pointer are normalized (vtable -> a synthetic __vftable field@0).

Block format:
    *** Dumping AST Record Layout
             0 | class hkReferencedObject
             0 |   (hkReferencedObject vtable pointer)
             8 |   hkInt16 m_memSizeAndFlags
            10 |   hkInt16 m_referenceCount
               | [sizeof=16, align=8,
               |  nvsize=16, nvalign=8]

Usage:
  python parse_layouts.py <dump.txt> [--only-prefix hk bhk] > layouts.json
"""
import argparse
import json
import re
import sys

HDR = re.compile(r'^\s*(\d+) \| (class|struct|union) (.+)$')
# offset | <indent><content>   -- capture indent width and content separately
FLD = re.compile(r'^( *)(\d+) \|( +)(\S.*?)\s*$')
SIZE = re.compile(r'\[sizeof=(\d+), align=(\d+),')
VtableRe = re.compile(r'v[fp]?table pointer\)\s*$')
BaseRe = re.compile(r'\((primary base|virtual base|base)\)\s*$')


def parse(text):
    records = {}
    blocks = text.split('*** Dumping AST Record Layout')
    for blk in blocks[1:]:
        lines = blk.splitlines()
        hi = 0
        while hi < len(lines) and not HDR.match(lines[hi]):
            hi += 1
        if hi >= len(lines):
            continue
        m = HDR.match(lines[hi])
        if int(m.group(1)) != 0:
            continue                      # nested/base dump; top-level only
        kind = m.group(2)
        name = m.group(3).strip()
        fields = []
        has_vtable = False
        size = align = None
        # Indentation rule: after recording a field at indent `ind`, skip every
        # deeper line (that field's own record-expansion).  Base-class marker
        # lines record nothing and don't trigger skipping, so inherited fields
        # (deeper) are pulled up to absolute offsets.  Member sub-records keep
        # their single typed field and their expansion is skipped.
        skip_deeper = None
        for ln in lines[hi + 1:]:
            sm = SIZE.search(ln)
            if sm:
                size, align = int(sm.group(1)), int(sm.group(2))
                break
            fm = FLD.match(ln)
            if not fm:
                continue
            ind = len(fm.group(3))
            off = int(fm.group(2))
            body = fm.group(4).strip()
            if skip_deeper is not None:
                if ind > skip_deeper:
                    continue
                skip_deeper = None
            if VtableRe.search(body):
                if off == 0:
                    has_vtable = True
                continue
            if BaseRe.search(body):
                continue                  # base marker: pull up its fields
            if body.endswith('(empty)'):
                continue
            sp = body.rsplit(None, 1)
            if len(sp) != 2:
                continue
            ftype, fname = sp[0].strip(), sp[1].strip()
            am = re.match(r'^([A-Za-z_]\w*)\[(\d+)\]$', fname)
            if am:
                fname = am.group(1)
                ftype = '%s[%s]' % (ftype, am.group(2))
            elif not re.match(r'^[A-Za-z_]\w*$', fname):
                continue
            fields.append({'offset': off, 'type': ftype, 'name': fname})
            skip_deeper = ind             # skip this field's own expansion
        if size is None:
            continue
        seen = set()
        uniq = []
        for f in fields:
            k = (f['offset'], f['name'])
            if k in seen:
                continue
            seen.add(k)
            uniq.append(f)
        records[name] = {'size': size, 'align': align, 'kind': kind,
                         'vtable': has_vtable, 'fields': uniq}
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dump')
    ap.add_argument('--only-prefix', nargs='*', default=None)
    args = ap.parse_args()
    with open(args.dump, 'r', errors='replace') as fh:
        recs = parse(fh.read())
    if args.only_prefix:
        recs = {k: v for k, v in recs.items()
                if any(k.startswith(p) for p in args.only_prefix)}
    json.dump(recs, sys.stdout, indent=1)
    print('', file=sys.stderr)
    print('parsed %d records' % len(recs), file=sys.stderr)


if __name__ == '__main__':
    main()
