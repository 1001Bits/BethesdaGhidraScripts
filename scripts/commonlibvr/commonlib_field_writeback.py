"""Field write-back to CommonLibVR headers (the export half of the cycle).

Reads the three per-runtime `resolved_fields.csv` (the cross-version-reconciled struct
field TYPES the pipeline discovered), and rewrites the matching `unkNN` members in the
CommonLibVR C++ headers to their resolved type -- closing the loop CommonLib -> Ghidra
-> populate -> CommonLib.

CONSERVATIVE, non-destructive by design:
  * Only SAFE demangled types (pointers / primitives / arrays -- see
    field_writeback_plan) and only when the runtimes AGREE; templates, bitfields,
    inline classes and cross-runtime conflicts are reported, never written.
  * The member NAME is KEPT (`unk168` stays `unk168`); only the type token changes, so
    no consumer that references the member breaks. The `// NN` offset comment is kept.
  * A class type is written only if the header ALREADY references it (forward-decl or
    include present) -- we never inject forward declarations (placement/namespace risk).
  * Each member is located inside its own `class`/`struct` brace region, matched by the
    exact `unkNN` name, so we never touch a same-named member of another class.

Dry-run by default (writes <out>.field_writeback.report.csv of every would-change /
skip-reason); CLVR_FWB=go applies the edits to the working tree (run on a branch and
review the diff). Env: CLVR_RE_DIR (CommonLibVR/include/RE), CLVR_RESOLVED_DIR
(dir holding the *.resolved_fields.csv).
"""
import csv
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import RE_DIR, RESOLVED_DIR, SCRIPT_DIR  # noqa: E402

APPLY = os.environ.get('CLVR_FWB', 'dry').lower() == 'go'
REPORT = os.path.join(RESOLVED_DIR, 'field_writeback.report.csv')

import importlib.util as _ilu  # noqa: E402
_spec = _ilu.spec_from_file_location('clvr_field_writeback_plan',
                                     os.path.join(SCRIPT_DIR, 'field_writeback_plan.py'))
wp = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(wp)

_RT = {'SE': 'se', 'AE': 'ae', 'VR': 'vr'}

# a member type CommonLib uses as a not-yet-resolved placeholder -> safe to retype.
# A concrete class/template type means CommonLib already RE'd it -> leave it alone.
_PLACEHOLDER = re.compile(
    r'^(std::(u?int(8|16|32|64)_t|u?intptr_t|byte)|void\*?|std::byte)$')

_SZ = {'std::uint8_t': 1, 'std::int8_t': 1, 'std::byte': 1, 'byte': 1, 'char': 1,
       'bool': 1, 'std::uint16_t': 2, 'std::int16_t': 2, 'std::uint32_t': 4,
       'std::int32_t': 4, 'float': 4, 'std::uint64_t': 8, 'std::int64_t': 8,
       'double': 8, 'std::uintptr_t': 8, 'std::intptr_t': 8}


_SMART = {'NiPointer', 'NiTSmartPointer', 'BSTSmartPointer', 'GPtr', 'BSTAutoPointer',
          'NiTPointer'}


def _sizeof(t):
    """Byte size of a primitive/pointer/smart-pointer type, or None if unknown."""
    if t.endswith('*'):
        return 8
    if '<' in t:                                      # template
        if t.split('<', 1)[0].split('::')[-1] in _SMART:
            return 8                                  # engine smart pointer slot
        return None                                   # other containers: size varies
    return _SZ.get(t)


def _new_size(newtype, suffix):
    if suffix:                                        # '[N]' array
        base = _sizeof(newtype)
        return base * int(suffix[1:-1]) if base else None
    return _sizeof(newtype)


def _load_resolved():
    rows = {}
    for tag, rt in _RT.items():
        path = os.path.join(RESOLVED_DIR, 'CommonLibImport_CLVR_%s.py.resolved_fields.csv' % tag)
        if not os.path.exists(path):
            continue
        with open(path, newline='') as fh:
            rows[rt] = [(r['class'], r['cl_offset'], r['typename']) for r in csv.DictReader(fh)]
    return rows


def _index_headers():
    """Map each `class X`/`struct X` name -> list of (file, body_start, body_end) brace
    regions across the RE headers, so a member can be located within its own type."""
    idx = {}
    decl = re.compile(r'\b(?:class|struct)\s+([A-Za-z_]\w*)\b')
    for path in glob.glob(os.path.join(RE_DIR, '**', '*.h'), recursive=True):
        try:
            text = open(path, encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        for m in decl.finditer(text):
            brace = text.find('{', m.end())
            if brace < 0:
                continue
            end = _match_brace(text, brace)
            if end > brace:
                idx.setdefault(m.group(1), []).append((path, brace, end))
    return idx


def _match_brace(text, open_idx):
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return i
    return -1


_BUILTIN = {'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t', 'int8_t', 'int16_t',
            'int32_t', 'int64_t', 'uintptr_t', 'intptr_t', 'char', 'bool', 'float',
            'double', 'void', 'std', 'RE', 'size_t'}


def _type_known(text, cpp):
    """Every class identifier in the C++ type (wrapper + inner, e.g. NiPointer AND
    NiAVObject in `NiPointer<NiAVObject>`) is already referenced in the file -- so the
    rewrite compiles without us injecting includes/forward-decls."""
    for ident in re.findall(r'[A-Za-z_]\w*', cpp):
        if ident in _BUILTIN:
            continue
        if not re.search(r'\b%s\b' % re.escape(ident), text):
            return False
    return True


def run():
    rows = _load_resolved()
    if not rows:
        print('No resolved_fields.csv found in %s' % RESOLVED_DIR)
        return
    decisions = wp.reconcile(rows)
    idx = _index_headers()
    print('field-writeback: %d resolved (class,offset) keys, %d classes indexed in %s'
          % (len(decisions), len(idx), RE_DIR))

    edits = []          # (path, old_line, new_line, cls, off)
    report = []         # (cls, off, ghidra, cpp, status)
    file_text = {}      # path -> current text (mutated as we apply)

    for (cls, off), rec in sorted(decisions.items()):
        off_n = int(off, 16)
        member = 'unk%X' % off_n
        if rec['conflict']:
            report.append((cls, off, rec['ghidra'], rec['cpp'] or '', 'skip:runtime-conflict'))
            continue
        if not rec['safe']:
            report.append((cls, off, rec['ghidra'], str(rec['cpp']), 'skip:%s' % rec['kind']))
            continue
        regions = idx.get(cls)
        if not regions:
            report.append((cls, off, rec['ghidra'], str(rec['cpp']), 'skip:class-not-found'))
            continue
        # member declaration line within the class body, named exactly unk<OFF>
        # indent | current type (no internal space) | ws gap | member | tail(;)
        pat = re.compile(r'(^[ \t]*)([\w:<>\*]+)([ \t]+)(%s)\b([ \t]*;)' % member, re.M)
        located = None
        for path, bs, be in regions:
            text = file_text.get(path) or open(path, encoding='utf-8', errors='replace').read()
            file_text[path] = text
            mm = pat.search(text[bs:be])
            if mm:
                located = (path, bs, mm)
                break
        if located is None:
            report.append((cls, off, rec['ghidra'], str(rec['cpp']), 'skip:member-not-found'))
            continue
        path, bs, mm = located
        cur_type = mm.group(2)
        # ONLY rewrite a placeholder member -- never clobber a type CommonLib already
        # resolved (a `unkNN`-named member can already carry a concrete type).
        if not _PLACEHOLDER.match(cur_type):
            report.append((cls, off, rec['ghidra'], str(rec['cpp']), 'skip:already-typed'))
            continue
        text = file_text[path]
        if rec['kind'] == 'array':
            newtype, suffix = rec['cpp'][0], '[%s]' % rec['cpp'][2]
        else:
            newtype, suffix = rec['cpp'], ''
        if newtype == cur_type and not suffix:        # no-op
            report.append((cls, off, rec['ghidra'], str(rec['cpp']), 'skip:same-type'))
            continue
        # SIZE guard: the resolved type must be the SAME width as the placeholder slot.
        # A mismatch means Ghidra and CommonLib disagree on the layout here (Ghidra
        # merged what CommonLib splits, or vice versa) -- retyping would overlap the
        # neighbouring members and break STATIC_ASSERT_SIZE. Flag, never write.
        cur_sz, new_sz = _sizeof(cur_type), _new_size(newtype, suffix)
        if cur_sz is not None and new_sz is not None and cur_sz != new_sz:
            report.append((cls, off, rec['ghidra'], newtype + suffix, 'skip:size-mismatch'))
            continue
        if rec['kind'] != 'array' and not _type_known(text, newtype):
            report.append((cls, off, rec['ghidra'], newtype, 'skip:type-not-in-header'))
            continue
        old_line = mm.group(0)
        # keep indent + the EXACT ws gap (preserve column alignment); retype only
        new_line = '%s%s%s%s%s%s' % (mm.group(1), newtype, mm.group(3), member, suffix, mm.group(5))
        edits.append((path, off, bs, mm.start(), mm.end(), old_line, new_line, cls))
        report.append((cls, off, rec['ghidra'], newtype + suffix, 'rewrite' if APPLY else 'would-rewrite'))

    # apply edits per file (offsets shift -> apply back-to-front within each file)
    applied = 0
    if APPLY:
        byfile = {}
        for e in edits:
            byfile.setdefault(e[0], []).append(e)
        for path, es in byfile.items():
            text = file_text[path]
            for e in sorted(es, key=lambda x: x[2] + x[3], reverse=True):
                _p, _off, bs, ms, me, old, new, _cls = e
                a, b = bs + ms, bs + me
                text = text[:a] + new + text[b:]
                applied += 1
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(text)

    def _cppstr(cpp):
        if cpp is None:
            return ''
        if isinstance(cpp, tuple):              # array (base, 'array', n)
            return '%s[%s]' % (cpp[0], cpp[2])
        return str(cpp)

    with open(REPORT, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['class', 'cl_offset', 'ghidra_type', 'cpp_type', 'status'])
        for cls, off, gh, cpp, status in sorted(report, key=lambda r: (r[4], r[0], r[1])):
            w.writerow([cls, off, gh, _cppstr(cpp), status])

    from collections import Counter
    tally = Counter(r[4].split(':')[0] for r in report)
    print('  %s: %d fields -> %s' % ('APPLIED' if APPLY else 'DRY-RUN', len(report), dict(tally)))
    print('  rewrite candidates: %d (applied=%d)' % (len(edits), applied))
    for e in edits[:15]:
        print('     %s +%s  %s' % (e[7], e[1], e[6].strip()[:70]))
    print('  report -> %s' % REPORT)
    if not APPLY:
        print('  set CLVR_FWB=go to apply (run on a CommonLibVR branch; review the diff).')




run()
