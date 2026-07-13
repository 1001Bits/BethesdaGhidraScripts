"""Extract CommonLib's CONCRETELY-typed struct members from the CommonLibVR headers.

The inverse-direction feed: CommonLib has already RE'd many members that Ghidra's
imported struct may still carry as an undefined blob (the import flattens nested
structs / drops some types). Pulling those typed members lets a Ghidra-side step apply
them where Ghidra has only undefined -- giving the decompiler more anchors so the NEXT
discovery pass propagates one level deeper.

Pure file parsing (no Ghidra). For each `class`/`struct X` body it yields the members
whose type is CONCRETE -- a class, pointer-to-class, smart pointer, or named container
-- skipping CommonLib's OWN placeholders (`unkNN` typed as uint*/void*) since those are
unknowns, not RE. Each member needs an offset, taken from its `// NN` or `/* NN */`
trailing comment. Writes <out>/commonlib_typed_members.csv (class, offset, cpp_type,
name).
"""
import csv
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import RE_DIR, TYPED_MEMBERS_CSV as OUT_CSV  # noqa: E402

# placeholder member types -- CommonLib's own unknowns, NOT RE to propagate.
_PLACEHOLDER = re.compile(
    r'^(std::(u?int(8|16|32|64)_t|u?intptr_t|byte)|void\s*\*?|std::byte)$')
_DECL = re.compile(r'\b(?:class|struct)\s+([A-Za-z_]\w*)')
# a member line: <type> <name>;  // NN   (or /* NN */). Type may hold <>,:*& and spaces.
_MEMBER = re.compile(
    r'^[ \t]*([A-Za-z_][\w:<>,\*&\t ]*?)\s+(\w+)\s*(?:\[[^\]]*\])?\s*;'
    r'[ \t]*(?://[ \t]*([0-9A-Fa-f]+)\b|/\*[ \t]*([0-9A-Fa-f]+)\b)')


def _match_brace(text, i):
    depth = 0
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def typed_members(re_dir):
    """Yield (class, offset_int, cpp_type, name) for concretely-typed members."""
    for path in glob.glob(os.path.join(re_dir, '**', '*.h'), recursive=True):
        try:
            text = open(path, encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        for dm in _DECL.finditer(text):
            cls = dm.group(1)
            brace = text.find('{', dm.end())
            if brace < 0:
                continue
            end = _match_brace(text, brace)
            if end <= brace:
                continue
            for line in text[brace:end].splitlines():
                mm = _MEMBER.match(line)
                if not mm:
                    continue
                cpp = mm.group(1).strip()
                if _PLACEHOLDER.match(cpp) or cpp in ('union', 'struct', 'enum', 'using'):
                    continue                      # CommonLib's own unknown / not a member
                off = mm.group(3) or mm.group(4)
                try:
                    yield (cls, int(off, 16), cpp, mm.group(2))
                except (TypeError, ValueError):
                    continue


def run():
    rows = list(typed_members(RE_DIR))
    seen = set()
    with open(OUT_CSV, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['class', 'offset', 'cpp_type', 'name'])
        for cls, off, cpp, name in rows:
            key = (cls, off)
            if key in seen:
                continue                          # first decl wins (avoid dup brace hits)
            seen.add(key)
            w.writerow([cls, '0x%X' % off, cpp, name])
    print('commonlib typed members: %d (%d unique class+offset) -> %s'
          % (len(rows), len(seen), OUT_CSV))


if __name__ == '__main__':
    run()
