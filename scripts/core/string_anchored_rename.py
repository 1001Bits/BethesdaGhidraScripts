"""Ghidra driver: name unnamed functions from the debug strings the engine
embeds about itself.  Technique adapted from alandtse's CommonLibVR fork.

Scans ``FUN_*``/``sub_*``/``thunk_*`` functions for three self-naming
string patterns (timer-zone profiler labels, self-naming assert/log
messages, telemetry SDK names -- see string_anchor_match.py) and renames
them to the real ``Namespace::method``.

NON-DESTRUCTIVE: only renames functions still carrying a placeholder name;
never clobbers an established name.  A name is applied only when a function
maps to a SINGLE consistent identifier that is unique across the program.

CROSS-VERSION: match is by STRING, so the same debug string names the same
function in SE/AE/VR (and across F4/SF builds) without address mapping.

Run via pyghidra against a program (see apply_enrichment_to_user_project.py).
Knobs (env):
  BGS_ENRICH_APPLY=go        actually rename (default: dry-run report)
  BGS_RENAME_TELEMETRY_NS    comma list of telemetry namespaces (default: bnet)
  BGS_ENRICH_ENTRY_WINDOW    timer ref must sit within N bytes of entry (default 0x80)
"""
import os
import sys

# string_anchor_match.py lives alongside this driver.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import string_anchor_match as sam  # noqa: E402

APPLY = os.environ.get('BGS_ENRICH_APPLY', 'dry').lower() == 'go'
ENTRY_WINDOW = int(os.environ.get('BGS_ENRICH_ENTRY_WINDOW', '0x80'), 0)
TELEMETRY_NS = set((os.environ.get('BGS_RENAME_TELEMETRY_NS') or 'bnet').split(','))


def _is_placeholder(name):
    return (name.startswith('FUN_') or name.startswith('sub_')
            or name.startswith('thunk_FUN'))


def _iter_strings(listing):
    di = listing.getDefinedData(True)
    while di.hasNext():
        d = di.next()
        tn = d.getDataType().getName().lower()
        if 'char' not in tn and 'string' not in tn:
            continue
        v = d.getValue()
        if v is None:
            continue
        yield d, str(v).strip()


def _collect(cp):
    """func-entry-offset -> (func, set(candidate names)) from all patterns.

    Also returns the names that are already OWNED: a self-naming string that a
    non-placeholder function references too belongs to that function, so an
    unnamed helper or outlined block sharing the string must not inherit the
    name.  Counting only placeholder referrers made such a helper look unique.
    """
    fm, listing, rm = (cp.getFunctionManager(), cp.getListing(),
                       cp.getReferenceManager())
    by_func = {}
    owned = set()
    for d, s in _iter_strings(listing):
        name, is_timer = sam.match_any(s, TELEMETRY_NS)
        if not name:
            continue
        for ref in rm.getReferencesTo(d.getAddress()):
            f = fm.getFunctionContaining(ref.getFromAddress())
            if f is None:
                continue
            if not _is_placeholder(f.getName()):
                owned.add(name)
                continue
            ep = f.getEntryPoint().getOffset()
            if is_timer and ref.getFromAddress().getOffset() - ep > ENTRY_WINDOW:
                continue  # timer string must be at entry
            by_func.setdefault(ep, (f, set()))[1].add(name)
    for ep in list(by_func):
        by_func[ep][1].difference_update(owned)
        if not by_func[ep][1]:
            del by_func[ep]
    return by_func, owned


def _namespace(cp, st, parts):
    from ghidra.program.model.symbol import SourceType
    ns = cp.getGlobalNamespace()
    for part in parts:
        child = st.getNamespace(part, ns)
        if child is None:
            child = st.createNameSpace(ns, part, SourceType.ANALYSIS)
        ns = child
    return ns


def run():
    from ghidra.program.model.symbol import SourceType
    cp = currentProgram  # noqa: F821
    st = cp.getSymbolTable()
    by_func, owned = _collect(cp)
    plan, ambiguous = sam.resolve(by_func)
    # A function that already carries the exact qualified name owns it too.
    taken = set()
    for ep, name in plan:
        for symbol in st.getSymbols(name.split('::')[-1]):
            if (str(symbol.getSymbolType()) == 'Function' and
                    symbol.getName(True) == name):
                taken.add(name)
    plan = [(ep, name) for ep, name in plan if name not in taken]
    owned |= taken

    applied = errors = 0
    tx = cp.startTransaction('string-anchored rename') if APPLY else None
    success = False
    try:
        for ep, name in plan:
            f = by_func[ep][0]
            parts = name.split('::')
            if APPLY:
                try:
                    ns = _namespace(cp, st, parts[:-1])
                    f.getSymbol().setNameAndNamespace(
                        parts[-1], ns, SourceType.ANALYSIS)
                    applied += 1
                except Exception:
                    errors += 1
        success = True
    finally:
        if tx is not None:
            cp.endTransaction(tx, success)

    print('string-anchored rename (%s): %s'
          % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN'))
    print('  already-owned-skipped=%d' % len(owned))
    print('  %s=%d  errors=%d  ambiguous-skipped=%d'
          % ('renamed' if APPLY else 'would-rename',
             applied if APPLY else len(plan), errors, len(ambiguous)))
    for ep, name in plan[:40]:
        print('   0x%X -> %s' % (ep, name))
    if not APPLY:
        print('  set BGS_ENRICH_APPLY=go to apply.')


from pyghidra_result import completion_line, script_program  # noqa: E402

if script_program(globals()) is not None:
    run()
    # Positive proof of execution; launchers fail closed without it.
    print(completion_line('string_anchored_rename'))
