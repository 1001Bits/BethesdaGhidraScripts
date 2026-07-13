"""Name unnamed functions from the debug strings the engine embeds about itself.

The highest-signal, cheapest RE anchor: internal strings the binary builds for its own
profiler/asserts/logs name the enclosing function (and often its `this` class) outright.
This driver scans `FUN_*`/`sub_*`/`thunk_*` functions for three self-naming string patterns
and renames them to the real C++ `Namespace::method`:

  1. TIMER ZONE -- a string like `TthkbWorld::step` / `LtBSOffsetAnimationGenerator::generate`
     stored into the TLS profiler buffer at function ENTRY (the HK_TIMER_BEGIN macro, used by
     Havok AND Bethesda's hkbGenerator subclasses -- BS*/BGS* animation generators). The
     `Lt`/`Tt` prefix is the macro marker; the rest is the function's own qualified name, so
     the referencing function IS that method. Guarded to references within the first 0x80
     bytes (entry) to keep it to the timer-begin site.
  2. SELF-NAMING MESSAGE -- an assert/log string that LEADS with a qualified name then a
     message, e.g. `"BGSSaveLoadManager::CopySaveGamesFromHost failed to read ..."` or
     `"GFxDrawText::Display is called w/o ..."`. The leading identifier names the function.
  3. TELEMETRY SDK -- a bare qualified name from an SDK that logs each call's own name to a
     telemetry helper (`LEA arg,[name]; CALL log`). Gated to a namespace allowlist
     (TELEMETRY_NS, default `bnet` -- Bethesda.net UGC) so only known self-naming SDKs apply;
     this avoids mislabeling a bare type-name (`hkCachedHashMap::Elem`) as a function. NOTE:
     `bnet` exists in SE/AE only -- the VR build ships no bnet strings, so VR yields 0 here.

NON-DESTRUCTIVE: only renames functions still carrying a `FUN_/sub_/thunk_` placeholder
(never clobbers an established name). A name is applied only when a function maps to a
SINGLE consistent identifier AND that identifier maps to a single function in this program
(ambiguous strings -- e.g. two functions both referencing `EventLog::CollectLogData` -- are
reported, not guessed). Dry-run default; CLVR_RENAME=go to apply.

CROSS-VERSION: match is by STRING, not address -- the same debug string exists in SE/AE/VR,
so running this per program names the same function in each without any address mapping.
Run on each of SkyrimSE.exe / SkyrimSE.1170.exe / SkyrimVR.exe (File->Save after each;
symbols can't be saved from inside eval). See README and the populate cycle: a named,
typed anchor lets the next discovery pass resolve one level deeper.
"""
import os
import re
from collections import Counter

APPLY = os.environ.get('CLVR_RENAME', 'dry').lower() == 'go'
ENTRY_WINDOW = 0x80  # a timer-zone ref must sit within this many bytes of the function entry
# top-level namespaces whose bare qualified-name strings are self-naming telemetry labels
TELEMETRY_NS = set((os.environ.get('CLVR_RENAME_TELEMETRY_NS') or 'bnet').split(','))

# timer-zone label: [LT]t macro prefix + qualified name (the prefix guarantees a method, so
# no per-namespace or case restriction -- covers hk*, BS*/BGS* hkbGenerator subclasses, etc.).
_TIMER = re.compile(r'^[LT]t([A-Za-z_]\w*(?:::[A-Za-z_]\w*)+)$')
# self-naming message: a qualified C++ name, then whitespace, then a >=3-word message.
_LEAD = re.compile(r'^([A-Za-z_]\w*(?:::[A-Za-z_]\w*)+)\s+([A-Za-z].*)$')
# bare qualified name (telemetry tier; gated by TELEMETRY_NS).
_BARE = re.compile(r'^([A-Za-z_]\w*(?:::[A-Za-z_]\w*)+)$')


def _is_placeholder(name):
    return name.startswith('FUN_') or name.startswith('sub_') or name.startswith('thunk_FUN')


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


def _timer_name(s):
    if ' ' in s or len(s) > 80:
        return None
    m = _TIMER.match(s)
    return m.group(1) if m else None


def _message_name(s):
    if len(s) < 14:
        return None
    m = _LEAD.match(s)
    if not m:
        return None
    ident, msg = m.group(1), m.group(2)
    if ident.startswith('hk') or msg.count(' ') < 2 or len(ident.split('::')) > 3:
        return None
    return ident


def _telemetry_name(s):
    if ' ' in s or len(s) > 80:
        return None
    m = _BARE.match(s)
    if not m or m.group(1).split('::')[0] not in TELEMETRY_NS:
        return None
    return m.group(1)


def _collect(cp):
    """func entry -> set(candidate names) from all three patterns."""
    fm, listing, rm = cp.getFunctionManager(), cp.getListing(), cp.getReferenceManager()
    by_func = {}
    for d, s in _iter_strings(listing):
        timer = _timer_name(s)
        name = timer or _message_name(s) or _telemetry_name(s)
        if not name:
            continue
        for ref in rm.getReferencesTo(d.getAddress()):
            f = fm.getFunctionContaining(ref.getFromAddress())
            if f is None or not _is_placeholder(f.getName()):
                continue
            ep = f.getEntryPoint().getOffset()
            if timer and ref.getFromAddress().getOffset() - ep > ENTRY_WINDOW:
                continue                              # timer string must be at entry
            by_func.setdefault(ep, (f, set()))[1].add(name)
    return by_func


def _namespace(cp, st, parts):
    ns = cp.getGlobalNamespace()
    from ghidra.program.model.symbol import SourceType
    for part in parts:
        child = st.getNamespace(part, ns)
        if child is None:
            child = st.createNameSpace(ns, part, SourceType.USER_DEFINED)
        ns = child
    return ns


def run():
    from ghidra.program.model.symbol import SourceType
    cp = currentProgram  # noqa: F821
    st = cp.getSymbolTable()
    by_func = _collect(cp)

    # one consistent name per function, and that name unique across functions
    single = {ep: list(names)[0] for ep, (f, names) in by_func.items() if len(names) == 1}
    multi = {ep for ep, (f, names) in by_func.items() if len(names) > 1}
    counts = Counter(single.values())

    plan, ambiguous = [], set()
    for ep, name in single.items():
        if counts[name] > 1:
            ambiguous.add(name)
        else:
            plan.append((ep, name))
    for ep in multi:
        ambiguous.add('|'.join(sorted(by_func[ep][1])))

    applied = errors = 0
    tx = cp.startTransaction('string-anchored rename') if APPLY else None
    try:
        for ep, name in sorted(plan):
            f = by_func[ep][0]
            parts = name.split('::')
            if APPLY:
                try:
                    f.setParentNamespace(_namespace(cp, st, parts[:-1]))
                    f.setName(parts[-1], SourceType.USER_DEFINED)
                    applied += 1
                except Exception:
                    errors += 1
    finally:
        if tx is not None:
            cp.endTransaction(tx, True)

    print('string-anchored rename (%s): %s' % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN'))
    print('  %s=%d  errors=%d  ambiguous-skipped=%d'
          % ('renamed' if APPLY else 'would-rename', applied if APPLY else len(plan),
             errors, len(ambiguous)))
    for ep, name in sorted(plan)[:40]:
        print('   0x%X -> %s' % (ep, name))
    for a in sorted(ambiguous)[:10]:
        print('   AMBIGUOUS (skipped): %s' % a)
    if not APPLY:
        print('  set CLVR_RENAME=go to apply. Run per program; File->Save after.')


run()
