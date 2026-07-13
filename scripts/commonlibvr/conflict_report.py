"""CommonLibVR -> Ghidra type-conflict analyzer (read-only).

Runs INSIDE Ghidra (via the MCP eval_python, or the Script Manager) against the
target program. Reads a generated ``CommonLibImport_CLVR_*.py`` and compares every
struct it would create against the live DataTypeManager, WITHOUT writing anything.

The point: before applying the import we need to know which generated structs
collide with types the program already has (manual RE in /types.h, PDB-imported
types, auto stubs) and, for each collision, which definition is the "right" one so
the apply can reuse / upgrade / skip instead of blanket-REPLACE (which would create
parallel duplicate types and fragment the type system).

Classification per generated struct:
  NEW           - no same-named type exists            -> safe to create
  MATCH         - existing size == generated size      -> reuse existing, don't duplicate
  STUB_UPGRADE  - existing is an empty stub (<=1 byte / 0 members) -> safe to fill in place
  EXTENDS       - sizes differ but every existing defined member lines up inside the
                  generated layout (gen is a superset) -> safe to upgrade in place
  DIVERGENT     - sizes differ AND members disagree    -> NEEDS HUMAN REVIEW

"Which existing is correct" when a name exists in several categories: trust order
  /types.h (manual RE) > *.pdb (PDB import) > /Demangler,/auto_structs (auto) > other,
tie-broken by defined-member count.

Output: prints a summary and writes a CSV (default beside the import file:
``<import>.conflicts.csv``) with one row per generated struct so the conflicts can
be triaged in a spreadsheet. Override the import path / csv path via the module
globals IMPORT_PATH / CSV_PATH before exec, or the env vars CLVR_IMPORT / CLVR_CSV.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from layout_diff import (  # noqa: E402
    layout_diverges, auto_extract_score, _placeholder_typename as placeholder_typename,
    has_overlapping_fields, find_component_drift, verify_handcurated as _verify_handcurated_pure)

import ghidra.program.model.data as D

from clvr_config import IMPORT_PATH  # noqa: E402

CSV_PATH = os.environ.get('CLVR_CSV', IMPORT_PATH + '.conflicts.csv')


def _extract_list(text, var):
    """Return the python source of ``VAR = [ ... ]`` (bracket-balanced)."""
    start = text.find(var + ' = [')
    if start < 0:
        return None
    i = text.find('[', start)
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    return None


def _gen_namespace(category):
    """'/CommonLibSSE/RE' -> 'RE'; '/CommonLibSSE/DirectX/SimpleMath' ->
    'DirectX::SimpleMath'. The category encodes the C++ namespace."""
    parts = [p for p in category.strip('/').split('/') if p]
    if parts and parts[0] in ('CommonLibSSE', 'CommonLibVR'):
        parts = parts[1:]
    return '::'.join(parts)


# Existing-type categories that hold RE/global engine types (project convention
# puts manual RE in /types.h; PDB imports land in the *.pdb categories). A
# generated RE:: type may legitimately match any of these by leaf name.
_RE_CATS = ('/types.h', '/SkyrimSE.pdb', '/SkyrimVR.pdb', '/CommonLibVR.pdb',
            '/SkyrimAE.pdb', '/Demangler', '/auto_structs')


def _ns_compatible(gen_ns, existing_cat):
    """Is an existing type (by leaf name) plausibly the SAME FQN as the
    generated one? Avoids false collisions like RE::Color vs
    DirectX::SimpleMath::Color that merely share a leaf name."""
    if gen_ns in ('RE', ''):
        # RE engine types AND global/system C types (e.g. _LIST_ENTRY, _M128A) that
        # the generator buckets under /CommonLibSSE/RE. Match any existing same-name
        # type so we reuse it (incl. Windows/CRT header categories like /winnt.h)
        # instead of duplicating into /types.h. The SUSPICIOUS size-ratio guard in
        # classify() rejects accidental leaf-name collisions.
        return True
    # Non-RE generated namespace (DirectX, std, fmt, ...): require the existing
    # category to actually carry that namespace, else it's not the same type.
    return gen_ns.replace('::', '/') in existing_cat


def _trust(cat):
    if cat.startswith('/types.h'):
        return 3
    if '.pdb' in cat.lower():
        return 2
    if cat.startswith('/Demangler') or cat.startswith('/auto_structs'):
        return 1
    return 0


# NOTE: PDB is NOT treated as authoritative. For RE, a PDB is just an intake
# format for sharing data -- one source among several, no more trustworthy than
# CommonLib's generated per-runtime layout. Accuracy is only knowable from binary
# effects, so a genuine size disagreement against a PDB type is a plain DIVERGENT
# (default to the generated layout, logged for binary verification), not a
# protected status. Mechanical import corruption is handled separately by DOUBLED.


def _existing_members(dt):
    """[(offset, length, typename, fieldname)] for defined components."""
    out = []
    try:
        for c in dt.getDefinedComponents():
            cdt = c.getDataType()
            tn = cdt.getName() if cdt is not None else '?'
            out.append((c.getOffset(), c.getLength(), tn, c.getFieldName() or ''))
    except Exception:
        pass
    return out


def _has_bad(members):
    return any('-BAD-' in (m[3] or '') for m in members)


def _existing_vftable(dt, members):
    """Detect an existing vtable pointer at offset 0 (by field name or by a
    pointer to a *VFTable / *_vtbl type)."""
    for (o, ln, tn, fn) in members:
        if o != 0:
            continue
        nm = (fn or '').lower()
        if 'vftable' in nm or 'vtbl' in nm or 'vtable' in nm:
            return True
        t = (tn or '')
        if t.endswith('VFTable *') or t.endswith('_vtbl *') or 'VFTable' in t or t.endswith('_vtbl'):
            return True
    return False


def _embeds_base(dt):
    """True if the existing type's offset-0 member is an embedded polymorphic base
    class (a Structure whose own first member is a vftable pointer), e.g.
    NiNode { _base: NiAVObject; ... }. Replacing such a type with a flattened
    generated layout would discard the base-class composition, so we protect it."""
    try:
        comps = dt.getDefinedComponents()
    except Exception:
        return False
    if not comps:
        return False
    c0 = comps[0]
    if c0.getOffset() != 0:
        return False
    import ghidra.program.model.data as _D
    cdt = c0.getDataType()
    if not isinstance(cdt, _D.Structure):
        return False
    try:
        sub = cdt.getDefinedComponents()
    except Exception:
        return False
    if not sub:
        return False
    s0 = sub[0]
    s0n = (s0.getFieldName() or '').lower()
    return (isinstance(s0.getDataType(), _D.Pointer) and
            (s0.getOffset() == 0) and ('vf' in s0n or 'vtbl' in s0n or 'vtable' in s0n
             or (s0.getDataType().getName() or '').endswith('VFTable *')))


def _gen_vftable(gen_members, ghas_vt):
    if ghas_vt:
        return True
    for m in gen_members:
        t = str(m[1])
        if t.startswith('vtblptr:'):
            return True
        # an embedded base at offset 0 carries the (inherited) vtable, so the final
        # type still has a vptr there even though no top-level vtblptr field exists.
        if m[2] == 0 and t.startswith('struct:') and str(m[0]).startswith('_base'):
            return True
    return False


def _is_stub(dt, members):
    return dt.getLength() <= 1 or len(members) == 0


def _has_dup_fieldnames(members):
    """A struct with the SAME field name at more than one component is corrupt --
    an auto-extraction artifact that stacked repeated copies of a member (e.g.
    /auto_structs LODMode = index, singleLevel, singleLevel, index, index,
    singleLevel). A clean struct never repeats a field name."""
    names = [fn for (_o, _l, _t, fn) in members if fn]
    return len(names) != len(set(names))


def _gen_field_concrete(ftype_str):
    """A generated field whose type is a real composite (struct / enum / vtable-ptr, or
    an array of a non-primitive) -- worth placing over a placeholder. Plain primitives and
    u8/byte-array stubs are NOT (placing them is a no-op or a downgrade)."""
    ts = str(ftype_str)
    if ts.startswith('struct:') or ts.startswith('enum:') or ts.startswith('vtblptr:'):
        return True
    if ts.startswith('arr:'):
        elem = ts[4:].rsplit(':', 1)[0]
        return elem not in ('u8', 'u16', 'u32', 'u64', 's8', 's16', 's32', 's64', 'bool')
    return False


def _has_fillable_fields(emembers, gen_members):
    """True if a generated field has a concrete type at an offset where the existing
    struct only carries a placeholder (undefined / primitive / *_raw). This is the
    same-size-but-stale case that plain MATCH->REUSE silently leaves unimproved -- e.g. a
    BSTArray<T> stubbed as uint+padding by an import generated before that template
    instantiation existed. Improve-only: never flags a field where the existing type is
    already concrete (so a real layout is never downgraded to a generated stub)."""
    by_off = {o: (ln, tn, fn) for (o, ln, tn, fn) in emembers}
    for (fname, ftype, foff, fsize) in gen_members:
        if not _gen_field_concrete(ftype):
            continue
        e = by_off.get(foff)
        if e is None or placeholder_typename(e[1]) or (e[2] or '').endswith('_raw'):
            return True
    return False


def _extends(existing_members, gen_members, gen_size):
    """True if every existing defined member sits at a matching (offset,length)
    slot inside the generated layout, and gen is at least as large."""
    if not existing_members:
        return False
    # gen_members entries are (fname, ftype_str, foffset, fsize)
    gen_slots = set((m[2], m[3]) for m in gen_members)
    for (o, ln, _tn, _fn) in existing_members:
        if (o, ln) not in gen_slots:
            return False
    return True


def load_generated_structs(import_path=None):
    """eval the STRUCTS list out of a generated CommonLibImport_*.py."""
    with open(import_path or IMPORT_PATH, 'r') as f:
        text = f.read()
    structs_src = _extract_list(text, 'STRUCTS')
    if not structs_src:
        raise RuntimeError('STRUCTS list not found in ' + (import_path or IMPORT_PATH))
    return eval(structs_src)   # noqa: S307 (trusted generated file)


def build_live(dtm):
    """bare name -> [Structure DataType] index of the live program."""
    live = {}
    for dt in dtm.getAllDataTypes():
        if isinstance(dt, D.Structure):
            live.setdefault(dt.getName(), []).append(dt)
    return live


def scan_component_drift(dtm):
    """Walk every Structure in dtm and flag component-slot size drift (see
    layout_diff.find_component_drift's docstring) -- proactive detection for the
    "Field X does not fit in structure Y" corruption class that a bulk-apply
    resizing a widely-embedded type can leave behind in OTHER, untouched structs.

    Run this after any bulk-apply pass to catch the class of corruption before a
    user notices a GUI error. Returns the same tuple list find_component_drift
    does: (struct_path, field_name, offset, slot_length, current_type_length,
    struct_length).
    """
    components = []
    for dt in dtm.getAllDataTypes():
        if not isinstance(dt, D.Structure):
            continue
        for c in dt.getDefinedComponents():
            is_bf = c.isBitFieldComponent() if hasattr(c, 'isBitFieldComponent') else False
            ct = c.getDataType()
            components.append((
                dt.getPathName(), c.getFieldName(), c.getOffset(), c.getLength(),
                ct.getLength() if ct else -1, dt.getLength(), is_bf))
    return find_component_drift(components)


def verify_handcurated(st, c, drift_struct_paths=None):
    """Ghidra-side glue for layout_diff.verify_handcurated(): re-verify a struct
    classify() marked HANDCURATED, since that label only means "looks hand-curated
    by a naming heuristic" -- not "confirmed correct". See layout_diff.verify_handcurated
    for the concrete BSMultiBoundNode counterexample this closes.

    st: the generated struct tuple (as passed to classify()).
    c: the dict classify() returned for st (must have status == 'HANDCURATED';
       c['best'] is the existing Ghidra Structure).
    drift_struct_paths: optional set of struct getPathName() strings known to have
       component-slot drift (e.g. {d[0] for d in scan_component_drift(dtm)}) --
       if st's existing struct's path is in this set, treated as SUSPECT_OTHER.

    Returns (status, reason) same as layout_diff.verify_handcurated.
    """
    name, gsize, gcat, gfields, gbases, ghas_vt = st
    gen_members = [(fld[0], fld[1], fld[2], fld[3]) for fld in gfields
                   if not str(fld[1]).startswith('bf:')]
    best = c['best']
    existing_members = _existing_members(best)
    has_drift = bool(drift_struct_paths) and best is not None and \
        best.getPathName() in drift_struct_paths
    return _verify_handcurated_pure(existing_members, gen_members, c['existing_size'], gsize, has_drift)


def classify(st, live):
    """Classify one generated struct tuple against the live index.

    Returns dict: status, best (existing DataType or None), gen_size,
    existing_size, existing_category, n_existing_members, has_bad,
    existing_vftable, gen_vftable, auto_score. Single source of truth shared by
    the report and the apply.
    """
    name, gsize, gcat, gfields, gbases, ghas_vt = st
    gen_members = [(fld[0], fld[1], fld[2], fld[3]) for fld in gfields
                   if not str(fld[1]).startswith('bf:')]
    # layout_diverges() needs the bitfield members too (it now compares them by
    # name instead of by offset -- see its docstring) to avoid a false field-count
    # mismatch against `emembers`, which still has every real bitfield member.
    # The other consumers of `gen_members` below (_has_fillable_fields,
    # _gen_vftable) were never designed for 'bf:'-typed entries, so they keep the
    # filtered list.
    gen_members_with_bf = [(fld[0], fld[1], fld[2], fld[3]) for fld in gfields]
    gen_ns = _gen_namespace(gcat)

    # A generated field list with overlapping offset ranges means the extractor
    # flattened an anonymous C++ union (e.g. XMCOLOR's byte/uint views) into a
    # single tuple list -- there is no valid flat struct layout that satisfies it,
    # so no action (CREATE/FILL/REPLACE) can ever converge; every attempt "succeeds"
    # while changing nothing, permanently burning batch budget. Exclude these from
    # the eligible pool entirely rather than looping on them forever.
    if has_overlapping_fields(gen_members):
        cands0 = live.get(name)
        best0 = None
        if cands0:
            cands0 = [d for d in cands0 if _ns_compatible(gen_ns, d.getCategoryPath().getPath())]
            if cands0:
                best0 = sorted(cands0, key=lambda d: (_trust(d.getCategoryPath().getPath()),
                                                       d.getNumDefinedComponents()))[-1]
        return {'status': 'UNION_FLATTENED', 'best': best0, 'gen_size': gsize,
                'existing_size': best0.getLength() if best0 else None,
                'existing_category': best0.getCategoryPath().getPath() if best0 else '',
                'n_existing_members': len(_existing_members(best0)) if best0 else 0,
                'has_bad': False, 'existing_vftable': False,
                'gen_vftable': _gen_vftable(gen_members, ghas_vt), 'auto_score': None}

    cands = live.get(name)
    if cands:
        cands = [d for d in cands if _ns_compatible(gen_ns, d.getCategoryPath().getPath())]
    if not cands:
        return {'status': 'NEW', 'best': None, 'gen_size': gsize, 'existing_size': None,
                'existing_category': '', 'n_existing_members': 0, 'has_bad': False,
                'existing_vftable': False, 'gen_vftable': _gen_vftable(gen_members, ghas_vt),
                'auto_score': None}

    best = sorted(cands, key=lambda d: (_trust(d.getCategoryPath().getPath()),
                                        d.getNumDefinedComponents()))[-1]
    esize = best.getLength()
    emembers = _existing_members(best)
    e_vftbl = _existing_vftable(best, emembers)
    g_vftbl = _gen_vftable(gen_members, ghas_vt)
    auto = auto_extract_score(emembers)
    vftable_loss = e_vftbl and not g_vftbl
    handcurated = auto < 0.5 and len(emembers) >= 3

    # Drastic size ratio between same-leaf-name types almost always means they are
    # DIFFERENT types colliding on the leaf name (e.g. RE::BSJobs::JobList[8] vs a
    # 216-byte /types.h JobList), not one type at two runtime sizes. Real VR-vs-SE
    # deltas are well under 2x. Protect these from replacement.
    suspicious = (esize > 0 and gsize > 0 and
                  float(max(esize, gsize)) / min(esize, gsize) >= 4.0)

    # A low-trust auto-extracted struct with duplicate field names is corrupt; the
    # protect heuristics (suspicious / handcurated) must not shield it from the
    # authoritative generated layout. (Clean low-trust collisions -- a real type
    # sharing a leaf name -- have unique field names and stay protected.)
    corrupt_lowtrust = _trust(best.getCategoryPath().getPath()) <= 1 and \
        _has_dup_fieldnames(emembers)

    if gsize == 0:
        status = 'GEN_EMPTY'
    elif _is_stub(best, emembers) and esize == gsize:
        # An empty existing struct (no defined members) of the RIGHT size must be
        # FILLED in place, not reused. AE had pre-existing same-size stub shells; the
        # old `esize == gsize -> MATCH` check ran first and reused the empty stubs
        # (~16.9k structs left as undefined, e.g. Crime), so the CommonLib layout was
        # never applied. Same-size stub detection must precede MATCH (fill in place,
        # no resize -> the fast FILL action).
        status = 'STUB_FILL'
    elif esize == gsize and _has_fillable_fields(emembers, gen_members):
        # Same total size, but a populated existing struct still has placeholder fields
        # (undefined / primitive) where the generated layout has a concrete type -- e.g. a
        # BSTArray<T> stubbed as uint+padding by an import predating that template. Plain
        # MATCH->REUSE keeps the stale stubs forever (the BSShadowLight blind spot), so
        # route to the in-place FILL action. The fill is improve-only + comment-preserving,
        # so real existing fields and hand comments are never lost.
        status = 'STUB_FILL'
    elif esize == gsize and layout_diverges(emembers, gen_members_with_bf):
        # Same total size, but the internal layout genuinely disagrees at some
        # offset (not just a cosmetic name/typedef spelling difference) -- a size
        # match is NOT proof of a content match. Route to DIVERGENT so this gets
        # reviewed/reapplied instead of being silently protected forever.
        status = 'DIVERGENT'
    elif esize == gsize:
        status = 'MATCH'
    elif _is_stub(best, emembers):
        # empty stub of the WRONG size -> resize + fill via stage/replaceDataType.
        status = 'STUB_UPGRADE'
    elif _extends(emembers, gen_members, gsize):
        status = 'EXTENDS'
    elif vftable_loss:
        status = 'VFTABLE_LOSS'
    elif esize == 2 * gsize:
        # existing is EXACTLY double the generated size -- a Ghidra import doubling
        # artifact (pointer/alignment), not a real layout difference. Seen on
        # system/DirectX types (_GUID 32 vs 16, XMDEC4 8 vs 4). The generated
        # clang size is correct; replace even over HANDCURATED/PDB/EMBED guards.
        # (Ordered after VFTABLE_LOSS so a vtable is never dropped.)
        status = 'DOUBLED'
    elif corrupt_lowtrust:
        # corrupt auto-extracted existing -> default to the generated layout.
        status = 'DIVERGENT'
    elif suspicious:
        status = 'SUSPICIOUS'
    elif _embeds_base(best):
        # existing uses compositional base embedding; replacing with a flattened
        # generated layout would discard that. Keep + review.
        status = 'EMBED_BASE'
    elif handcurated:
        status = 'HANDCURATED'
    else:
        status = 'DIVERGENT'
    return {'status': status, 'best': best, 'gen_size': gsize, 'existing_size': esize,
            'existing_category': best.getCategoryPath().getPath(),
            'n_existing_members': len(emembers), 'has_bad': _has_bad(emembers),
            'existing_vftable': e_vftbl, 'gen_vftable': g_vftbl, 'auto_score': auto}


def run():
    STRUCTS = load_generated_structs()
    print('Parsed {} generated structs from {}'.format(len(STRUCTS), os.path.basename(IMPORT_PATH)))

    dtm = currentProgram.getDataTypeManager()  # noqa: F821
    live = build_live(dtm)

    rows = []
    counts = {'NEW': 0, 'MATCH': 0, 'STUB_FILL': 0, 'STUB_UPGRADE': 0, 'EXTENDS': 0,
              'GEN_EMPTY': 0, 'DIVERGENT': 0, 'VFTABLE_LOSS': 0, 'HANDCURATED': 0}
    div_dir = {'gen_larger': 0, 'gen_smaller': 0}
    for st in STRUCTS:
        c = classify(st, live)
        status = c['status']
        counts[status] = counts.get(status, 0) + 1
        if status == 'DIVERGENT':
            div_dir['gen_larger' if c['gen_size'] > c['existing_size'] else 'gen_smaller'] += 1
        rows.append((st[0], status, c['gen_size'],
                     '' if c['existing_size'] is None else c['existing_size'],
                     c['existing_category'], c['n_existing_members'],
                     'BAD' if c['has_bad'] else '',
                     'E' if c['existing_vftable'] else '-',
                     'G' if c['gen_vftable'] else '-',
                     '' if c['auto_score'] is None else '%.2f' % c['auto_score'],
                     ''))

    # CSV
    try:
        with open(CSV_PATH, 'w') as out:
            out.write('name,status,gen_size,existing_size,existing_category,'
                      'existing_nmembers,has_bad,existing_vftable,gen_vftable,'
                      'auto_extract_score,n_categories\n')
            for r in rows:
                out.write(','.join(str(x) for x in r) + '\n')
        print('Wrote conflict report: {}'.format(CSV_PATH))
    except Exception as e:
        print('CSV write failed:', e)

    total = len(STRUCTS)
    print('\n=== conflict summary ({} generated structs) ==='.format(total))
    for k in ('NEW', 'MATCH', 'GEN_EMPTY', 'STUB_FILL', 'STUB_UPGRADE', 'EXTENDS',
              'DIVERGENT', 'DOUBLED', 'HANDCURATED', 'VFTABLE_LOSS',
              'SUSPICIOUS', 'EMBED_BASE'):
        print('  {:13s} {}'.format(k, counts.get(k, 0)))
    print('\nWRITE (create new / fill-stub / extend / replace-divergent): {}'.format(
        counts['NEW'] + counts['STUB_UPGRADE'] + counts['EXTENDS'] + counts['DIVERGENT']))
    print('REUSE existing untouched (match / gen-empty): {}'.format(
        counts['MATCH'] + counts['GEN_EMPTY']))
    print('PROTECT - keep existing, do NOT auto-replace (review): HANDCURATED={}, VFTABLE_LOSS={}, SUSPICIOUS={}'.format(
        counts.get('HANDCURATED', 0), counts.get('VFTABLE_LOSS', 0), counts.get('SUSPICIOUS', 0)))
    print('DIVERGENT (auto-extracted existing, safe to replace): {}  (gen_larger={}, gen_smaller={})'.format(
        counts['DIVERGENT'], div_dir['gen_larger'], div_dir['gen_smaller']))
    for label in ('VFTABLE_LOSS', 'HANDCURATED', 'SUSPICIOUS'):
        ex = [r for r in rows if r[1] == label][:20]
        if ex:
            print('\n--- {} (name, gen, existing, cat, nmembers, eVf, gVf, auto) ---'.format(label))
            for r in ex:
                print('  {} gen={} existing={} {} m={} vf={}/{} auto={}'.format(
                    r[0], r[2], r[3], r[4], r[5], r[7], r[8], r[9]))
    return counts


# Auto-run when exec'd directly in Ghidra. The apply tool exec's this module with
# AUTORUN=False pre-seeded to import classify()/build_live() without running.
if globals().get('AUTORUN', True):
    run()
