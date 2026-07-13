"""CommonLibVR -> Ghidra ENRICH-ONLY apply (conflict-aware, non-destructive).

Runs INSIDE Ghidra against the target program. Reads a generated
``CommonLibImport_CLVR_*.py`` and applies its types using the per-type policy from
conflict_report.classify(), instead of the generated script's blanket
REPLACE-everything behaviour:

  NEW          -> create in /types.h
  MATCH        -> reuse existing type (register, no write)
  GEN_EMPTY    -> keep existing (CommonLibVR opaque, no write)
  STUB_UPGRADE -> replaceDataType (fill empty stub)
  EXTENDS      -> replaceDataType (generated is a superset)
  DIVERGENT    -> replaceDataType (generated = validated VR layout; existing is
                  auto-extracted SE-sized)
  HANDCURATED  -> PROTECT: keep existing, never overwrite (listed for review)
  VFTABLE_LOSS -> PROTECT: keep existing (replace would drop a vtable pointer)

replaceDataType() rewires every reference and leaves function signatures intact
(the type identity is swapped, params/returns preserved).

SAFETY: DRY_RUN is the default. It writes NOTHING to the program and emits an
apply-plan CSV + summary. To actually apply, set env CLVR_APPLY=go.

  Dry-run:  exec this file in Ghidra (default)              -> plan only
  Apply:    set os.environ['CLVR_APPLY']='go' then exec     -> writes types
"""
import os
import sys

from ghidra.program.model.data import (
    StructureDataType, CategoryPath, DataTypeConflictHandler)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from layout_diff import plan_cascade_fix  # noqa: E402
from clvr_config import IMPORT_PATH, SCRIPT_DIR, TYPES_CAT  # noqa: E402

CONFLICT_REPORT = os.path.join(SCRIPT_DIR, 'conflict_report.py')
PLAN_CSV = os.environ.get('CLVR_PLAN', IMPORT_PATH + '.apply_plan.csv')
NEW_CAT = TYPES_CAT
STAGING_CAT = '/CommonLibVR_staging'
# See the long comment in _stage_struct() / apply_cascade_fix() for why staged
# replacements are named this way instead of the final target name directly.
_STAGE_RENAME_SUFFIX = '__pending_rename__'

DRY_RUN = os.environ.get('CLVR_APPLY', 'dry').lower() != 'go'

# Batching/coordination for a live apply run (see select_write_targets in apply_plan.py):
#   CLVR_APPLY_EXCLUDE -- comma-separated struct names to always skip this run (e.g.
#                         owned by concurrent manual clone-then-replace work).
#   CLVR_APPLY_MAX     -- caps how many write-actioned (CREATE/FILL/REPLACE) structs
#                         get applied in this call; 0 = unlimited. The plan/CSV/summary
#                         always reflect the FULL, uncapped classification -- only the
#                         actual write phase is capped. Safe to re-run repeatedly with
#                         the same cap to drain a backlog (see select_write_targets doc).
#   CLVR_APPLY_PRIORITIZE -- an existing_category (e.g. '/types.h') to drain first
#                         within a capped batch, ahead of everything else. Default
#                         '/types.h' since CommonLib's own std/fmt/REX namespaces
#                         generate a large volume of low-RE-value template-instantiation
#                         noise that would otherwise dilute a capped batch's budget away
#                         from curated, genuinely useful RE progress. Set to '' to disable
#                         (falls back to plain plan order, matching pre-existing behavior).
APPLY_EXCLUDE = set(
    n.strip() for n in os.environ.get('CLVR_APPLY_EXCLUDE', '').split(',') if n.strip())
APPLY_MAX = int(os.environ.get('CLVR_APPLY_MAX', '0') or 0)
APPLY_PRIORITIZE = os.environ.get('CLVR_APPLY_PRIORITIZE', '/types.h')

# Pure planning logic (no Ghidra deps) loaded by path so it works under MCP exec.
import importlib.util as _ilu  # noqa: E402
_ap_spec = _ilu.spec_from_file_location('clvr_apply_plan', os.path.join(SCRIPT_DIR, 'apply_plan.py'))
apply_plan = _ilu.module_from_spec(_ap_spec)
_ap_spec.loader.exec_module(apply_plan)
ACTION = apply_plan.ACTION
select_fill_targets = apply_plan.select_fill_targets

# dedup.purge_conflicts is reused at the end of an apply so a run never leaves
# .conflict copies behind (one canonical type always). AUTORUN=False keeps importing
# it from triggering dedup's own full run.
_dd_spec = _ilu.spec_from_file_location('clvr_dedup', os.path.join(SCRIPT_DIR, 'dedup.py'))
clvr_dedup = _ilu.module_from_spec(_dd_spec)
clvr_dedup.AUTORUN = False
_dd_spec.loader.exec_module(clvr_dedup)


def _load_generated_ns():
    """exec the generated import file WITHOUT its trailing run() so we get its
    data (ENUMS/STRUCTS/VTABLES/SYMBOLS) and helpers (resolve_type/created/dtm).
    """
    with open(IMPORT_PATH, 'r') as f:
        text = f.read()
    cut = text.rfind('\nrun()')
    if cut < 0:
        raise RuntimeError('could not find trailing run() to strip')
    body = text[:cut]
    gns = dict(globals())             # inherit flat API
    gns.update(_ghidra_globals())     # currentProgram/monitor are name-injected, not in globals()
    exec(compile(body, IMPORT_PATH, 'exec'), gns)
    return gns


def _load_classifier():
    cns = dict(globals())
    cns.update(_ghidra_globals())
    cns['AUTORUN'] = False
    exec(compile(open(CONFLICT_REPORT).read(), CONFLICT_REPORT, 'exec'), cns)
    return cns


def _ghidra_globals():
    """currentProgram/monitor are injected as names by pyghidra but are not keys
    in globals(); collect the ones the generated/report code reads."""
    g = {}
    for nm in ('currentProgram', 'monitor', 'state', 'currentAddress',
               'createFunction', 'createLabel', 'getCurrentProgram'):
        try:
            g[nm] = eval(nm)
        except Exception:
            pass
    return g


def run():
    gns = _load_generated_ns()
    cns = _load_classifier()
    classify = cns['classify']
    build_live = cns['build_live']

    dtm = gns['dtm']
    resolve_type = gns['resolve_type']
    make_padding = gns['make_padding']
    created = gns['created']
    STRUCTS = gns['STRUCTS']
    ENUMS = gns['ENUMS']
    VTABLES = gns['VTABLES']
    _U8 = gns['_BYTE']; _U16 = gns['_U16']; _U32 = gns['_U32']; _U64 = gns['_U64']
    KEEP = DataTypeConflictHandler.KEEP_HANDLER

    live = build_live(dtm)

    # ---- decide an action for every generated struct ----
    plan = []          # (name, status, action, gen_size, existing_size, category)
    counts = {}
    for st in STRUCTS:
        name = st[0]
        c = classify(st, live)
        status = c['status']
        action = ACTION.get(status, 'PROTECT')
        counts[action] = counts.get(action, 0) + 1
        plan.append((name, status, action, c['gen_size'], c['existing_size'],
                     c['existing_category']))

    # ---- always: write the plan CSV + summary (no program writes here) ----
    try:
        with open(PLAN_CSV, 'w') as out:
            out.write('name,status,action,gen_size,existing_size,existing_category\n')
            for p in plan:
                out.write(','.join('' if x is None else str(x) for x in p) + '\n')
        print('Wrote apply plan: {}'.format(PLAN_CSV))
    except Exception as e:
        print('plan CSV write failed:', e)

    print('\n=== apply plan ({} structs) ==='.format(len(STRUCTS)))
    for a in ('CREATE', 'FILL', 'REUSE', 'REPLACE', 'PROTECT'):
        print('  {:9s} {}'.format(a, counts.get(a, 0)))
    print('  (+ {} enums, {} vtable structs to create/reuse)'.format(len(ENUMS), len(VTABLES)))
    prot = [p for p in plan if p[2] == 'PROTECT']
    if prot:
        print('\n--- PROTECT (kept as-is, NOT overwritten) ---')
        for p in prot[:30]:
            print('  {} [{}] gen={} existing={} {}'.format(p[0], p[1], p[3], p[4], p[5]))
    rep = [p for p in plan if p[2] == 'REPLACE']
    print('\n--- REPLACE sample (existing -> generated VR layout) ---')
    for p in rep[:15]:
        print('  {} [{}] {} -> {}  ({})'.format(p[0], p[1], p[4], p[3], p[5]))

    if DRY_RUN:
        print('\nDRY_RUN: no changes written. Set env CLVR_APPLY=go to apply.')
        return counts

    # ---- batching/exclude gate: decide which write-actioned structs actually get
    # applied THIS call, without altering the full plan/summary computed above ----
    write_allowed = apply_plan.select_write_targets(
        plan, APPLY_EXCLUDE, APPLY_MAX, prioritize_category=APPLY_PRIORITIZE or None)
    if APPLY_EXCLUDE or APPLY_MAX:
        n_write_total = sum(1 for p in plan if p[2] in ('CREATE', 'FILL', 'REPLACE'))
        print('\nBatch gate: {} write-actioned structs total, excluding {}, '
              'applying {} this call (CLVR_APPLY_MAX={})'.format(
                  n_write_total, sorted(APPLY_EXCLUDE) or '(none)',
                  len(write_allowed), APPLY_MAX or 'unlimited'))

    def classify(st, live, _real_classify=classify):
        c = _real_classify(st, live)
        name = st[0]
        action = ACTION.get(c['status'], 'PROTECT')
        if action in ('CREATE', 'FILL', 'REPLACE') and name not in write_allowed:
            c = dict(c)
            c['status'] = 'BATCH_SKIPPED'
        return c

    # =========================== APPLY ===========================
    print('\n*** APPLYING (CLVR_APPLY=go) ***')
    tx = dtm.startTransaction('CommonLibVR enrich apply')
    try:
        # Phase 1: register created[] target for every struct + enum + vtable.
        # REUSE/PROTECT -> existing dt; CREATE -> shell in /types.h; REPLACE ->
        # staging shell (filled later, then swapped via replaceDataType).
        _gen_namespace = cns['_gen_namespace']

        def _create_struct(name, size, gcat):
            # Keep /types.h for our (RE) types only; route library/system NEW types
            # (std, DirectX, REX, global, ...) to their own generated category.
            ns = _gen_namespace(gcat)
            cat = NEW_CAT if (ns == 'RE' or ns.startswith('RE::')) else gcat
            return dtm.addDataType(StructureDataType(CategoryPath(cat), name, size), KEEP)

        def _stage_struct(name, size, _existing):
            # Stage under a temporary distinct name, then rename back to `name`
            # after replaceDataType() commits (see the Phase 3 swap loop below).
            # Observed this session: staging a replacement under the EXACT SAME
            # name as the type being replaced could make dtm.replaceDataType()
            # report success -- correct new size visible for the rest of that
            # same script run, currentProgram.isChanged() True -- but silently
            # fail to persist: a genuinely separate, later eval_python call
            # showed the struct reverted to its old definition, with no pending
            # transaction, no available undo, and no .conflict duplicate
            # anywhere in the DataTypeManager. Root cause not fully understood;
            # reproduced concretely for BSCullingProcess (a 312->197112 byte
            # resize) but NOT for most other same-session same-name replaces,
            # so this isn't known to be universal -- staging under a temp name
            # then renaming after the swap sidesteps it unconditionally, at the
            # cost of one extra setName() call, and was verified reliable
            # across 4 chained fixes (BSCullingProcess, LocalMapCullingProcess,
            # LocalMapMenu, MapMenu) in the same session.
            sdt = StructureDataType(CategoryPath(STAGING_CAT), name + _STAGE_RENAME_SUFFIX, size)
            return dtm.addDataType(sdt, DataTypeConflictHandler.REPLACE_HANDLER)

        def _register(st, dt):
            name, gcat = st[0], st[2]
            ns_alias = '::'.join(gcat.strip('/').split('/')[1:])
            created[name] = dt
            created[gcat + '/' + name] = dt
            if ns_alias:
                created[ns_alias + '::' + name] = dt

        # fill_list/staging are tracked at creation time (NOT re-derived from
        # created[], which the enum pass below also writes to) -- see apply_plan.
        fill_list, staging = select_fill_targets(
            STRUCTS, classify, live, _create_struct, _stage_struct, register=_register)

        # enums: conflict-aware + parent-scoped (apply_plan). NEW->create;
        # MATCH->reuse; EXTEND->add missing values to existing (lossless); size
        # diff->keep existing (no repack). All three name aliases registered so
        # struct fields referencing an enum by full name resolve.
        EnumDataType = gns['EnumDataType']
        import ghidra.program.model.data as _D
        live_enum = {}
        for d in dtm.getAllDataTypes():
            if isinstance(d, _D.Enum):
                live_enum.setdefault(apply_plan.enum_parent_key(
                    d.getCategoryPath().getPath(), d.getName()), d)

        def _register_enum(ename, ecat, dt):
            created[ename] = dt
            created[ecat + '/' + ename] = dt
            ns = '::'.join(ecat.strip('/').split('/')[1:])
            if ns:
                created[ns + '::' + ename] = dt

        enum_stats = {'NEW': 0, 'MATCH': 0, 'EXTEND': 0, 'KEEP_SIZE': 0}
        for en in ENUMS:
            ename, esize, ecat, evals = en
            ex = live_enum.get(apply_plan.enum_parent_key(ecat, ename))
            ex_size = ex.getLength() if ex is not None else None
            ex_names = list(ex.getNames()) if ex is not None else []
            action, add_vals = apply_plan.classify_enum(esize, evals, ex_size, ex_names)
            enum_stats[action] = enum_stats.get(action, 0) + 1
            if action == 'NEW':
                e = EnumDataType(CategoryPath(NEW_CAT), ename, esize)
                for vname, vval in evals:
                    try:
                        e.add(vname, vval)
                    except Exception:
                        try:
                            e.add(vname + '_', vval)
                        except Exception:
                            pass
                dt = dtm.addDataType(e, KEEP)
            else:
                dt = ex
                if action == 'EXTEND':
                    for vname, vval in add_vals:
                        try:
                            ex.add(vname, vval)
                        except Exception:
                            pass
            _register_enum(ename, ecat, dt)
        print('Enums: ' + ', '.join('{}={}'.format(k, v) for k, v in enum_stats.items()))

        # vtable structs (NEW names like X_vtbl) -> create in /types.h
        _create_vtable_structs(gns, dtm, NEW_CAT)

        # Phase 2: fill fields for the shells WE created/staged (tracked explicitly
        # in fill_list, so an enum sharing a struct's name can't redirect us).
        # A generated struct whose leaf name is taken by an existing ENUM in the
        # target category classifies NEW (build_live indexes only structs), but the
        # KEEP-handler addDataType then returns that enum instead of a new struct.
        # Skip those -- the name is owned by a non-struct, so there is nothing to fill.
        import ghidra.program.model.data as _Dfill
        _skipped_nonstruct = 0
        for s, st in fill_list:
            if not isinstance(s, _Dfill.Structure):
                _skipped_nonstruct += 1
                continue
            _gsize, _gfields = st[1], st[3]
            _fill_struct(s, _gsize, _gfields, resolve_type, make_padding,
                         _U16, _U32, _U64, _U8)
        if _skipped_nonstruct:
            print('Skipped {} fill targets owned by a non-struct '
                  '(enum/typedef leaf-name collision)'.format(_skipped_nonstruct))

        # Phase 3: swap each staged replacement in for the existing type (rewires
        # all refs; function signatures preserved). updateCategoryPath=True moves
        # the staged type into the existing type's category and removes existing.
        swapped = 0
        for name, (sdt, existing) in staging.items():
            existing_cat = existing.getCategoryPath()
            try:
                dtm.replaceDataType(existing, sdt, True)
                # Re-fetch fresh rather than reusing `sdt` -- Ghidra's own
                # object identity across a replaceDataType() swap isn't
                # guaranteed stable, and the live post-swap type may be a
                # different Java instance than the one we staged with.
                live = dtm.getDataType(existing_cat, name + _STAGE_RENAME_SUFFIX)
                if live is not None:
                    live.setName(name)
                else:
                    print('post-swap rename target not found for {}'.format(name))
                swapped += 1
            except Exception as e:
                print('replace failed for {}: {}'.format(name, e))
        print('Replaced {} existing types via replaceDataType'.format(swapped))
    finally:
        dtm.endTransaction(tx, True)
    print('Type enrich-apply complete. (symbols/vtable-names are a separate pass)')

    # Always collapse any .conflict copies this (or a prior) run produced onto their
    # canonical twin -- the apply must never leave a duplicated conflict state behind.
    if not DRY_RUN:
        try:
            cp = gns.get('currentProgram') or _ghidra_globals().get('currentProgram')
            mon = _ghidra_globals().get('monitor')
            clvr_dedup.purge_conflicts(cp, dtm, True, mon)
        except Exception as e:
            print('purge_conflicts failed:', e)
    return counts


def _is_placeholder_dt(dt):
    """A field type that carries no real RE -- undefined bytes or a bare integer/char
    filler. Improve-only fills replace ONLY these; a concrete existing type is never
    downgraded to a generated stub."""
    if dt is None:
        return True
    n = dt.getName()
    return (n in ('undefined', 'uint', 'int', 'byte', 'sbyte', 'ushort', 'short',
                  'ulong', 'long', 'ulonglong', 'longlong')
            or n.startswith('undefined') or n.startswith('char['))


def _fill_struct(s, size, gfields, resolve_type, make_padding, _U16, _U32, _U64, _U8):
    for field in gfields:
        fname, ftype_str, foffset, fsize = field
        if str(ftype_str).startswith('bf:'):
            parts = ftype_str.split(':')
            bit_off = int(parts[1]); width = int(parts[2])
            bw = 4; base = _U32
            for _bw, _bd in [(1, _U8), (2, _U16), (4, _U32), (8, _U64)]:
                bits = _bw * 8
                sb = (bit_off // bits) * _bw
                if bit_off % bits + width <= bits and sb + _bw <= size:
                    bw = _bw; base = _bd; break
            storage = (bit_off // (bw * 8)) * bw
            in_storage = bit_off % (bw * 8)
            try:
                s.insertBitFieldAt(storage, bw, in_storage, base, width, fname, '')
            except Exception:
                pass
            continue
        if fsize <= 0 or foffset + fsize > size:
            continue
        comp = s.getComponentContaining(foffset)
        cur = comp.getDataType() if comp else None
        at_start = comp is not None and comp.getOffset() == foffset
        # Improve-only: never clobber a concrete existing field. (On an empty stub every
        # slot is undefined, so this still fills the whole struct; on a same-size-but-stale
        # struct it touches only the placeholder slots and keeps real fields + comments.)
        if at_start and cur is not None and not _is_placeholder_dt(cur):
            continue
        dtf = resolve_type(ftype_str)
        if dtf and dtf.getLength() == fsize:
            use_dt, use_name = dtf, fname
        else:
            # generated type didn't resolve to a concrete same-size type -> a stub; don't
            # write padding over a real field (only fill genuinely-empty slots).
            if at_start and cur is not None and not _is_placeholder_dt(cur):
                continue
            use_dt, use_name = make_padding(fsize), fname + '_raw'
        cmt = comp.getComment() if at_start else None      # preserve any hand comment
        try:
            s.replaceAtOffset(foffset, use_dt, fsize, use_name, cmt or '')
        except Exception:
            pass


def apply_cascade_fix(dtm, struct_name, category_path=NEW_CAT):
    """Fix ONE named struct's component-slot drift (see
    layout_diff.find_component_drift / plan_cascade_fix): a field embeds
    another type as a fixed-size component whose CURRENT length no longer
    matches the component's frozen slot length, because that referenced type
    was legitimately resized elsewhere. Widens/shrinks the drifted slot and
    shifts every subsequent field by the same delta.

    Deliberately scoped to a single, explicitly-named struct per call -- this
    does NOT scan the whole DataTypeManager or recurse into further cascades
    it might create. A caller that wants to fix a chain of structs must call
    this once per struct, explicitly, so the specific set of touched types is
    always a deliberate, reviewable choice rather than an open-ended sweep.

    Only handles the SIMPLE case (exactly one drifted component) -- see
    plan_cascade_fix. Returns without mutating anything if the case isn't
    simple, or if the struct doesn't exist / has no drift.

    Returns a dict: {"struct": name, "fixed": bool, "old_size": int|None,
    "new_size": int|None, "drifted_field": str|None, "reason": str|None}.
    """
    cat = CategoryPath(category_path)
    existing = dtm.getDataType(cat, struct_name)
    if existing is None:
        return {"struct": struct_name, "fixed": False, "old_size": None,
                "new_size": None, "drifted_field": None,
                "reason": "no such struct in category {}".format(category_path)}

    old_len = existing.getLength()
    components = []
    for c in existing.getDefinedComponents():
        is_bf = c.isBitFieldComponent() if hasattr(c, 'isBitFieldComponent') else False
        ct = c.getDataType()
        components.append((c.getFieldName(), c.getOffset(), c.getLength(),
                            ct.getLength() if ct else -1, is_bf))

    plan = plan_cascade_fix(components, old_len)
    if not plan["simple"]:
        return {"struct": struct_name, "fixed": False, "old_size": old_len,
                "new_size": None, "drifted_field": None, "reason": plan["reason"]}

    delta = plan["delta"]
    drifted_offset = plan["offset"]
    new_len = plan["new_struct_length"]

    # Snapshot every original component's (name, dtype, length, offset) before
    # building the replacement -- getDefinedComponents() objects go stale once
    # we start mutating a different Structure instance.
    orig = [(c.getFieldName(), c.getDataType(), c.getLength(), c.getOffset())
            for c in existing.getDefinedComponents()]

    # Stage under a temporary distinct name rather than `struct_name` directly,
    # then rename back after the swap commits -- see the matching comment in
    # _stage_struct() in run() above for why. Same-name staging was observed
    # to silently fail to persist for at least one large struct this session
    # (BSCullingProcess) despite reporting success within the same call.
    temp_name = struct_name + _STAGE_RENAME_SUFFIX
    sdt = StructureDataType(CategoryPath(STAGING_CAT), temp_name, new_len)
    for fname, fdt, flen, foff in orig:
        new_off = foff if foff <= drifted_offset else foff + delta
        new_flen = plan["new_slot"] if foff == drifted_offset else flen
        sdt.replaceAtOffset(new_off, fdt, new_flen, fname, "")

    staged = dtm.addDataType(sdt, DataTypeConflictHandler.REPLACE_HANDLER)
    dtm.replaceDataType(existing, staged, True)

    # Re-fetch fresh rather than reusing `staged` -- object identity across
    # the swap isn't guaranteed stable.
    live = dtm.getDataType(cat, temp_name)
    if live is not None:
        live.setName(struct_name)

    fresh = dtm.getDataType(cat, struct_name)
    return {"struct": struct_name, "fixed": True, "old_size": old_len,
            "new_size": fresh.getLength() if fresh else new_len,
            "drifted_field": plan["drifted_field"], "reason": None}


def _create_vtable_structs(gns, dtm, cat):
    """Mirror the generated _import_types vtable-struct creation, targeting `cat`
    and only creating ones that don't already exist (KEEP handler)."""
    StructureDataType_ = gns['StructureDataType']
    FunctionDefinitionDataType = gns['FunctionDefinitionDataType']
    ParameterDefinitionImpl = gns['ParameterDefinitionImpl']
    CategoryPath_ = gns['CategoryPath']
    resolve_type = gns['resolve_type']
    created = gns['created']
    _PTR = gns['_PTR']
    KEEP = DataTypeConflictHandler.KEEP_HANDLER
    for vt in gns['VTABLES']:
        vname, class_full_name, vtbl_size, category, slots = vt
        s = StructureDataType_(CategoryPath_(cat), vname, vtbl_size)
        for slot_off, slot_name, slot_ret, slot_params in slots:
            field_name = slot_name.replace('~', '_dtor_') if slot_name.startswith('~') else slot_name
            if slot_off + 8 > vtbl_size:
                continue
            try:
                if slot_ret is not None and slot_params is not None:
                    fdef = FunctionDefinitionDataType(CategoryPath_(cat), field_name + '_t', dtm)
                    ret_dt = resolve_type(slot_ret)
                    if ret_dt:
                        fdef.setReturnType(ret_dt)
                    if slot_params:
                        pdefs = []
                        for pname, ptype in slot_params:
                            pdefs.append(ParameterDefinitionImpl(pname, resolve_type(ptype) or _PTR, ''))
                        fdef.setArguments(pdefs)
                    fptr = dtm.getPointer(dtm.addDataType(fdef, KEEP), 8)
                    s.replaceAtOffset(slot_off, fptr, 8, field_name, '')
                else:
                    s.replaceAtOffset(slot_off, _PTR, 8, field_name, '')
            except Exception:
                pass
        created['vtbl:' + vname] = dtm.addDataType(s, KEEP)


def _upgrade_sig(f):
    """True if it is safe to overwrite this function's signature with CommonLib's.

    Upgrade when the current signature is auto-derived -- either absent
    (DefaultDataType / undefined return) or inferred by Ghidra's analyzer
    (signature source DEFAULT or ANALYSIS). NEVER touch a USER_DEFINED or
    IMPORTED (PDB) signature: those are hand-curated or authoritative, and a
    generated CommonLib prototype must not clobber them.
    """
    from ghidra.program.model.symbol import SourceType
    try:
        src = f.getSignatureSource()
        if src in (SourceType.USER_DEFINED, SourceType.IMPORTED):
            return False
        return True   # DEFAULT / ANALYSIS -> auto-inferred, safe to upgrade
    except Exception:
        # Fall back to the return-type heuristic if source is unavailable.
        try:
            rt = f.getSignature().getReturnType()
            return rt.getClass().getSimpleName() == 'DefaultDataType' or \
                (rt.getName() or '').startswith('undefined')
        except Exception:
            return True


def _safe_eol_comment(cu, text):
    """Set the EOL comment only if empty; otherwise prepend our line(s) without
    clobbering an existing (possibly manual) comment."""
    if cu is None:
        return
    existing = cu.getComment(0)
    if not existing:
        cu.setComment(0, text)
    elif text.split('\n')[0] not in existing:
        cu.setComment(0, text + '\n' + existing)


def run_symbols():
    """Enrich-safe symbol + vtable pass (separate from the types pass):
      - apply VTABLE_/RTTI_ labels (additive),
      - name functions ONLY where currently FUN_/sub_ (never clobber a real name),
      - set EOL comments only if absent (prepend, never overwrite),
      - apply CommonLib signatures ONLY to functions that have none,
      - then the generated (already enrich-safe) vtable virtual-function naming +
        fallback symbol passes.
    """
    from ghidra.program.model.symbol import SourceType
    from ghidra.app.cmd.disassemble import DisassembleCommand
    gns = _load_generated_ns()
    dtm = gns['dtm']
    created = gns['created']
    SYMBOLS = gns['SYMBOLS']
    VERSION = gns['VERSION']
    apply_structured_sig = gns['apply_structured_sig']
    create_function = gns.get('createFunction')
    cp = gns['currentProgram']
    fm = cp.getFunctionManager()
    stt = cp.getSymbolTable()
    base = cp.getImageBase()
    listing = cp.getListing()

    # Rebuild created[] from the LIVE (already type-applied) program so signature
    # type references resolve without recreating anything.
    live = {}
    for dt in dtm.getAllDataTypes():
        live.setdefault(dt.getName(), dt)
    for st in gns['STRUCTS']:
        if st[0] in live:
            created[st[0]] = live[st[0]]
    for en in gns['ENUMS']:
        if en[0] in live:
            created[en[0]] = live[en[0]]
    for vt in gns['VTABLES']:
        if vt[0] in live:
            created['vtbl:' + vt[0]] = live[vt[0]]

    vkey = {'svr': 'v', 'se': 's', 'ae': 'a'}.get(VERSION, 'a')

    def relid(s):
        si, ai = s.get('si'), s.get('ai')
        if si and ai:
            return 'RELOCATION_ID(%d, %d)' % (si, ai)
        if si:
            return 'REL::ID(%d)' % si
        if ai:
            return 'REL::ID(%d)' % ai
        return None

    tx = cp.startTransaction('CommonLibVR symbol/vtable enrich')
    labeled = named = made = sigd = 0
    try:
        for s in SYMBOLS:
            off = s.get(vkey)
            if not off:
                continue
            addr = base.add(int(off))
            nm = s['n']
            if s['t'] == 'label':
                if nm not in [x.getName() for x in stt.getSymbols(addr)]:
                    stt.createLabel(addr, nm, SourceType.USER_DEFINED)
                    labeled += 1
                rc = relid(s)
                if rc:
                    _safe_eol_comment(listing.getCodeUnitAt(addr), rc)
            else:  # function
                f = fm.getFunctionAt(addr)
                if f is None and create_function is not None:
                    DisassembleCommand(addr, None, True).applyTo(cp)
                    try:
                        f = create_function(addr, nm)
                    except Exception:
                        f = fm.getFunctionAt(addr)
                    if f is not None:
                        made += 1
                if f is None:
                    continue
                cur = f.getName()
                if cur.startswith('FUN_') or cur.startswith('sub_'):
                    f.setName(nm, SourceType.USER_DEFINED)
                    named += 1
                rc = relid(s)
                if rc:
                    _safe_eol_comment(listing.getCodeUnitAt(addr), rc)
                sd = s.get('sd')
                if sd and _upgrade_sig(f):
                    try:
                        apply_structured_sig(sd, f.getName(), addr, fm)
                        sigd += 1
                    except Exception:
                        pass
        print('Symbols: labeled %d, named %d, created %d, signatures %d' % (labeled, named, made, sigd))
        gns['_import_vtable_names']()       # enrich-safe: names vfuncs at vtable slots
        gns['_import_fallback_symbols']()   # enrich-safe: FUN_/sub_ only
    finally:
        cp.endTransaction(tx, True)
    print('Symbol/vtable enrich complete.')


def _sig_key(sig):
    """Normalized comparable key for a Ghidra FunctionSignature: return type +
    ordered param type names. Ignores parameter names and cosmetic spacing."""
    try:
        ret = sig.getReturnType().getName()
        ps = tuple(p.getDataType().getName() for p in sig.getArguments())
        return (ret, ps)
    except Exception:
        return None


def _decompile_text(decomp, f, monitor):
    try:
        res = decomp.decompileFunction(f, 30, monitor)
        if res and res.decompileCompleted():
            df = res.getDecompiledFunction()
            if df:
                return df.getC()
    except Exception:
        pass
    return None


def _snapshot_sig(f):
    """Capture a function's current signature as a re-appliable FunctionDefinition
    plus its source, so a losing trial can be rolled back exactly."""
    from ghidra.program.model.data import FunctionDefinitionDataType
    sig = f.getSignature()
    fdef = FunctionDefinitionDataType(sig)
    return (fdef, f.getSignatureSource())


def _restore_sig(addr, snap, cp):
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    fdef, src = snap
    ApplyFunctionSignatureCmd(addr, fdef, src, True, False).applyTo(cp)


def run_sigconflict():
    """Conflict-resolution pass: where a CommonLib signature DIFFERS from an
    existing USER_DEFINED/IMPORTED one, decompile the function both ways and keep
    whichever decompiles cleaner. Incumbent wins ties/noise (see decompile_score).

    Dry-run by default (logs a CSV, writes nothing). Set CLVR_SIGCONFLICT=go to
    persist the winners. CLVR_SIGCONFLICT_MAX caps how many conflicts to evaluate.
    """
    import csv
    import importlib.util as _ilu
    from ghidra.program.model.symbol import SourceType
    from ghidra.app.decompiler import DecompInterface

    _ds_spec = _ilu.spec_from_file_location(
        'clvr_decompile_score', os.path.join(SCRIPT_DIR, 'decompile_score.py'))
    ds = _ilu.module_from_spec(_ds_spec)
    _ds_spec.loader.exec_module(ds)

    gns = _load_generated_ns()
    SYMBOLS = gns['SYMBOLS']
    VERSION = gns['VERSION']
    apply_structured_sig = gns['apply_structured_sig']
    cp = gns['currentProgram']
    fm = cp.getFunctionManager()
    base = cp.getImageBase()
    dtm = gns['dtm']
    created = gns['created']

    # Rebuild created[] from the live (type-applied) program so candidate sigs
    # resolve to real struct types.
    live = {}
    for dt in dtm.getAllDataTypes():
        live.setdefault(dt.getName(), dt)
    for st in gns['STRUCTS']:
        if st[0] in live:
            created[st[0]] = live[st[0]]

    apply_go = os.environ.get('CLVR_SIGCONFLICT', 'dry').lower() == 'go'
    cap = int(os.environ.get('CLVR_SIGCONFLICT_MAX', '0') or 0)
    vkey = {'svr': 'v', 'se': 's', 'ae': 'a'}.get(VERSION, 'a')
    out_csv = IMPORT_PATH + '.sigconflict.csv'

    decomp = DecompInterface()
    decomp.openProgram(cp)

    rows = []
    evaluated = wins_cand = wins_exist = conflicts = 0
    tx = cp.startTransaction('CommonLibVR signature conflict resolution')
    try:
        for s in SYMBOLS:
            if s.get('t') != 'func':
                continue
            sd = s.get('sd')
            if not sd:
                continue
            off = s.get(vkey)
            if not off:
                continue
            addr = base.add(int(off))
            f = fm.getFunctionAt(addr)
            if f is None:
                continue
            src = f.getSignatureSource()
            # Only challenge authoritative/curated incumbents; auto-inferred ones
            # are already handled by run_symbols().
            if src not in (SourceType.USER_DEFINED, SourceType.IMPORTED):
                continue

            # Snapshot, then build the candidate by applying it, to get its key.
            snap = _snapshot_sig(f)
            existing_key = _sig_key(f.getSignature())
            existing_text = _decompile_text(decomp, f, gns['monitor'])
            try:
                apply_structured_sig(sd, s['n'], addr, fm)
            except Exception:
                continue
            candidate_key = _sig_key(f.getSignature())
            if candidate_key == existing_key:
                _restore_sig(addr, snap, cp)   # no real conflict
                continue
            conflicts += 1
            candidate_text = _decompile_text(decomp, f, gns['monitor'])

            winner, se, sc = ds.choose_better(existing_text, candidate_text)
            evaluated += 1
            if winner == 'candidate':
                wins_cand += 1
                if not apply_go:
                    _restore_sig(addr, snap, cp)  # dry-run: revert the trial
            else:
                wins_exist += 1
                _restore_sig(addr, snap, cp)      # incumbent kept either way

            rows.append((str(addr), s['n'],
                         src.name() if hasattr(src, 'name') else str(src),
                         se, sc, winner,
                         'applied' if (winner == 'candidate' and apply_go) else 'kept-existing'))
            if cap and conflicts >= cap:
                break
    finally:
        cp.endTransaction(tx, True)
        decomp.dispose()

    with open(out_csv, 'w') as fh:
        w = csv.writer(fh)
        w.writerow(['address', 'name', 'incumbent_source',
                    'existing_score', 'candidate_score', 'winner', 'action'])
        for r in rows:
            w.writerow(r)
    print('Sig-conflict: %s. conflicts=%d evaluated=%d candidate_better=%d incumbent_better=%d'
          % ('APPLIED' if apply_go else 'DRY-RUN', conflicts, evaluated, wins_cand, wins_exist))
    print('Decision log: ' + out_csv)


def run_classes():
    """Class-population pass (OO namespaces + vftable wiring).

    B) Reparent functions whose name is a flat 'Class::Method' string into a real
       Ghidra namespace, creating a GhidraClass for the class component (so the
       class browser + decompiler treat methods as members). Reuses any existing
       (e.g. PDB-derived) class namespace; never reparents a name that is not a
       flat qualified string.
    A) Re-point a polymorphic struct's offset-0 `vftable` field at our generated
       `<Class>_vtbl` (CommonLib FunctionDefinition slots) when it still points at
       the PDB `__VFTable` or an untyped pointer, so virtual calls render as named
       method calls. Most roots are already wired at import time; this fixes the
       stragglers.

    Dry-run by default; set CLVR_CLASSES=go to write. CLVR_CLASSES_MAX caps the
    number of function reparents (0 = all).
    """
    from ghidra.program.model.symbol import SourceType

    gns = _load_generated_ns()
    STRUCTS = gns['STRUCTS']
    VTABLES = gns['VTABLES']
    dtm = gns['dtm']
    cp = gns['currentProgram']
    fm = cp.getFunctionManager()
    st = cp.getSymbolTable()
    global_ns = cp.getGlobalNamespace()

    apply_go = os.environ.get('CLVR_CLASSES', 'dry').lower() == 'go'
    cap = int(os.environ.get('CLVR_CLASSES_MAX', '0') or 0)

    # Known class names (short): any generated struct or vtable class. Short names
    # are enough to flag the leaf qualifier as a class for namespace planning.
    class_names = set()
    for stt in STRUCTS:
        class_names.add(stt[0])
    for vt in VTABLES:
        class_names.add(vt[1].split('::')[-1])

    ns_cache = {}

    def get_ns(chain, class_index):
        """Resolve/create the namespace chain; the component at class_index is a
        GhidraClass, the rest plain namespaces. Existing namespaces are reused."""
        key = '::'.join(chain)
        if key in ns_cache:
            return ns_cache[key]
        parent = global_ns
        for i, part in enumerate(chain):
            sub = st.getNamespace(part, parent)
            if sub is None and apply_go:
                if i == class_index:
                    sub = st.createClass(parent, part, SourceType.USER_DEFINED)
                else:
                    sub = st.createNameSpace(parent, part, SourceType.USER_DEFINED)
            if sub is None:
                sub = parent   # dry-run, or creation skipped
            parent = sub
        ns_cache[key] = parent
        return parent

    reparented = classes_seen = errors = 0
    tx = cp.startTransaction('CommonLibVR class population')
    sample = []
    try:
        # B: reparent flat Class::Method functions
        from ghidra.util.exception import DuplicateNameException
        for f in fm.getFunctions(True):
            # Full qualified name: catches flat 'Class::Method' strings, IDA-style
            # 'Class__Method' (IDA has no class namespaces), AND a redundant doubled
            # class prefix that only shows once the parent namespace is included
            # (short name 'Class_Method' inside class Class).
            nm = f.getName(True)
            short = f.getName()
            if '::' not in nm and '__' not in nm:
                continue
            # compiler-generated, not real class methods -- leave them alone.
            if short.startswith('_dynamic_initializer') or '_anonymous_namespace_' in nm:
                continue
            plan = apply_plan.class_namespace_plan(nm, class_names)
            if plan is None:
                continue
            chain, leaf, class_index = plan
            # already correctly placed -> skip (avoids reprocessing the ~12k
            # already-membered functions and re-suffixing their overloads). Holds
            # for both class and plain-namespace parents, hence chain[-1].
            cur_parent = f.getParentNamespace()
            if (leaf == short and cur_parent is not global_ns
                    and cur_parent.getName() == chain[-1]):
                continue
            classes_seen += 1
            if len(sample) < 12:
                sample.append('%s -> %s::%s' % (nm[:40], '::'.join(chain), leaf))
            if not apply_go:
                reparented += 1
                if cap and reparented >= cap:
                    break
                continue
            try:
                target_ns = get_ns(chain, class_index)
                if target_ns is not global_ns:
                    f.setParentNamespace(target_ns)
                try:
                    f.setName(leaf, SourceType.USER_DEFINED)
                except DuplicateNameException:
                    # leaf already taken in this namespace (overload/static) --
                    # disambiguate with the address, matching the vtable-walk style.
                    f.setName('%s_%X' % (leaf, f.getEntryPoint().getOffset()),
                              SourceType.USER_DEFINED)
                reparented += 1
            except Exception:
                errors += 1
            if cap and reparented >= cap:
                break

        # C: promote any known-class component that exists as a plain Namespace
        # to a GhidraClass, so OO features (class browser, this typing) apply.
        # get_ns reuses pre-existing namespaces (PDB or prior passes) which may be
        # plain Namespaces; convert them here regardless of reparenting.
        from ghidra.app.util import NamespaceUtils
        from ghidra.program.model.symbol import SymbolType
        converted = 0
        for cn in class_names:
            for s in st.getSymbols(cn):
                if s.getSymbolType() == SymbolType.NAMESPACE:
                    if apply_go:
                        try:
                            NamespaceUtils.convertNamespaceToClass(s.getObject())
                            converted += 1
                        except Exception:
                            errors += 1
                    else:
                        converted += 1

        # A: re-point straggler vftable fields to our generated _vtbl.
        # _load_generated_ns does not run type creation, so resolve the live
        # `<name>_vtbl` struct from the program rather than the empty created[].
        from java.util import ArrayList
        rewired = 0
        for stt in STRUCTS:
            name, size, category, fields, bases, has_vtable = stt
            if not has_vtable:
                continue
            _vl = ArrayList()
            dtm.findDataTypes(name + '_vtbl', _vl)
            vdt = None
            for _i in range(_vl.size()):
                _c = _vl.get(_i)
                if _c.getClass().getSimpleName() == 'StructureDB':
                    vdt = _c
                    break
            if vdt is None:
                continue
            dt = dtm.getDataType(CategoryPath(category), name)
            if dt is None or dt.getNumComponents() == 0:
                continue
            c0 = dt.getComponent(0)
            if c0.getFieldName() not in ('vftable', '__vftable', '_vftable'):
                continue
            tn = c0.getDataType().getName()
            if '_vtbl' in tn:
                continue   # already wired to ours
            if not ('__VFTable' in tn or tn in ('void *', 'ulonglong', 'undefined8')):
                continue   # leave anything else alone
            if apply_go:
                try:
                    dt.replaceAtOffset(0, dtm.getPointer(vdt, 8), 8, c0.getFieldName(), '')
                    rewired += 1
                except Exception:
                    errors += 1
            else:
                rewired += 1
    finally:
        cp.endTransaction(tx, True)

    print('Classes: %s. flat-method functions=%d, reparented=%d, ns->class=%d, '
          'vftable rewired=%d, errors=%d'
          % ('APPLIED' if apply_go else 'DRY-RUN', classes_seen, reparented,
             converted, rewired, errors))
    for s in sample:
        print('   ' + s)


def run_thiscall():
    """Post-classes phase: normalize class members to proper `__thiscall` (delegates
    to seed_this.py).

    MUST run AFTER run_classes(): the GhidraClass<->struct association that pass
    creates is what lets `__thiscall` auto-TYPE the `this` param. The symbols phase
    deliberately leaves members as `__fastcall`-with-explicit-`this` (a typed `this`
    helps the sigconflict decompile scoring, and at symbols time the class
    association does not exist yet); this phase converts that explicit `this` to the
    correct `__thiscall` convention and seeds a typed `this` on the non-id-bound
    tail (vtable-walk-named / reparented functions).

    Dry-run by default; set CLVR_SEED=go to apply (per seed_this.py). Decision logic
    is in seed_plan.py (unit-tested). Reads the same CLVR_IMPORT / CLVR_SCRIPT_DIR.
    """
    path = os.path.join(SCRIPT_DIR, 'seed_this.py')
    g = dict(globals())
    g['__name__'] = '__main__'
    with open(path) as fh:
        code = fh.read()
    exec(compile(code, path, 'exec'), g)


if __name__ == '__main__':
    # Guards against the exact incident this comment documents: a plain
    # `import apply_enrich` (e.g. for introspection, to reuse resolve_type/
    # make_padding/_fill_struct) sets __name__ to the module name, not
    # '__main__' -- so it no longer auto-executes a live run() even if a
    # stale CLVR_APPLY=go happens to be sitting in os.environ from an
    # earlier call in the same session. Direct execution (GUI Script
    # Manager, `exec(open(path).read())`) still sets __name__ == '__main__'
    # and runs normally.
    _PHASE = os.environ.get('CLVR_PHASE', 'types').lower()
    if _PHASE == 'symbols':
        run_symbols()
    elif _PHASE == 'sigconflict':
        run_sigconflict()
    elif _PHASE == 'classes':
        run_classes()
    elif _PHASE == 'thiscall':
        run_thiscall()
    else:
        run()
