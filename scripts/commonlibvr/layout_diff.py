"""Pure (Ghidra-free) struct/vtable layout comparison used by conflict_report.

Kept separate from conflict_report.py (which imports ghidra.program.model.data at
module level) so this logic is unit-testable without a Ghidra runtime, matching the
vt_plan.py / dedup_plan.py convention in this package.
"""
import re

_AUTO_SUFFIX = re.compile(r'_[0-9A-Fa-f]{1,4}$')

_PLACEHOLDER_TYPES = frozenset((
    'undefined', 'uint', 'int', 'byte', 'sbyte', 'ushort', 'short',
    'ulong', 'long', 'ulonglong', 'longlong', 'uint64_t',
    'undefined1', 'undefined2', 'undefined4', 'undefined8'))


def _placeholder_typename(tn):
    """True if a member's declared type is still a raw/unfinished placeholder
    (a primitive, `undefined*`, or a `char[]`/`byte[]` blob array) rather than a
    real, specific type."""
    t = (tn or '').lower()
    return (t in _PLACEHOLDER_TYPES or t.startswith('undefined') or
            t.startswith('char[') or t.startswith('byte['))


def auto_extract_score(members):
    """Fraction of members whose name is the auto-extraction signature
    'Name_<hex>' (e.g. Enabled_8, CasterRefId_34, FormFlags_10) or _pad_/unk
    filler, OR whose declared type is still a raw placeholder (undefined /
    primitive / char[]/byte[] blob -- see _placeholder_typename) despite having
    a field name. NOTE: the hex token is the ORIGINAL (often SE) offset baked
    into the name and need not equal the member's current offset, so we match
    the pattern, not the value. High score => machine-generated/unfinished
    (safe to overwrite); low score => clean descriptive names with real types
    (PDB symbols or hand RE) -> protect.

    The type check matters because a partial extraction pass can leave behind
    named "remainder" fields (e.g. a `_base`/`_middle`/`_tail` split around a
    few manually-identified members, or an `apply_enrich.py`-style `<name>_raw`
    padding stub) that are NOT machine-suffix-named but are still unfinished
    placeholders -- without it, a struct that is mostly untyped byte blobs with
    a couple of real fields poked in scores as "hand-curated" and is protected
    forever instead of being reapplied. This is the fix for a real bug found on
    ``Character``: its existing struct is `_base_raw (byte[688]), Rotation,
    Position, _middle (char[192]), EditorLocPosition, _tail (char[388])` -- none
    of the placeholder fields matched the old name-only patterns, so the score
    came out low and the struct was permanently protected as "hand-curated"
    despite `_base_raw` alone being exactly the size of (and meant to embed) the
    generated `Actor` base.

    members: [(offset, length, typename, fieldname)]
    """
    if not members:
        return 1.0
    auto = 0
    for (o, ln, tn, fn) in members:
        nm = fn or ''
        low = nm.lower()
        if low.startswith('_pad') or low.startswith('pad') or low.startswith('unk') or \
           low.startswith('field_') or low.endswith('_raw') or 'vftable' in low or not nm:
            auto += 1
        elif _AUTO_SUFFIX.search(nm):
            auto += 1
        elif _placeholder_typename(tn):
            auto += 1
    return float(auto) / len(members)


_KIND_PREFIXES = ('struct:', 'enum:', 'union:', 'class:', 'typedef:')

# Ghidra renders a pointer field as '<bare-type-name> *<bits>' (e.g. 'TESForm *64'),
# not a bare trailing '*' -- the generated side's own pointer marker is a 'ptr:'
# prefix (e.g. 'ptr:struct:RE::TESForm'), never a trailing '*' either. Neither the
# old bare-'*'-suffix check nor a kind-prefix strip recognized either spelling, so
# every pointer-typed field (the overwhelming majority of real RE struct fields)
# fell through to a raw string compare that could never match across the two
# pipeline stages.
_PTR_SUFFIX = re.compile(r'\*\s*\d*$')

# Ghidra renders an array field as '<elemtype>[<count>]' (e.g. 'TESForm *64[2]'
# for an array of pointers); the generated side spells it 'arr:<elemtype>:<count>'.
_ARRAY_SUFFIX = re.compile(r'\[\d+\]$')


def _class_of(tn):
    """Coarse type-class for a member typename, so cosmetic name/typedef spelling
    differences don't trigger a false DIVERGENT. 'ptr'/'func ptr' collapse together
    (both are 8-byte pointer-shaped slots -- the common case for a vtable's function
    pointers, which are typed as bare function-pointer typedefs, not 'struct:X *').
    Primitives of the same byte width also collapse (uint32/int32 are interchangeable
    at the ABI level and differ constantly between hand-RE and clang-generated layouts).

    A named struct/enum/union type is normalized to its bare leaf name (kind prefix
    and C++ namespace qualification stripped) before falling through to the raw
    string, so e.g. the generated side's 'struct:DirectX::XMFLOAT3' and the Ghidra
    side's bare 'XMFLOAT3' -- the SAME type, just spelled differently by each
    pipeline stage -- compare equal instead of permanently tripping DIVERGENT. This
    is the fix for a real bug: any generated field whose type is a named
    struct/enum (basically every non-primitive field) failed this comparison on
    namespace spelling alone, so structs with already-correct live fields (e.g.
    ``DirectX::BoundingBox``, fully resolved to `Center`/`Extents: XMFLOAT3`) kept
    reclassifying DIVERGENT and getting endlessly, pointlessly re-applied by every
    batch run with zero actual change.

    Pointer fields get the same treatment: the generated side spells a pointer as
    'ptr:<pointee>' while Ghidra spells it '<pointee> *<bits>' -- neither form was
    recognized as "a pointer" by the old check (a bare trailing '*' with no bit
    suffix), so e.g. generated 'ptr:struct:RE::TESForm' vs live 'TESForm *64'
    normalized to 'tesform' vs 'tesform *64' and never matched, permanently
    misclassifying almost every real struct with pointer fields (the vast
    majority of them) as DIVERGENT despite already being correct.

    Arrays get the same treatment recursively: the generated side spells
    'arr:<elemtype>:<count>' while Ghidra spells '<elemtype>[<count>]' (e.g. an
    array of pointers renders as '<pointee> *<bits>[<count>]') -- both forms are
    stripped down to their element type and re-classified via a recursive call,
    then re-prefixed with 'arr:', so e.g. generated 'arr:ptr:struct:RE::TESForm:2'
    and live 'TESForm *64[2]' both normalize to 'arr:ptr'."""
    t = (tn or '').lower()
    if t.startswith('arr:'):
        inner = re.sub(r':\d+$', '', t[len('arr:'):])
        return 'arr:' + _class_of(inner)
    m = _ARRAY_SUFFIX.search(t)
    if m:
        return 'arr:' + _class_of(t[:m.start()])
    if t.startswith('ptr:') or _PTR_SUFFIX.search(t) or 'vtbl' in t or 'vftable' in t or t.startswith('function') or t.startswith('code *'):
        return 'ptr'
    # Ghidra renders a bitfield-of-a-primitive as '<primitive>:<width>' (e.g.
    # 'uint:28' for a real Windows-header `DWORD Flags : 28;`). The generated
    # side's clang extraction of the SAME header field often only captures the
    # flat DWORD (no bitfield decomposition), spelling it plain 'u32' with no
    # colon suffix -- so 'uint:28' needs the SAME primitive-bucket mapping 'u32'
    # gets, not just a bare suffix-strip to 'uint' (a string that matches
    # nothing below, permanently mismatching against 'u32'). Recurse through the
    # bare primitive name so it gets full normalization.
    m_bf = re.match(r'^([a-z_][a-z0-9_]*):\d+$', t)
    if m_bf and m_bf.group(1) in (
            'undefined1', 'byte', 'sbyte', 'bool', 'char', 'uchar', 'i8', 'u8',
            'undefined2', 'ushort', 'short', 'word', 'i16', 'u16',
            'undefined4', 'uint', 'int', 'dword', 'float', 'i32', 'u32', 'f32',
            'undefined8', 'ulong', 'long', 'ulonglong', 'longlong', 'uint64_t', 'qword',
            'double', 'i64', 'u64', 'f64'):
        return _class_of(m_bf.group(1))
    # The generated side spells primitives with its own fixed-width names (i8/u8/
    # i16/u16/i32/u32/f32/i64/u64/f64), never Ghidra's own vocabulary (short/int/
    # float/...) -- these two conventions never overlapped, so e.g. generated 'i16'
    # fell through every check below untouched while live 'short' correctly mapped
    # to 'u16', permanently mismatching every primitive field on the generated
    # pipeline's own spelling alone. Map both conventions into the same buckets.
    if t in ('undefined1', 'byte', 'sbyte', 'bool', 'char', 'uchar', 'i8', 'u8'):
        return 'u8'
    if t in ('undefined2', 'ushort', 'short', 'word', 'i16', 'u16'):
        return 'u16'
    if t in ('undefined4', 'uint', 'int', 'dword', 'float', 'i32', 'u32', 'f32'):
        return 'u32'
    if t in ('undefined8', 'ulong', 'long', 'ulonglong', 'longlong', 'uint64_t', 'qword',
             'double', 'i64', 'u64', 'f64'):
        return 'u64'
    for pfx in _KIND_PREFIXES:
        if t.startswith(pfx):
            t = t[len(pfx):]
            break
    t = re.sub(r':\d+$', '', t)  # enum bitfield-width suffix, e.g. 'bool_bits:4'
    if '::' in t:
        t = t.rsplit('::', 1)[-1]
    return t


def has_overlapping_fields(gen_members):
    """True if the generated field list itself has two fields occupying overlapping
    byte ranges at different offsets-with-size (not just two zero-length fields
    sharing an offset).

    This detects an anonymous C++ union that the CommonLib type-extraction step
    flattened into a single flat tuple list instead of modeling as a union -- e.g.
    ``union { struct { BYTE b,g,r,a; }; UINT c; }`` (DirectX's XMCOLOR) becomes
    ``[('b','u8',0,1), ('c','u32',0,4), ('g','u8',1,1), ...]``: 'b'@0..1 and
    'c'@0..4 both claim offset 0, and 'g'@1..2 sits inside 'c'@0..4 too. There is
    no valid non-overlapping flat layout that satisfies both views simultaneously,
    so such a generated struct can never be correctly filled/replaced as an
    ordinary struct -- every batch run would keep re-selecting and "successfully"
    reapplying it with zero actual change, permanently wasting batch budget. Real
    fix is proper union modeling in the generator; this is the cheap classify()-side
    guard so these get excluded from the eligible pool instead of looping forever.

    gen_members: [(fname, ftype, foffset, fsize)]
    """
    spans = sorted((foff, foff + fsize) for (_fname, _ftype, foff, fsize) in gen_members
                   if fsize > 0)
    for i in range(1, len(spans)):
        if spans[i][0] < spans[i - 1][1]:
            return True
    return False


def find_component_drift(components):
    """Detect stale component slots: a field embedding another struct/type AS A
    FIXED-SIZE COMPONENT whose *referenced type* has since been resized (by a
    later replaceDataType()/fill on that type elsewhere), while this component's
    own frozen slot length was never updated to match.

    Ghidra's Structure model has two independent size concepts per component:
    the component's frozen slot length (fixed when placed, never auto-updated)
    and the referenced DataType's current actual length (which changes live as
    that type gets resized elsewhere in the same DataTypeManager). Bulk-apply
    batches legitimately resize widely-embedded types (e.g. correcting a stub to
    its real CommonLib size); every OTHER struct that embeds that type as a
    fixed component -- even one never itself touched, e.g. HANDCURATED/protected
    -- is left with a stale, too-small (or too-large) slot. Ghidra's own decompiler/
    UI surfaces this as "Field <name> does not fit in structure <container>" the
    next time something touches the container.

    components: iterable of (struct_path, field_name, offset, slot_length,
                current_type_length, is_bitfield) tuples -- one per defined,
                non-bitfield-eligible component across every Structure in a
                DataTypeManager. Bitfield components are expected to share byte
                ranges by design (multiple sub-byte fields packed into the same
                bytes) and must be excluded by the caller or marked is_bitfield
                so they're skipped here rather than false-flagged.

    Returns a list of (struct_path, field_name, offset, slot_length,
    current_type_length, struct_length) tuples for every genuine drift found,
    in input order.
    """
    drift = []
    for struct_path, field_name, offset, slot_length, current_type_length, struct_length, is_bitfield in components:
        if is_bitfield:
            continue
        if current_type_length <= 0:
            continue
        if current_type_length != slot_length:
            drift.append((struct_path, field_name, offset, slot_length, current_type_length, struct_length))
    return drift


def plan_cascade_fix(components, struct_length):
    """Decide whether a single struct's component-slot drift (see
    find_component_drift) is the SIMPLE, mechanically-fixable case: exactly one
    non-bitfield component has a stale slot, and every other component can be
    fixed up by shifting the ones after it by the same delta.

    This is the pure decision logic behind a real, recurring fix pattern this
    session: a widely-embedded base type (e.g. NiAVObject, IMenu, BSCullingProcess)
    gets corrected to its true size, and every OTHER struct that embeds it as a
    fixed-size component (even ones never themselves touched) is left with a
    stale slot -- Ghidra surfaces this as "Field X does not fit in structure Y".
    The mechanical fix is always the same shape: widen/shrink the one drifted
    slot to match the referenced type's current length, and shift every field
    after it by the resulting delta. This function only PLANS that fix; it does
    not touch Ghidra (see apply_enrich.apply_cascade_fix for the mutation glue).

    components: iterable of (field_name, offset, slot_length,
                current_type_length, is_bitfield) tuples for every DEFINED
                component of ONE struct, in offset order.
    struct_length: the struct's own total length.

    Returns a dict:
      simple=True  -> {"simple": True, "drifted_field": name, "offset": int,
                       "old_slot": int, "new_slot": int, "delta": int,
                       "new_struct_length": int}
      simple=False -> {"simple": False, "reason": "..."}
    """
    non_bf = [c for c in components if not c[4]]
    drifted = [c for c in non_bf if c[3] > 0 and c[3] != c[2]]

    if not drifted:
        return {"simple": False, "reason": "no component drift found"}
    if len(drifted) > 1:
        return {"simple": False,
                "reason": "multiple drifted components ({}), not a single-field cascade"
                          .format(len(drifted))}

    field_name, offset, old_slot, new_slot, _is_bf = drifted[0]
    delta = new_slot - old_slot
    return {
        "simple": True,
        "drifted_field": field_name,
        "offset": offset,
        "old_slot": old_slot,
        "new_slot": new_slot,
        "delta": delta,
        "new_struct_length": struct_length + delta,
    }


def layout_diverges(existing_members, gen_members):
    """True if, DESPITE existing_size == generated_size, the two layouts disagree
    at some offset in a way that isn't just a cosmetic name/typedef difference.

    This is the fix for a real bug: a struct/vtable can grow a bogus extra field
    (or drop a real one) that shifts every subsequent member's offset while the
    TOTAL size happens to stay the same (an existing member elsewhere is also off
    by the same amount, or padding absorbs the delta) -- classify()'s old
    ``esize == gsize -> MATCH`` treated this as "already correct" and skipped
    reapplying the freshly-generated (correct) layout, permanently protecting the
    stale/wrong one. This happened concretely to ``RE::Actor``'s vtable: a bogus
    ``Unk_84`` declaration shifted every subsequent vtable slot by one, but the
    struct's total size still matched, so the drift went uncorrected across
    however many pipeline runs happened since it was introduced.

    Deliberately lenient about what counts as "diverges" -- only offset+type-class
    disagreement or a differing field count trips it. A bare name difference alone
    (e.g. Ghidra's own better name for a placeholder, or a cosmetic rename) is NOT
    treated as divergence: forcing every hand-renamed field back through DIVERGENT
    review just because clang's generated name differs would make DIVERGENT so noisy
    that real cases stop getting attention.

    existing_members: [(offset, length, typename, fieldname)]  (Ghidra side)
    gen_members:       [(fname, ftype_str, foffset, fsize)]    (generated side)
    """
    if len(existing_members) != len(gen_members):
        return True

    # Bitfield members: the generator packs bit-offset/width entirely into the
    # type string ('bf:<bitoffset>:<width>') and zeroes the ordinary offset/size
    # tuple fields, since a sub-byte field has no meaningful byte offset of its
    # own -- every bitfield member in a struct therefore collides on the same
    # offset key (0) when run through the by-offset dict below, so only the
    # LAST one survives dict construction and every other bitfield member is
    # silently discarded from the comparison. This permanently misclassified
    # already-correct bitfield structs (e.g. RE::ActorState::ActorState1/2,
    # whose live fields matched the generated ones name-for-name) as DIVERGENT.
    # Compare bitfield members as a NAME SET instead of by offset -- name is the
    # only reliable join key across the two sides' incompatible offset
    # encodings, and the containing struct's own overall offset/size is already
    # verified matching by the caller before this function runs.
    gen_bf_names = {fname for (fname, ftype, _foff, _fsize) in gen_members if ftype.startswith('bf:')}
    if gen_bf_names:
        exist_bf_names = {fn for (_o, _ln, _tn, fn) in existing_members if fn in gen_bf_names}
        if exist_bf_names != gen_bf_names:
            return True
        existing_members = [m for m in existing_members if m[3] not in gen_bf_names]
        gen_members = [m for m in gen_members if not m[1].startswith('bf:')]
        if len(existing_members) != len(gen_members):
            return True

    by_off_e = {o: (ln, tn) for (o, ln, tn, _fn) in existing_members}
    by_off_g = {foff: (fsize, ftype) for (fname, ftype, foff, fsize) in gen_members}
    offsets = set(by_off_e) | set(by_off_g)
    for off in offsets:
        e = by_off_e.get(off)
        g = by_off_g.get(off)
        if e is None or g is None:
            return True  # a slot exists on one side only -> real structural disagreement
        e_len, e_tn = e
        g_len, g_tn = g
        if e_len != g_len:
            return True
        if _class_of(e_tn) != _class_of(g_tn):
            return True
    return False


def verify_handcurated(existing_members, gen_members, existing_size, gen_size, has_drift=False):
    """Judge whether a struct classified HANDCURATED (protected from auto-replace
    because it "looks hand-curated") is actually verified-correct, or a latent bug
    that classify()'s heuristic mistook for deliberate hand-curation.

    `HANDCURATED` only means "few fields look machine-generated" -- it is NOT proof
    of correctness. This session found a concrete counterexample: `BSMultiBoundNode`
    was HANDCURATED all session (gen_size=352, existing_size=312, a genuine 40-byte
    deficit from `BSNiNode` growing out from under it) -- not a deliberately-richer
    hand-curated struct, just a stale one that happened to score low on the
    machine-generated-name heuristic.

    Three checks, in priority order:

    1. SUSPECT_STALE -- existing_size < gen_size. Genuine hand-curation means "we
       know MORE than the generic extractor" (a real base class embedded, real
       extra fields discovered by RE) -- it should make the existing struct equal
       or RICHER than generated, never smaller. A struct smaller than its own
       generated reference is the exact BSMultiBoundNode pattern: stale content
       from before some dependency was fixed, not intentional richness.

    2. SUSPECT_OTHER (drift) -- has_drift=True, i.e. this struct (or a type it
       embeds) shows up in a component-drift scan (see find_component_drift).
       A struct with real component-slot corruption is definitively broken,
       independent of its size relationship to the generated reference.

    3. SUSPECT_OTHER (field mismatch) -- existing_size >= gen_size (the
       "genuinely richer" case), so compare the SHARED byte range: every
       generated field's exact offset must exist in the existing layout with a
       compatible type-class and length (via `_class_of`, so cosmetic spelling
       differences don't false-flag). Existing fields beyond `gen_size`, or
       existing fields interleaved within the shared range that don't correspond
       to a generated field, are fine (that IS the hand-curated content) -- but a
       generated field with no matching slot, or a slot with a genuinely
       different type/length where a generated field expects one, means even the
       claimed-correct hand-curated content itself disagrees with the ground
       truth, not just extends it.

    Only if none of the above trip does the struct pass as VERIFIED_CORRECT.

    existing_members: [(offset, length, typename, fieldname)]
    gen_members:       [(fname, ftype_str, foffset, fsize)] (bitfield 'bf:' entries
                        already excluded by the caller, matching classify()'s own
                        gen_members convention -- NOT gen_members_with_bf)
    existing_size, gen_size: total struct byte lengths
    has_drift: bool, True if a component-drift scan flagged this struct or an
               embedded type of its

    Returns (status, reason) -- status one of 'VERIFIED_CORRECT', 'SUSPECT_STALE',
    'SUSPECT_OTHER'; reason is a short human-readable string.
    """
    if existing_size < gen_size:
        return ('SUSPECT_STALE',
                'existing_size {} < gen_size {} (stale-deficit pattern)'.format(existing_size, gen_size))

    if has_drift:
        return ('SUSPECT_OTHER', 'component-slot drift detected on this struct or an embedded type')

    by_off_e = {o: (ln, tn) for (o, ln, tn, _fn) in existing_members}
    for (fname, ftype, foff, fsize) in gen_members:
        e = by_off_e.get(foff)
        if e is None:
            return ('SUSPECT_OTHER',
                    'generated field {!r} at offset {} has no matching existing slot'.format(fname, foff))
        e_len, e_tn = e
        if e_len != fsize:
            return ('SUSPECT_OTHER',
                    'generated field {!r} at offset {} size {} != existing size {}'.format(
                        fname, foff, fsize, e_len))
        if _class_of(e_tn) != _class_of(ftype):
            return ('SUSPECT_OTHER',
                    'generated field {!r} at offset {} type {!r} != existing type {!r}'.format(
                        fname, foff, ftype, e_tn))

    return ('VERIFIED_CORRECT', 'existing_size >= gen_size and shared byte range matches')
