"""Pure (Ghidra-free) decision logic for the `this`-pointer seeder.

Replaces the naive PopulateParameters approach: resolve the class from the real
GhidraClass namespace (the driver does that) and decide, per function, whether to
set param-0 to `Class*`. Non-destructive by construction -- only seeds when the
slot is currently untyped and the signature is not authoritative, never touching
IMPORTED/USER_DEFINED prototypes or static/operator members. Seeds use
SourceType.ANALYSIS so a human edit or a CommonLib re-import always outranks them.

These extra typed `this` anchors are what a downstream call-graph type-propagation
fixpoint radiates from.
"""

# IMPORTED = PDB: its calling convention may be deliberate, and a PDB symbol in a
# class namespace can be a static or a free function, so don't reconvention it.
# USER_DEFINED/ANALYSIS/DEFAULT members ARE convertible -- thiscall is the correct
# convention for a member, so we fix the signature rather than leave it __fastcall.
_PROTECTED_SOURCES = ('IMPORTED',)
_SKIP_LEAF_PREFIX = ('operator',)


def is_untyped(typename):
    """True if a param type carries no class information (so seeding `this` is an
    improvement, not a clobber): absent, undefined, or a bare void pointer."""
    if not typename:
        return True
    t = typename.replace(' ', '')
    while t.endswith(('*', '64')):
        t = t[:-2] if t.endswith('64') else t[:-1]
    return t == '' or t.startswith('undefined') or t == 'void'


def should_set_thiscall(class_known, leaf, current_convention, sig_source,
                        is_static, already_has_typed_this):
    """Decide whether to make a function a `__thiscall` member. Returns
    (action, reason) where action is 'set' or 'skip'.

    Setting `__thiscall` makes Ghidra auto-insert a `this` param and, when the
    GhidraClass is associated with its struct (it is, for our `/types.h` types),
    auto-TYPE it to `Class*` -- the proper OO mechanism, vs. building the param by
    hand. The driver verifies the auto-`this` actually typed and falls back to
    explicit typing if not (see is_untyped).

      class_known         a /types.h struct for the class exists (so auto-this can
                          resolve a type)
      leaf                method short name (to exclude operators/lambdas)
      current_convention   the function's calling convention name ('__fastcall'...)
      sig_source           'IMPORTED'/'USER_DEFINED'/'ANALYSIS'/'DEFAULT'
      is_static            the method is static (no `this`) -- from CommonLib if known
      already_has_typed_this  param-0 is already a typed (class) pointer

    Returns ('set', ...) when the `this` slot is empty/untyped (just set __thiscall
    and let the auto-this fill it), or ('convert', ...) when the function already
    has an explicit typed `this` (the convention is wrong -- it should be
    __thiscall -- so the driver removes the explicit this and sets __thiscall,
    which avoids the double-this/storage-shift that a naive convention change
    causes; verified clean).
    """
    if is_static:
        return ('skip', 'static-no-this')
    if not class_known:
        return ('skip', 'class-type-not-found')
    if not leaf or leaf.startswith(_SKIP_LEAF_PREFIX) or '<lambda' in leaf:
        return ('skip', 'operator-or-lambda')
    if sig_source in _PROTECTED_SOURCES:
        return ('skip', 'imported-pdb')
    if current_convention == '__thiscall':
        return ('skip', 'already-thiscall')
    if already_has_typed_this:
        return ('convert', 'has-explicit-this')   # remove this + set __thiscall
    return ('set', 'ok')
