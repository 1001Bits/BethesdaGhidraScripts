"""Pure (Ghidra-free) decision logic for the call-graph type-propagation fixpoint.

EMPIRICAL BACKGROUND (why this is filtered, not a blind commit):
Measuring the Ghidra decompiler's prototype inference against the DB signature on
this codebase showed that committing the decompiler's whole prototype
(HighFunctionDBUtil.commitParamsToDatabase) is NET-NEGATIVE:
  * returns are almost always proposed as `void` -> clobbers an honest `undefined`;
  * untyped params come back as `longlong`/`ulonglong` (false precision, no real
    information) far more often than a concrete struct pointer (~1 in 35 class
    methods yielded a genuine named-pointer gain, e.g. `undefined8 -> Stream *`).
And commitParamsToDatabase is all-or-nothing per function, so it cannot keep the
one good param and drop the junk.

So propagation here commits a slot ONLY when the decompiler gives a CONCRETE NAMED
type (a struct/class, typically a pointer) where the DB currently has a GENERIC one
(undefined/void/empty/bare integer). Each such slot is applied surgically via
Parameter.setDataType / Function.setReturnType (SourceType.ANALYSIS), never the bulk
commit -- so honest "unknown"s are never replaced with misleading primitives and
existing concrete/authoritative types are never touched. This is the rule-expressible
core; the driver does the decompiling, the worklist, and the apply.
"""

# Generic integer/float primitives the decompiler emits as filler for an unknown
# slot. Treating these as "not a refinement" is the crux: undefined8 -> longlong is
# noise, undefined8 -> Actor* is signal.
_GENERIC_PRIMS = (
    'undefined', 'void', 'longlong', 'ulonglong', 'long', 'ulong',
    'int', 'uint', 'short', 'ushort', 'char', 'uchar', 'byte', 'sbyte',
    'bool', 'float', 'double', 'word', 'dword', 'qword', 'longdouble',
    'code', 'pointer',
)


def _strip(typename):
    """Lowercased type with pointer/width decoration removed, for comparison."""
    if not typename:
        return ''
    t = typename.replace(' ', '')
    while t.endswith('*') or t.endswith('64'):
        t = t[:-2] if t.endswith('64') else t[:-1]
    return t


def is_generic(typename):
    """True if a type carries no class/struct information: absent, undefined, void,
    or a bare integer/float primitive (the decompiler's filler for unknown slots)."""
    t = _strip(typename)
    if t == '':
        return True
    low = t.lower()
    for g in _GENERIC_PRIMS:
        if low == g or low.startswith('undefined'):
            return True
    return False


def is_concrete_named(typename):
    """True if a type names a struct/class/enum/typedef (real RE information).
    The inverse of is_generic for a present type."""
    return bool(_strip(typename)) and not is_generic(typename)


def safe_refinement(old_typename, new_typename):
    """Should the decompiler's `new` type replace the DB's `old` type for one slot?

    Only when it is a strict information GAIN with no risk of clobber:
      * old is generic (undefined/void/primitive/empty) -- nothing real to lose;
      * new is a concrete named type (struct/class pointer) -- real RE info;
      * they actually differ.
    Everything else is refused: concrete->anything (protect existing RE),
    generic->generic (undefined8->longlong noise), and concrete->generic (a
    decompiler downgrade such as ret->void).
    """
    if not is_concrete_named(new_typename):
        return False
    if not is_generic(old_typename):
        return False
    return _strip(old_typename).lower() != _strip(new_typename).lower()


# Signature sources whose prototypes are authoritative -- never propagate over them.
PROTECTED_SOURCES = ('IMPORTED', 'USER_DEFINED')


def is_protected(sig_source):
    return sig_source in PROTECTED_SOURCES
