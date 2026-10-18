"""Validate ``VTABLE_*`` address-library labels against the target's own RTTI.

An address-library ID only says *where* something is.  The *name* attached to
it comes from a community header, and CommonLibF4's ``IDs_VTABLE.h`` lists one
ID under several class names.  The binary knows better: an MSVC x64 vtable is
preceded by a pointer to its CompleteObjectLocator,

    vtable[-1] -> COL { signature=1, offset, cdOffset, pTypeDescriptor,
                        pClassDescriptor, pSelf }   (image-relative RVAs)
    TypeDescriptor { pVFTable, spare, char name[] }   name = ".?AVActor@@"

so every label can be compared with the class the executable itself names.

Verdicts (``compare_label``):
  match         the COL's class is the label's class                 -> KEPT
  mismatch      the COL provably names a different class             -> DROPPED
  unverifiable  the two names cannot be compared confidently         -> KEPT,
                counted (dropped only when a sibling label at the same RVA
                is confirmed, or in ``strict`` mode)
  no_col        ``vtable[-1]`` is not a valid COL: not an RTTI vtable -> DROPPED
  duplicate     a second confirmed name on an already confirmed RVA   -> DROPPED

Everything here is pure: the image is an in-memory section list, so the
validator runs on synthetic layouts in tests and on a staged PE in generators.
"""
from __future__ import annotations

import csv
import os
import re
import struct
from collections import namedtuple
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

MATCH = 'match'
MISMATCH = 'mismatch'
UNVERIFIABLE = 'unverifiable'
NO_COL = 'no_col'
DUPLICATE = 'duplicate'

ColInfo = namedtuple(
    'ColInfo', 'locator_rva subobject_offset type_descriptor_rva decorated_name')


class ColError(ValueError):
    """``vtable[-1]`` does not lead to a valid x64 CompleteObjectLocator."""


class UnsupportedName(ValueError):
    """The decorated name uses a construct this conservative parser skips."""


# ---------------------------------------------------------------------------
# In-memory image
# ---------------------------------------------------------------------------

class SectionImage:
    """File-backed section bytes of one PE image, addressed by RVA."""

    def __init__(self, image_base: int, image_size: int,
                 sections: Iterable[Tuple[int, bytes]]):
        self.image_base = int(image_base)
        self.image_size = int(image_size)
        self.sections = sorted(
            ((int(rva), bytes(data)) for rva, data in sections),
            key=lambda item: item[0])

    @classmethod
    def from_layout(cls, layout) -> 'SectionImage':
        """Load the non-executable sections of a ``pe_layout.PELayout`` once."""
        if layout.pointer_size != 8:
            raise ValueError('MSVC COL vtable validation requires PE32+')
        sections = []
        with open(layout.path, 'rb') as stream:
            for section in layout.sections:
                if section.executable or not section.raw_size:
                    continue
                stream.seek(section.raw_offset)
                data = stream.read(min(section.raw_size, section.size))
                sections.append((section.rva, data))
        return cls(layout.image_base, layout.image_size, sections)

    def read(self, rva: int, size: int) -> Optional[bytes]:
        if rva < 0 or size <= 0:
            return None
        for start, data in self.sections:
            if start <= rva < start + len(data):
                chunk = data[rva - start:rva - start + size]
                return chunk if len(chunk) == size else None
        return None

    def read_cstring(self, rva: int, limit: int = 4096) -> Optional[bytes]:
        for start, data in self.sections:
            if start <= rva < start + len(data):
                begin = rva - start
                end = data.find(b'\0', begin, begin + limit)
                return data[begin:end] if end >= 0 else None
        return None


def read_vtable_col(image: SectionImage, vtable_rva: int) -> ColInfo:
    """Follow ``vtable[-1]`` -> COL -> TypeDescriptor; raise ``ColError``."""
    raw = image.read(vtable_rva - 8, 8)
    if raw is None:
        raise ColError('vtable[-1] has no file-backed bytes')
    locator_rva = struct.unpack('<Q', raw)[0] - image.image_base
    if locator_rva <= 0 or locator_rva + 24 > image.image_size:
        raise ColError('vtable[-1] does not point into the image')
    raw = image.read(locator_rva, 24)
    if raw is None:
        raise ColError('COL has no file-backed bytes')
    signature, subobject, _cd_offset, type_rva, class_rva, self_rva = \
        struct.unpack('<6I', raw)
    if signature != 1:
        raise ColError('COL signature is not 1 (x64)')
    if self_rva != locator_rva:
        raise ColError('COL self RVA is inconsistent')
    if not (0 < type_rva < image.image_size and 0 < class_rva < image.image_size):
        raise ColError('COL metadata RVAs are invalid')
    name = image.read_cstring(type_rva + 16)
    if not name or not name.startswith(b'.?A'):
        raise ColError('TypeDescriptor name is not a decorated class name')
    return ColInfo(locator_rva, subobject, type_rva, name.decode('latin-1'))


# ---------------------------------------------------------------------------
# Decorated type name -> ordered tokens
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r'(?:[A-Za-z_]\w*|<lambda_[0-9a-f]+>)\Z')
_PRIMITIVES = {
    'X': 'void', 'D': 'char', 'C': 'signed char', 'E': 'unsigned char',
    'F': 'short', 'G': 'unsigned short', 'H': 'int', 'I': 'unsigned int',
    'J': 'long', 'K': 'unsigned long', 'M': 'float', 'N': 'double',
    'O': 'long double',
}
_PRIMITIVES_EXT = {
    '_N': 'bool', '_J': '__int64', '_K': 'unsigned __int64',
    '_W': 'wchar_t', '_S': 'char16_t', '_U': 'char32_t', '_Q': 'char8_t',
    '_D': '__int8', '_E': 'unsigned __int8', '_F': '__int16',
    '_G': 'unsigned __int16', '_H': '__int32', '_I': 'unsigned __int32',
}
_CV = {'A': '', 'B': 'const', 'C': 'volatile', 'D': 'const volatile'}


class _TypeNameParser:
    """Recursive-descent reader for MSVC decorated *type* names.

    Returns the name as ordered tokens ``('id'|'lambda'|'anon'|'kw'|'num',
    text)`` in the order
    ``undname`` prints them (outer scope first).  Anything outside the small,
    well-understood subset raises ``UnsupportedName`` -- the caller then
    reports ``unverifiable`` instead of guessing.
    """

    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.names: List[list] = []
        self.params: List[list] = []
        self.has_function_type = False

    def _peek(self, n: int = 1) -> str:
        return self.s[self.i:self.i + n]

    def _starts(self, prefix: str) -> bool:
        return self.s.startswith(prefix, self.i)

    def _until_at(self) -> str:
        end = self.s.find('@', self.i)
        if end < 0:
            raise UnsupportedName('unterminated name')
        text = self.s[self.i:end]
        self.i = end + 1
        return text

    def _memorize(self, tokens: list) -> None:
        if len(self.names) < 10 and tokens not in self.names:
            self.names.append(tokens)

    def descriptor(self) -> list:
        if self._starts('.?AW4'):
            self.i += 5
        elif self._peek(4) in ('.?AV', '.?AU', '.?AT'):
            self.i += 4
        else:
            raise UnsupportedName('not a class/struct/union/enum descriptor')
        tokens = self.qualified_name()
        if self.i != len(self.s):
            raise UnsupportedName('trailing characters')
        return tokens

    def qualified_name(self) -> list:
        pieces = []
        while True:
            if self.i >= len(self.s):
                raise UnsupportedName('unterminated qualified name')
            if self._peek() == '@':
                self.i += 1
                break
            pieces.append(self.name_piece())
        if not pieces:
            raise UnsupportedName('empty qualified name')
        tokens = []
        for piece in reversed(pieces):
            tokens.extend(piece)
        return tokens

    def name_piece(self) -> list:
        char = self._peek()
        if char.isdigit():
            self.i += 1
            index = int(char)
            if index >= len(self.names):
                raise UnsupportedName('dangling name back-reference')
            return list(self.names[index])
        if self._starts('?$'):
            return self.template_instantiation()
        if self._starts('?A'):
            key = self._until_at()
            tokens = [('anon', key)]
            self._memorize(tokens)
            return tokens
        if char == '?':
            raise UnsupportedName('locally scoped or special name')
        ident = self._until_at()
        if not _IDENT_RE.match(ident):
            raise UnsupportedName('non-identifier name piece')
        tokens = [('lambda' if ident.startswith('<') else 'id', ident)]
        self._memorize(tokens)
        return tokens

    def template_instantiation(self) -> list:
        self.i += 2
        outer = (self.names, self.params)
        self.names, self.params = [], []
        try:
            if self._peek() == '?':
                raise UnsupportedName('operator template name')
            ident = self._until_at()
            if not _IDENT_RE.match(ident):
                raise UnsupportedName('non-identifier template name')
            tokens = [('id', ident)]
            self._memorize(list(tokens))
            tokens.extend(self.template_arguments())
        finally:
            self.names, self.params = outer
        self._memorize(list(tokens))
        return tokens

    def template_arguments(self) -> list:
        tokens = []
        while True:
            if self.i >= len(self.s):
                raise UnsupportedName('unterminated template arguments')
            if self._peek() == '@':
                self.i += 1
                return tokens
            for marker in ('$$$V', '$$V', '$$Z', '$S'):
                if self._starts(marker):
                    self.i += len(marker)
                    break
            else:
                if self._starts('$$Y'):
                    self.i += 3
                    tokens.extend(self.qualified_name())
                elif self._starts('$0'):
                    self.i += 2
                    tokens.append(('num', str(self.number())))
                elif self._starts('$1?') or self._starts('$E?'):
                    self.i += 3
                    tokens.extend(self.global_variable())
                elif self._peek() == '$' and not self._starts('$$'):
                    raise UnsupportedName('non-type template argument')
                else:
                    tokens.extend(self.type())

    def global_variable(self) -> list:
        """``&variable`` template argument: ``name@scope@@3<type><cv>``."""
        tokens = self.qualified_name()
        if self._peek() != '3':
            raise UnsupportedName('template argument is not a global variable')
        self.i += 1
        self.type()                      # undname prints only the name
        while self._peek() in ('E', 'I', 'F'):
            self.i += 1
        if self._peek() not in _CV:
            raise UnsupportedName('malformed variable storage class')
        self.i += 1
        return tokens

    def number(self) -> int:
        if self._peek() == '?':
            self.i += 1
        char = self._peek()
        if char.isdigit():
            self.i += 1
            return int(char) + 1
        digits = self._until_at()
        if any(c < 'A' or c > 'P' for c in digits):
            raise UnsupportedName('malformed number')
        value = 0
        for c in digits:
            value = value * 16 + (ord(c) - ord('A'))
        return value

    def type(self) -> list:
        if self._starts('$$'):
            if self._starts('$$Q') or self._starts('$$R'):
                self.i += 2
                return self.pointer()
            if self._starts('$$A6'):
                self.i += 4
                result, parameters = self.function_signature()
                return result + parameters
            if self._starts('$$C'):
                self.i += 3
                return self.cv_qualified()
            if self._starts('$$BY'):
                self.i += 3
                return self.type()
            if self._starts('$$T'):
                self.i += 3
                return [('kw', 'std::nullptr_t')]
            raise UnsupportedName('unsupported $$ type')
        char = self._peek()
        if char in ('V', 'U', 'T'):
            self.i += 1
            return self.qualified_name()
        if char == 'W':
            if not self._peek(2)[1:].isdigit():
                raise UnsupportedName('malformed enum type')
            self.i += 2
            return [('kw', 'enum')] + self.qualified_name()
        if char in ('P', 'Q', 'R', 'S', 'A', 'B'):
            return self.pointer()
        if char == 'Y':
            self.i += 1
            tokens = []
            for _ in range(self.number()):
                tokens.append(('num', str(self.number())))
            return self.type() + tokens
        if char == '_':
            name = _PRIMITIVES_EXT.get(self._peek(2))
            if name is None:
                raise UnsupportedName('unknown extended primitive')
            self.i += 2
            return [('kw', name)]
        if char in _PRIMITIVES:
            self.i += 1
            return [('kw', _PRIMITIVES[char])]
        raise UnsupportedName('unsupported type code {!r}'.format(char))

    def cv_qualified(self) -> list:
        qualifier = _CV.get(self._peek())
        if qualifier is None:
            raise UnsupportedName('unsupported cv-qualifier')
        self.i += 1
        tokens = self.type()
        return tokens + ([('kw', qualifier)] if qualifier else [])

    def pointer(self) -> list:
        self.i += 1
        if self._peek() == '6':
            self.i += 1
            result, parameters = self.function_signature()
            return result + parameters
        if self._peek() == '8':
            # ``ret (Class::*)(params)``: undname prints the class in between.
            self.i += 1
            owner = self.qualified_name()
            while self._peek() in ('E', 'I', 'F'):
                self.i += 1
            if self._peek() not in _CV:
                raise UnsupportedName('unsupported member-function qualifier')
            self.i += 1
            result, parameters = self.function_signature()
            return result + owner + parameters
        while self._peek() in ('E', 'I', 'F'):
            self.i += 1
        return self.cv_qualified()

    def function_signature(self) -> Tuple[list, list]:
        """Return ``(return_type_tokens, parameter_tokens)``."""
        self.has_function_type = True
        if not self._peek().isalpha():
            raise UnsupportedName('malformed calling convention')
        self.i += 1
        result = []
        if self._peek() == '@':
            self.i += 1
        elif self._peek() == '?':
            self.i += 1
            result.extend(self.cv_qualified())
        else:
            result.extend(self.type())
        tokens = []
        if self._peek() == 'X':
            self.i += 1
            tokens.append(('kw', 'void'))
        else:
            while self._peek() not in ('@', 'Z'):
                if self.i >= len(self.s):
                    raise UnsupportedName('unterminated parameter list')
                char = self._peek()
                if char.isdigit():
                    self.i += 1
                    if int(char) >= len(self.params):
                        raise UnsupportedName('dangling type back-reference')
                    tokens.extend(self.params[int(char)])
                    continue
                start = self.i
                parsed = self.type()
                if self.i - start > 1 and len(self.params) < 10:
                    self.params.append(parsed)
                tokens.extend(parsed)
            self.i += 1
        if self._starts('_E'):
            self.i += 2
        if self._peek() != 'Z':
            raise UnsupportedName('missing throw specification')
        self.i += 1
        return result, tokens


def parse_type_descriptor_name(decorated: str) -> List[Tuple[str, str]]:
    """``'.?AVB@A@@'`` -> ``[('id', 'A'), ('id', 'B')]`` (undname order)."""
    return _TypeNameParser(decorated).descriptor()


# ---------------------------------------------------------------------------
# Label <-> decorated name comparison
# ---------------------------------------------------------------------------

# CommonLib label names are the undecorated class name with ``::`` -> ``__``,
# ``<`` ``>`` ``,`` -> ``_`` and every other non-identifier character removed.
# Identifiers may themselves contain ``_``, so both sides are compared with
# all non-alphanumerics removed.  Qualifier / pointer / calling-convention
# spellings differ between the header generators (``void_3_`` vs
# ``void_____ptr64_3_``); they are accepted as filler between the required
# tokens and never decide a verdict.  The RTTI name's identifiers, primitive
# template arguments and integer constants are REQUIRED, in order: a filler
# that also swallowed digits and primitives matched ``Actor2`` to ``Actor``
# and ``BSTArray_int_`` to ``BSTArray<float>``.
_FILLER_WORDS = (
    # ``?A0x<hash>`` anonymous-namespace keys and ``<lambda_<hash>>`` names are
    # derived from the translation unit: every build spells them differently.
    'A0x[0-9a-f]{8}', 'anonymousnamespace', 'stdnullptrt', 'constvolatile',
    'volatile', 'const', 'ptr64', 'cdecl', 'stdcall', 'fastcall', 'thiscall',
    'vectorcall', 'enum', 'class', 'struct', 'union', 'nullptrt', 'restrict',
    'unaligned',
)
# Primitive spellings: required when the RTTI name has them.  Only the
# non-MATCH diagnostics (``_LOOSE_FILLER``) and the residue strip still treat
# them -- and bare digits -- as filler, so a differing argument reads as
# unverifiable rather than as an extra identifier.
_PRIMITIVE_WORDS = (
    'unsigned', 'signed', 'int64', 'int32', 'int16', 'int8', 'int', 'wchart',
    'char16t', 'char32t', 'char8t', 'char', 'short', 'longdouble', 'long',
    'float', 'double', 'bool', 'void',
)
_PRIMITIVE_TYPES = frozenset(_PRIMITIVES.values()) | frozenset(
    _PRIMITIVES_EXT.values())
_FILLER = '(?:' + '|'.join(_FILLER_WORDS) + ')*'
_LOOSE_FILLER = '(?:' + '|'.join(_FILLER_WORDS + _PRIMITIVE_WORDS) + r'|\d+)*'
_LAMBDA = r'lambda[0-9a-f]{32}'
_FILLER_STRIP_RE = re.compile(
    '|'.join(_FILLER_WORDS + _PRIMITIVE_WORDS) + r'|\d+|\|')
_VTABLE_LABEL_RE = re.compile(r'VTABLE_(.+?)(?:_(\d+))?\Z')


def _alnum(text: str) -> str:
    return re.sub(r'[^A-Za-z0-9]', '', text)


def split_vtable_label(name: str) -> Tuple[str, int]:
    """``'VTABLE_Actor_3'`` -> ``('Actor', 2)``.  Prefer the parser's own
    ``vtable_class`` when available: a class may legitimately end in ``_<n>``.
    """
    match = _VTABLE_LABEL_RE.match(name)
    if not match:
        raise ValueError('not a VTABLE label: {}'.format(name))
    return match.group(1), (int(match.group(2)) - 1 if match.group(2) else 0)


def compare_label(class_label: str, decorated: str) -> Tuple[str, str]:
    """Return ``(verdict, reason)`` for one label class vs one RTTI name."""
    parser = _TypeNameParser(decorated)
    try:
        tokens = parser.descriptor()
    except UnsupportedName as exc:
        return UNVERIFIABLE, 'unparsed RTTI name: {}'.format(exc)
    label = _alnum(class_label)
    identifiers = [_alnum(text) for kind, text in tokens if kind == 'id']
    identifiers = [text for text in identifiers if text]
    if not label or not identifiers:
        return UNVERIFIABLE, 'nothing to compare'

    def _required(kind, text):
        return kind in ('id', 'lambda', 'num') or (
            kind == 'kw' and text in _PRIMITIVE_TYPES)

    def _cover(kinds, lambda_hash=True, filler=_FILLER):
        parts = []
        for kind, text in tokens:
            if kind == 'lambda' and not lambda_hash:
                parts.append(_LAMBDA)
            elif kind in kinds and _required(kind, text) and _alnum(text):
                parts.append(re.escape(_alnum(text)))
        return re.fullmatch(filler + filler.join(parts) + filler, label)

    if _cover(('id', 'lambda', 'num', 'kw')):
        return MATCH, ''
    if parser.has_function_type:
        # Header generators cut ``std::function<void (A, B)>`` at the ``(``:
        # a label that spells a leading part of the RTTI name and then stops
        # is truncated, not wrong.
        spelled = [re.escape(_alnum(text)) for kind, text in tokens
                   if kind in ('id', 'lambda', 'num') and _alnum(text)]
        for count in range(len(spelled) - 1, 0, -1):
            if re.fullmatch(_LOOSE_FILLER + _LOOSE_FILLER.join(spelled[:count])
                            + _LOOSE_FILLER, label):
                return UNVERIFIABLE, 'label truncated at a function type'
    missing = [text for text in identifiers if text not in label]
    if missing:
        return MISMATCH, 'RTTI identifier absent from label: {}'.format(missing[0])
    if all(kind == 'id' for kind, _text in tokens):
        # A plain ``A::B`` name has exactly one spelling.
        return MISMATCH, 'label is not the RTTI class name'
    # Every RTTI identifier occurs in the label.  It still names another class
    # if it carries identifiers the RTTI name does not have.
    residue = label
    for text in sorted(identifiers, key=len, reverse=True):
        residue = residue.replace(text, '|', 1)
    residue = _FILLER_STRIP_RE.sub('', re.sub(_LAMBDA, '', residue))
    if len(residue) >= 3:
        return MISMATCH, 'label identifier absent from RTTI name: {}'.format(residue)
    if _cover(('id', 'lambda'), filler=_LOOSE_FILLER):
        return UNVERIFIABLE, 'identifiers agree, template constants/arguments differ'
    if _cover(('id', 'num'), lambda_hash=False, filler=_LOOSE_FILLER):
        # ``<lambda_HASH>`` is derived from the translation unit, so the same
        # closure class is spelled differently by every build.
        return UNVERIFIABLE, 'identifiers agree, lambda hash differs'
    return UNVERIFIABLE, 'identifiers agree, order/keywords differ'


# ---------------------------------------------------------------------------
# Batch validation
# ---------------------------------------------------------------------------

LabelVerdict = namedtuple(
    'LabelVerdict', 'name rva verdict reason decorated subobject_offset')


class VtableCheckResult:
    """``dropped_rows`` are indices into ``verdicts``: the same label listed
    twice at one RVA is one confirmed row plus one duplicate, not two drops."""

    def __init__(self, verdicts: Sequence[LabelVerdict], dropped_rows):
        self.verdicts = list(verdicts)
        self._dropped = set(dropped_rows)
        self._pair_dropped = None

    @property
    def dropped(self) -> List[LabelVerdict]:
        return [v for i, v in enumerate(self.verdicts) if i in self._dropped]

    @property
    def kept(self) -> List[LabelVerdict]:
        return [v for i, v in enumerate(self.verdicts) if i not in self._dropped]

    def is_dropped_row(self, index: int) -> bool:
        return index in self._dropped

    def is_dropped(self, name: str, rva: int) -> bool:
        """True when no row of that ``(name, rva)`` pair survived."""
        if self._pair_dropped is None:
            pairs: Dict[Tuple[str, int], bool] = {}
            for index, v in enumerate(self.verdicts):
                pair = (v.name, v.rva)
                pairs[pair] = pairs.get(pair, True) and index in self._dropped
            self._pair_dropped = pairs
        return self._pair_dropped.get((name, rva), False)

    def counts(self) -> Dict[str, int]:
        kept = self.kept
        return {
            'checked': len(self.verdicts),
            'kept_confirmed': sum(1 for v in kept if v.verdict == MATCH),
            'kept_unverifiable': sum(1 for v in kept if v.verdict == UNVERIFIABLE),
            'dropped': len(self._dropped),
            'dropped_mismatch': sum(1 for v in self.dropped if v.verdict == MISMATCH),
            'dropped_no_col': sum(1 for v in self.dropped if v.verdict == NO_COL),
            'dropped_unconfirmed_sibling': sum(
                1 for v in self.dropped if v.verdict == UNVERIFIABLE),
            'dropped_duplicate': sum(
                1 for v in self.dropped if v.verdict == DUPLICATE),
        }

    def summary(self) -> str:
        c = self.counts()
        return ('{checked} checked: {kept_confirmed} kept (RTTI-confirmed), '
                '{kept_unverifiable} kept (unverifiable), {dropped} dropped '
                '({dropped_mismatch} name mismatch, {dropped_no_col} no COL, '
                '{dropped_duplicate} repeated on a confirmed RVA, '
                '{dropped_unconfirmed_sibling} unconfirmed sibling/strict)'
                .format(**c))


def check_vtable_labels(labels: Iterable[Tuple[str, int, Optional[str]]],
                        image: SectionImage,
                        strict: bool = False) -> VtableCheckResult:
    """Check ``(label_name, vtable_rva, class_label_or_None)`` rows.

    ``strict`` additionally drops ``unverifiable`` labels; use it where the ID
    namespace itself is only statistically established (Fallout 4 VR).
    When several names share one RVA, a confirmed name evicts every
    unconfirmed sibling.
    """
    verdicts: List[LabelVerdict] = []
    for name, rva, class_label in labels:
        if class_label is None:
            class_label = split_vtable_label(name)[0]
        try:
            col = read_vtable_col(image, rva)
        except ColError as exc:
            verdicts.append(LabelVerdict(name, rva, NO_COL, str(exc), '', None))
            continue
        verdict, reason = compare_label(class_label, col.decorated_name)
        verdicts.append(LabelVerdict(
            name, rva, verdict, reason, col.decorated_name, col.subobject_offset))

    confirmed_rvas = {v.rva for v in verdicts if v.verdict == MATCH}
    dropped = set()
    confirmed_once = set()
    for index, v in enumerate(verdicts):
        if v.verdict in (MISMATCH, NO_COL):
            dropped.add(index)
        elif v.verdict == UNVERIFIABLE and (strict or v.rva in confirmed_rvas):
            dropped.add(index)
        elif v.verdict == MATCH:
            # Upstream arrays repeat an ID (``X`` and ``X_2`` on one address):
            # the same class confirmed twice at one RVA is one vtable.
            if v.rva in confirmed_once:
                verdicts[index] = v._replace(
                    verdict=DUPLICATE,
                    reason='same RVA already carries a confirmed label')
                dropped.add(index)
            confirmed_once.add(v.rva)
    return VtableCheckResult(verdicts, dropped)


def check_rtti_labels(labels: Iterable[Tuple[str, int, Optional[str]]],
                      image: SectionImage,
                      strict: bool = False) -> VtableCheckResult:
    """Check ``RTTI_*`` rows: the RVA must BE the class's TypeDescriptor.

    ``(label_name, type_descriptor_rva, class_label_or_None)``.  Same verdicts
    as ``check_vtable_labels``; ``no_col`` here means "no class
    TypeDescriptor at that address".
    """
    verdicts: List[LabelVerdict] = []
    dropped = set()
    for name, rva, class_label in labels:
        if class_label is None:
            class_label = name[len('RTTI_'):] if name.startswith('RTTI_') else name
        raw = image.read_cstring(rva + 16)
        if not raw or not raw.startswith(b'.?A'):
            verdict = LabelVerdict(name, rva, NO_COL,
                                   'no class TypeDescriptor at this address', '', None)
        else:
            decorated = raw.decode('latin-1')
            outcome, reason = compare_label(class_label, decorated)
            verdict = LabelVerdict(name, rva, outcome, reason, decorated, None)
        verdicts.append(verdict)
        if verdict.verdict == MISMATCH or (
                strict and verdict.verdict in (NO_COL, UNVERIFIABLE)):
            dropped.add(len(verdicts) - 1)
    return VtableCheckResult(verdicts, dropped)


def check_nirtti_labels(labels: Iterable[Tuple[str, int, Optional[str]]],
                        image: SectionImage,
                        strict: bool = False) -> VtableCheckResult:
    """Check ``NiRTTI_*`` rows: the RVA must be that class's ``NiRTTI`` object.

    ``NiRTTI { const char* name; const NiRTTI* base; }`` is filled by a
    dynamic initializer, so in the image it is normally zero: that is
    ``unverifiable`` (dropped in ``strict`` mode), never confirmed.  Only a
    file-backed name pointer to the class's own name string is a match.
    """
    verdicts: List[LabelVerdict] = []
    dropped = set()
    for name, rva, class_label in labels:
        if class_label is None:
            class_label = (name[len('NiRTTI_'):] if name.startswith('NiRTTI_')
                           else name)
        raw = image.read(rva, 8)
        pointer = struct.unpack('<Q', raw)[0] if raw is not None else 0
        text = (image.read_cstring(pointer - image.image_base)
                if pointer > image.image_base else None)
        if raw is None or not pointer:
            verdict = LabelVerdict(name, rva, UNVERIFIABLE,
                                   'NiRTTI is runtime-initialised (zero in the image)',
                                   '', None)
        elif not text or not _IDENT_RE.match(text.decode('latin-1')):
            verdict = LabelVerdict(name, rva, NO_COL,
                                   'no NiRTTI name string at this address', '', None)
        elif _alnum(text.decode('latin-1')) == _alnum(class_label.split('__')[-1]):
            verdict = LabelVerdict(name, rva, MATCH, '', text.decode('latin-1'), None)
        else:
            verdict = LabelVerdict(name, rva, MISMATCH,
                                   'NiRTTI names another class',
                                   text.decode('latin-1'), None)
        verdicts.append(verdict)
        if verdict.verdict in (MISMATCH, NO_COL) or (
                strict and verdict.verdict == UNVERIFIABLE):
            dropped.add(len(verdicts) - 1)
    return VtableCheckResult(verdicts, dropped)


def write_dropped_csv(path: str, result: VtableCheckResult,
                      ids: Optional[Dict[Tuple[str, int], int]] = None) -> int:
    """Write the dropped labels (sorted, deterministic) and return the count."""
    rows = sorted(result.dropped, key=lambda v: (v.rva, v.name))
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, lineterminator='\n')
        writer.writerow(['rva', 'id', 'label', 'verdict', 'rtti_name', 'reason'])
        for v in rows:
            writer.writerow([
                '0x{:X}'.format(v.rva),
                (ids or {}).get((v.name, v.rva), ''),
                v.name, v.verdict, v.decorated, v.reason])
    return len(rows)


def validate_symbol_vtable_labels(symbols: List[dict], key: str,
                                  image: SectionImage, strict: bool = False,
                                  class_labels: Optional[Dict[str, str]] = None,
                                  prefix: str = 'VTABLE_') -> VtableCheckResult:
    """Drop ``symbol[key]`` for every ``VTABLE_*`` label the image refutes.

    ``prefix='RTTI_'`` checks TypeDescriptor labels the same way.

    Mirrors the generators' ``_validate_symbol_offsets``: only the offset of
    the target that disproved the label is removed, and the reason is recorded
    under ``rejected_offsets``.  ``class_labels`` maps a label name to the
    class part the header declared (without ``VTABLE_`` / ``_<n>``).
    """
    class_labels = class_labels or {}
    checked = [s for s in symbols
               if s.get('t') == 'label' and s.get('n', '').startswith(prefix)
               and isinstance(s.get(key), int)]
    rows = [(s['n'], s[key], class_labels.get(s['n'])) for s in checked]
    checker = {'RTTI_': check_rtti_labels,
               'NiRTTI_': check_nirtti_labels}.get(prefix, check_vtable_labels)
    result = checker(rows, image, strict=strict)
    for index, s in enumerate(checked):
        if result.is_dropped_row(index):
            verdict = result.verdicts[index]
            s.setdefault('rejected_offsets', {})[key] = (
                prefix.rstrip('_').lower() + '_' + verdict.verdict)
            del s[key]
            for field in ('sections', 'target_sha256'):
                if isinstance(s.get(field), dict):
                    s[field].pop(key, None)
    return result


def validate_vtable_labels_for_layouts(symbols: List[dict], layouts: Dict[str, object],
                                       class_labels: Optional[Dict[str, str]] = None,
                                       report_dir: Optional[str] = None,
                                       report_prefix: str = 'vtable_labels_dropped',
                                       strict_keys: Sequence[str] = (),
                                       rtti_keys: Sequence[str] = (),
                                       id_fields=('id', 'ai', 'si'),
                                       log=print) -> Dict[str, VtableCheckResult]:
    """Run the RTTI check once per staged target layout (``{key: PELayout}``).

    Prints one summary line per target and writes
    ``<report_dir>/<report_prefix>_<key>.csv`` listing what was dropped.
    Targets without a staged executable are not checked (and not touched).
    ``strict_keys`` also drop what cannot be confirmed; ``rtti_keys`` extend
    the (strict) check to ``RTTI_*`` TypeDescriptor and ``NiRTTI_*`` labels
    of those targets.  ``id_fields`` is a field sequence or ``{key: fields}``
    -- the report must name the ID of the target's own namespace (Skyrim SE/VR
    ``si``, AE ``ai``).
    """
    def _has(key, prefix):
        return any(isinstance(s.get(key), int) and s.get('n', '').startswith(prefix)
                   for s in symbols)

    results: Dict[str, VtableCheckResult] = {}
    for key in sorted(layouts):
        layout = layouts[key]
        rtti_prefixes = [prefix for prefix in ('RTTI_', 'NiRTTI_')
                         if key in rtti_keys and _has(key, prefix)]
        if layout is None or not (_has(key, 'VTABLE_') or rtti_prefixes):
            continue
        fields = (id_fields.get(key, ()) if isinstance(id_fields, dict)
                  else id_fields)
        ids = {}
        for s in symbols:
            if isinstance(s.get(key), int):
                ids[(s.get('n'), s[key])] = next(
                    (s[f] for f in fields if s.get(f) is not None), '')
        image = SectionImage.from_layout(layout)
        result = validate_symbol_vtable_labels(
            symbols, key, image,
            strict=key in strict_keys, class_labels=class_labels)
        results[key] = result
        log('VTABLE label RTTI check [{}]: {}'.format(key, result.summary()))
        for prefix in rtti_prefixes:
            tag = prefix.rstrip('_').lower()
            rtti = validate_symbol_vtable_labels(
                symbols, key, image, strict=True, prefix=prefix)
            results['{}:{}'.format(key, tag)] = rtti
            log('{} label check [{}]: {}'.format(prefix, key, rtti.summary()))
            if report_dir:
                write_dropped_csv(os.path.join(
                    report_dir, '{}_{}_{}.csv'.format(report_prefix, key, tag)),
                    rtti, ids)
        if report_dir:
            path = os.path.join(report_dir, '{}_{}.csv'.format(report_prefix, key))
            write_dropped_csv(path, result, ids)
            log('  dropped list: {}'.format(path))
    return results
