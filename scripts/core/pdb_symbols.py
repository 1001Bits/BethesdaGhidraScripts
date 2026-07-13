"""PDB public symbol extraction.

Provides:
  load_pdb_names  - extracts identity-preserving public records from MSF 7 PDBs
  undecorate      - demangles MSVC-mangled symbol names via dbghelp
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import os
import re
from typing import Dict, Optional

from binary_identity import inspect_pe
from pdb_identity import PDBIdentityError, validate_pdb_for_pe
from pdb_msf import PDBMSFError, read_pdb_publics


# ---------------------------------------------------------------------------
# MSVC symbol demangling
# ---------------------------------------------------------------------------

def undecorate(name: str) -> str:
    """Demangle an MSVC-mangled symbol name using dbghelp.UnDecorateSymbolName."""
    try:
        buf = ctypes.create_string_buffer(512)
        if ctypes.windll.dbghelp.UnDecorateSymbolName(name.encode(), buf, 512, 0x1000):
            return buf.value.decode('ascii', errors='replace')
    except Exception:
        pass
    return name


def _clean_name(name: str) -> str | None:
    if name.startswith('?'):
        name = undecorate(name)
    if re.match(r'^FUN_[0-9A-Fa-f]+$', name):
        return None
    name = re.sub(r'_14[0-9A-Fa-f]{6,8}$', '', name)
    # ``__`` is legal and meaningful in compiler/runtime/C identifiers.  The
    # previous blanket replacement corrupted names such as ``__security_cookie``.
    name = re.sub(r':{3,}', '::', name)
    return name or None


# ---------------------------------------------------------------------------
# PDB public symbols
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PDBPublicSymbol:
    """One selected public while retaining its decorated PDB identity."""
    name: str
    decorated_name: str
    aliases: tuple[str, ...]
    name_unique: bool
    identity_unique: bool

    @property
    def merge_safe(self) -> bool:
        return self.name_unique and self.identity_unique


def _public_quality(record):
    cleaned, decorated = record
    compiler = cleaned.startswith(('?', '__', '_')) or '`' in cleaned
    return (compiler, '::' not in cleaned, -len(cleaned), cleaned, decorated)


def _select_public_symbols(aliases):
    """Select display names without discarding overload/alias ambiguity."""
    normalized = {}
    name_rvas = {}
    for rva, records in aliases.items():
        unique_records = sorted(set(records), key=_public_quality)
        if not unique_records:
            continue
        normalized[rva] = unique_records
        for cleaned, _decorated in unique_records:
            name_rvas.setdefault(cleaned, set()).add(rva)

    selected = {}
    for rva, records in normalized.items():
        cleaned, decorated = records[0]
        selected[rva] = PDBPublicSymbol(
            name=cleaned,
            decorated_name=decorated,
            aliases=tuple(record[1] for record in records),
            name_unique=len(name_rvas.get(cleaned, ())) == 1,
            identity_unique=len(records) == 1,
        )
    return selected


def unique_public_merge_target(public: PDBPublicSymbol, candidates):
    """Return one semantic target only when both identities are unique."""
    if not public.merge_safe or len(candidates) != 1:
        return None
    return candidates[0]

def load_pdb_names(file_path: str, pe_path: Optional[str] = None,
                   require_identity: bool = True) -> Dict[int, PDBPublicSymbol]:
    """Return RVA -> public records with decorated identity and ambiguity.

    The native reader handles section/original-section selection and
    OMAP_FROM_SRC before returning image RVAs.  Only S_PUB32 function records
    in executable source and target sections are admitted.
    """
    if not os.path.exists(file_path):
        return {}

    if require_identity and not pe_path:
        print(f"  WARNING: refusing unbound PDB {file_path}; pass pe_path")
        return {}
    if pe_path:
        try:
            identity = validate_pdb_for_pe(pe_path, file_path)
            print("  PDB identity verified: {}/age {}".format(
                identity["guid"], identity["age"]))
        except (OSError, PDBIdentityError) as exc:
            print(f"  WARNING: refusing mismatched/unverifiable PDB: {exc}")
            return {}

    try:
        corpus = read_pdb_publics(file_path)
    except (OSError, PDBMSFError) as exc:
        print(f"  WARNING: PDB parse failed ({exc}); skipping {file_path}")
        return {}
    target_sections = (inspect_pe(pe_path, include_sha256=False)['sections']
                       if pe_path else [])

    def target_is_executable(rva):
        return any(section['executable'] and
                   int(section['rva']) <= rva <
                   int(section['rva']) + max(int(section['virtual_size']),
                                             int(section['raw_size']))
                   for section in target_sections)

    aliases = {}

    def add_record(public):
        # CV_PUBSYMFLAGS::Function is 0x2.  Preserve the former loader's
        # function-only policy while the native parser supplies stricter
        # section bounds and OMAP validation.
        if not public.executable or not (public.flags & 0x2):
            return
        cleaned = _clean_name(public.name)
        if cleaned is None:
            return
        rva = public.rva
        if target_sections and not target_is_executable(rva):
            return
        bucket = aliases.setdefault(rva, [])
        record = (cleaned, str(public.name))
        if record not in bucket:
            bucket.append(record)

    for public in corpus.publics:
        add_record(public)

    conflicts = sum(1 for records in aliases.values() if len(set(records)) > 1)
    if conflicts:
        print('  PDB retained aliases at {} RVAs; quarantining them from '
              'cross-version name merges'.format(conflicts))
    selected = _select_public_symbols(aliases)
    ambiguous_names = sum(not record.name_unique for record in selected.values())
    if ambiguous_names:
        print('  PDB retained {} overload/name-collision records as SE-only'.format(
            ambiguous_names))
    return selected
