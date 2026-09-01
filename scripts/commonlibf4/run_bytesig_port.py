#!/usr/bin/env python3
"""Cross-version byte-signature port for Fallout 4 binaries.

CommonLibF4's IDs live in the NG/AE namespace (1.10.984 / 1.11.191).  OG
(1.10.163) and VR (1.2.72) use disjoint ID namespaces, so address-library
lookups can't transfer names directly.  This driver anchors at AE-named
functions (~25k from CommonLibImport_F4_AE.py + IDAImportNames) and finds
matching positions in OG / NG / VR via masked byte signatures.

Pipeline:
  Source pool:  CommonLibImport_F4_AE.py SYMBOLS + identity-bound normalized
                IDA evidence (or the historical byte-pinned legacy corpus)
  Signatures:   bytesig_port.py  (exact 32 B match + masked 48 B retry)
  Output:       OG/NG/VR scripts re-emitted with ported names embedded

Two-pass match:
  Pass 1 — exact 32-byte raw match  (high precision, lower recall)
  Pass 2 — 48-byte masked match wildcarding rel32 / rip-rel disp32 operands
           (cross-build resilient — OG/VR have different jump targets)

Only runs if both the source (AE) and target (OG / NG / VR) binaries are
present under exes/f4/<version>/.  Missing binaries are silently skipped.
Steam binaries with SteamStub DRM are auto-unpacked via Steamless.

Usage:
  python scripts/commonlibf4/run_bytesig_port.py             # all targets
  python scripts/commonlibf4/run_bytesig_port.py og          # one target
  python scripts/commonlibf4/run_bytesig_port.py og ng vr    # multiple
"""

from __future__ import annotations

import json
import hashlib
import importlib.util
import os
import re
import sys
from pathlib import Path


_SCRIPT_DIR  = Path(__file__).resolve().parent
_PROJECT_DIR = _SCRIPT_DIR.parent.parent
sys.path.insert(0, str(_PROJECT_DIR / "scripts" / "core"))
sys.path.insert(0, str(_SCRIPT_DIR))

import ast
from bytesig_port import load_pe_text, build_prefix_index, port_symbols  # noqa: E402
from steamless     import ensure_unpacked                                # noqa: E402
from addrlib_emit  import build_name_to_id, join_ids, write_addrlib_csv  # noqa: E402
from binary_identity import inspect_pe                                   # noqa: E402
from pe_unwind import extract_runtime_functions                          # noqa: E402
from importer_binding import accepts_manifest                           # noqa: E402
from bytesig_evidence import (                                           # noqa: E402
    load_validated as load_bytesig_evidence,
    persist as persist_bytesig_evidence,
)


# Several game pipelines have a top-level module named ``address_library``.
# A combined pytest/Python process may already have another game's module in
# sys.modules, so bind the F4 implementation by its exact file rather than
# trusting the ambiguous global module name.
_F4_ADDRESS_LIBRARY_MODULE = "bgs_commonlibf4_address_library"
_f4_address_library_spec = importlib.util.spec_from_file_location(
    _F4_ADDRESS_LIBRARY_MODULE, _SCRIPT_DIR / "address_library.py")
if _f4_address_library_spec is None or _f4_address_library_spec.loader is None:
    raise ImportError("cannot load the local Fallout 4 address-library module")
_f4_address_library = importlib.util.module_from_spec(_f4_address_library_spec)
sys.modules[_F4_ADDRESS_LIBRARY_MODULE] = _f4_address_library
_f4_address_library_spec.loader.exec_module(_f4_address_library)
F4AddressLibrary = _f4_address_library.F4AddressLibrary


_JSON_LOADS_RE = re.compile(r"^_json(?:_sym)?\.loads\((.+)\)$")


def _extract_symbols_array(content: str, var_name: str = "SYMBOLS"):
    """Pull a SYMBOLS/FALLBACK_SYMBOLS list out of a generated import script.

    The generator emits one of two forms (see ghidra_import_gen.py):
      * raw JSON literal:        ``SYMBOLS = [{...}]``
      * json.loads()-wrapped:    ``SYMBOLS = _json_sym.loads('[{...}]')``

    The wrapped form is used so JSON booleans (``true``/``false``) parse
    safely under Python at script load.  Either way return the parsed list.
    """
    m = re.search(rf"^{var_name} = (.+?)$", content, re.M)
    if not m:
        return None
    val = m.group(1).strip()
    wrap = _JSON_LOADS_RE.match(val)
    if wrap is not None:
        val = ast.literal_eval(wrap.group(1))
    return json.loads(val)


EXES_DIR       = _PROJECT_DIR / "exes" / "f4"
GENERATED_DIR  = _PROJECT_DIR / "ghidrascripts"
EXTRAS_DIR     = _PROJECT_DIR / "extras"
IDA_NORMALIZED_DIR = EXTRAS_DIR / "normalized"
STEAMLESS_CLI  = _PROJECT_DIR / "tools" / "Steamless" / "Steamless.CLI.exe"
IDA_CORPUS_SHA256 = 'b0c327619f1a4e71fb3061c571d44a9d4de9154ab641dcc1932414dcbca639c0'
IDA_SOURCE_SHA256 = {
    # AE 1.11.191 packed Steam exe ...
    '81694b37816c8045855905a52c5fb13583c5803121fabb5024760892014e9bc6',
    # ... its Steamless-unpacked artifact (the matcher runs on this one,
    # so the corpus gate must accept it or the IDA pool silently drops)
    'e555c6c0e7aba3e9e4801c2e5e11e3a76b42ce080683b4b9c1cf074c2030b737',
    'a5c5df53bf9f99201d35261851adf28f7bce309328c2b5ffd2a66326a7f4752a',
}

VERSION_TO_BIN_NAME = {
    "og": "Fallout4.exe",
    "ng": "Fallout4.exe",
    "ae": "Fallout4.exe",
    "vr": "Fallout4VR.exe",
    "221": "Fallout4.exe",
}


def _binary_for(target: str) -> Path | None:
    """Return the unpacked binary path for target, or None if not present."""
    name = VERSION_TO_BIN_NAME.get(target)
    if not name:
        return None
    raw = EXES_DIR / target / name
    if not raw.is_file():
        return None
    return ensure_unpacked(raw, STEAMLESS_CLI)


_NAME_RE = re.compile(r"^[A-Za-z_][\w:]*$")


def _load_commonlib_f4_names(source: str) -> dict[str, int]:
    """{name: source_rva} from CommonLibImport_F4_{SOURCE}.py SYMBOLS array.

    ``source`` is 'ae' or 'ng'; the matching RVA key on each symbol is 'a' or
    'ng' respectively (set up by parse_commonlib_types.py).
    """
    rva_key = "a" if source == "ae" else source
    script = GENERATED_DIR / f"CommonLibImport_F4_{source.upper()}.py"
    if not script.is_file():
        return {}
    content = script.read_text(encoding="utf-8")
    syms = _extract_symbols_array(content, "SYMBOLS")
    if syms is None:
        return {}
    out: dict[str, int] = {}
    for s in syms:
        if s.get("t") != "func":
            continue
        rva = s.get(rva_key)
        name = s.get("n", "")
        if not rva or not name or "<" in name or ">" in name:
            continue
        out.setdefault(name, rva)
    return out


def _load_ida_names(source_manifest) -> dict[str, int]:
    """Return an identity-bound, reciprocal-unique AE ``{name: rva}`` pool.

    A locally normalized archive map takes priority.  Its loader verifies the
    evidence content, exact PE identity, source-archive lock, section kind,
    linker function boundary, and duplicate-name quarantine.  The historical
    raw script remains a byte-for-byte pinned compatibility source only; an
    arbitrary/new raw script can never bypass normalization by changing a
    constant here.
    """
    from ida_name_archive import (
        load_normalized_evidence, select_normalized_evidence_path)
    normalized_path = select_normalized_evidence_path(
        "1.11.191.0", str(source_manifest.get("sha256") or ""),
        IDA_NORMALIZED_DIR)
    if normalized_path is not None:
        rows = load_normalized_evidence(
            normalized_path, source_manifest,
            expected_version="1.11.191.0")
        out: dict[str, int] = {}
        for row in rows:
            name = row["name"]
            if (row["kind"] != "func" or not _NAME_RE.match(name)
                    or "<" in name or ">" in name):
                continue
            if name in out:
                raise ValueError(
                    "normalized IDA evidence contains an ambiguous name")
            out[name] = int(row["rva"])
        return out

    p = EXTRAS_DIR / "IDAImportNames_1.11.191.0.py"
    if not p.is_file():
        return {}
    if (hashlib.sha256(p.read_bytes()).hexdigest() != IDA_CORPUS_SHA256 or
            source_manifest.get('sha256', '').lower() not in IDA_SOURCE_SHA256):
        print('  IDAImportNames corpus/source identity mismatch; skipping.')
        return {}
    name_re = re.compile(
        r"^\s*NAME\(\s*0x([0-9A-Fa-f]+)\s*,\s*['\"]([^'\"]+)['\"]\s*\)\s*$")
    addr_suffix_re = re.compile(r"_[0-9A-Fa-f]{6,12}$")
    placeholder_re = re.compile(
        r"^(?:FUN|sub|loc|byte|word|dword|qword|unk|off|stru|asc|jpt|nullsub|j_)"
        r"_[0-9A-Fa-f]+$")
    image_base = 0x140000000
    out: dict[str, int] = {}
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = name_re.match(line)
            if not m:
                continue
            try:
                abs_addr = int(m.group(1), 16)
            except ValueError:
                continue
            if abs_addr < image_base or abs_addr >= image_base + 0x80000000:
                continue
            rva = abs_addr - image_base
            raw = m.group(2).strip()
            if placeholder_re.match(raw):
                continue
            name = addr_suffix_re.sub("", raw).strip()
            if not name or not _NAME_RE.match(name):
                continue
            out.setdefault(name, rva)
    return out


def _section_for_rva(manifest, rva):
    for section in manifest.get('sections', []):
        start = int(section.get('rva', 0))
        size = max(int(section.get('virtual_size', 0)),
                   int(section.get('raw_size', 0)))
        if start <= rva < start + size:
            return section.get('name', '')
    return ''


def _merge_into_script(target: str, target_rva_key: str,
                       ported: list[tuple[str, int]], target_manifest: dict,
                       src_tag: str = "identity-bound-bytesig-port") -> int:
    """Inject ported (name, target_rva) entries into the target's generated
    script's SYMBOLS array.  Returns the number of new entries added.

    The script's SYMBOLS line is rewritten in place — entries whose name is
    already present in SYMBOLS get a target_rva_key field added; new names
    are appended as fresh entries.  Existing AE/NG offsets stay intact.
    """
    fname = f"CommonLibImport_F4_{target.upper()}.py"
    script = GENERATED_DIR / fname
    if not script.is_file():
        print(f"  {fname}: not found, skipping merge")
        return 0
    try:
        bound_manifest = accepts_manifest(script, target_manifest)
    except ValueError as exc:
        raise RuntimeError(
            '{} is not bound to the bytesig target: {}'.format(fname, exc))
    target_manifest = bound_manifest
    content = script.read_text(encoding="utf-8")
    syms = _extract_symbols_array(content, "SYMBOLS")
    if syms is None:
        print(f"  {fname}: no SYMBOLS array, skipping merge")
        return 0
    m = re.search(r"^SYMBOLS = (.+?)$", content, re.M)
    by_name: dict[str, dict] = {}
    by_rva: dict[int, dict] = {}
    for s in syms:
        if s.get("t") == "func":
            by_name.setdefault(s["n"], s)
            if s.get(target_rva_key):
                by_rva.setdefault(s[target_rva_key], s)

    added = augmented = 0
    for name, rva in ported:
        existing = by_name.get(name)
        occupant = by_rva.get(rva)
        if occupant is not None and occupant.get('n') != name:
            continue
        if existing is not None and existing.get(target_rva_key) not in (None, rva):
            continue
        if existing is not None and target_rva_key not in existing:
            existing[target_rva_key] = rva
            existing.setdefault("src_bytesig", src_tag)
            existing.setdefault('target_sha256', {})[target_rva_key] = \
                target_manifest['sha256']
            section = _section_for_rva(target_manifest, rva)
            if section:
                existing.setdefault('sections', {})[target_rva_key] = section
            augmented += 1
        elif existing is None:
            entry = {
                "n": name, "t": "func", "sig": "",
                target_rva_key: rva,
                "src": src_tag,
                'target_sha256': {target_rva_key: target_manifest['sha256']},
            }
            section = _section_for_rva(target_manifest, rva)
            if section:
                entry['sections'] = {target_rva_key: section}
            syms.append(entry)
            by_name[name] = entry
            by_rva[rva] = entry
            added += 1
    # Preserve the safe-loads wrapper so JSON ``false``/``true``/``null``
    # round-trip through the rewrite (see ghidra_import_gen.py).  Always
    # write the wrapped form -- backward-compatible with both reader paths.
    symbols_json = json.dumps(syms, separators=(",", ":"))
    new_blob = "SYMBOLS = _json_sym.loads(" + repr(symbols_json) + ")"
    content = content[:m.start()] + new_blob + content[m.end():]
    temporary = script.with_name(script.name + '.tmp')
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, script)
    print(f"  {fname}: merged {augmented} augmented + {added} new entries "
          f"({len(ported)} ported)")

    return augmented + added


def _runtime_boundaries(path: Path):
    extracted = extract_runtime_functions(str(path))
    rows = extracted.get('runtime_functions', [])
    if not rows:
        raise RuntimeError('{} has no validated AMD64 runtime functions'.format(path))
    return ({int(row['begin_rva']): int(row['size']) for row in rows},
            {int(row['begin_rva']) for row in rows})


def _reconcile_pairs(pairs):
    unique = set(pairs)
    names = {}
    targets = {}
    for name, rva in unique:
        names.setdefault(name, set()).add(rva)
        targets.setdefault(rva, set()).add(name)
    return sorted((name, rva) for name, rva in unique
                  if len(names[name]) == 1 and len(targets[rva]) == 1)


TARGET_TO_RVA_KEY = {"og": "og", "ng": "ng", "vr": "v", "221": "221", "ae": "a"}

# --- Address-library emit (item ①) ------------------------------------------
# The byte-sig port resolves (name -> target_rva); re-attaching the source
# AE/NG address-library ID can emit an id,offset file -- but ONLY where the
# target shares the source's ID namespace.
#
# EMPIRICAL (cross-check vs the official bins): OG (1.10.163) uses a DISJOINT
# id namespace from AE -- OG ids run 0..1.58M, AE ids run 15..8.7M, and every
# AE-derived id resolves to ZERO OG-bin entries.  So an AE-id-keyed OG file is
# meaningless to an OG consumer, exactly like VR.  Only NG/AE/221 share AE's
# namespace, and those already ship official bins, so an emit there is valid
# but redundant.  Net: F4 has no address library this usefully produces -- the
# emitter's real home is Starfield future-patch versionlibs (consistent 1.16.x
# namespace, no official bin).  This wiring stays as the validated harness +
# correctness cross-check; it refuses the disjoint F4 targets by default.
ADDRLIB_DIR        = _PROJECT_DIR / "addresslibrary" / "f4"
TARGET_TO_VERSION  = {"og": "1-10-163-0", "ng": "1-10-984-0",
                      "ae": "1-11-191-0", "221": "1-11-221-0", "vr": "1-2-72-0"}
_SHARED_NS_TARGETS = {"ng", "ae", "221"}  # OG + VR are disjoint (verified empirically)


def _emit_addrlib_supplement(tgt, ported, name_to_id, ambiguous,
                             allow_disjoint=False):
    """Emit an ``id,offset`` supplement CSV for `tgt` from the byte-sig pairs.

    Cross-checks against meh321's official bin (if shipped): overlapping IDs
    must agree -- that validates the byte-sig chain -- and the remainder is the
    net-new supplement (IDs meh hasn't published for this build).
    """
    if tgt not in _SHARED_NS_TARGETS and not allow_disjoint:
        print(f"  [addrlib] {tgt.upper()}: disjoint ID namespace -- refusing to "
              f"emit (pass --allow-disjoint-namespace to override).")
        return
    id_to_rva, stats = join_ids(ported, name_to_id, ambiguous)
    if not id_to_rva:
        print(f"  [addrlib] {tgt.upper()}: no id-keyed pairs to emit.")
        return
    ver = TARGET_TO_VERSION.get(tgt, tgt)

    overlap = match = mismatch = 0
    official = F4AddressLibrary().load_bin(str(ADDRLIB_DIR / f"version-{ver}.bin"))
    if official:
        for sid, rva in id_to_rva.items():
            off = official.get(sid)
            if off is None:
                continue
            overlap += 1
            if off == rva:
                match += 1
            else:
                mismatch += 1
    net_new = len(id_to_rva) - overlap

    out = ADDRLIB_DIR / f"version-{ver}-supplement.csv"
    write_addrlib_csv(str(out), id_to_rva, version_label=ver,
                      note=f"bytesig-supplement net-new={net_new}")
    print(f"  [addrlib] {tgt.upper()}: emitted {len(id_to_rva):,} ids "
          f"(joined {stats['joined']}, no-id {stats['dropped_no_id']}, "
          f"ambig {stats['dropped_ambiguous']}, conflict {stats['dropped_conflict']})")
    if official:
        rate = 100.0 * match / overlap if overlap else 0.0
        print(f"  [addrlib] {tgt.upper()}: vs official bin -- overlap {overlap:,}, "
              f"match {match:,} ({rate:.1f}%), MISMATCH {mismatch:,}, "
              f"NET-NEW {net_new:,}")
        if overlap > 50 and mismatch > overlap * 0.02:
            print(f"  [addrlib] WARNING: >2% mismatch -- byte-sig port may be "
                  f"placing some functions at wrong addresses; inspect before use.")
    print(f"  [addrlib] wrote {out}")


_F4_221_PDB_PUBLICS = (
    _PROJECT_DIR / "scripts" / "commonlibf4" / "refs" / "f4_221_pdb_publics.txt")


def _load_f4_221_pdb_names(target_pe: Path) -> dict[str, int]:
    """Reciprocal-unique function starts from the community PDB corpus."""
    if not _F4_221_PDB_PUBLICS.is_file():
        return {}
    from pdb_publics_f4_221 import load_executable_name_rvas
    target_manifest = inspect_pe(str(target_pe))
    rows = load_executable_name_rvas(
        str(target_pe), target_manifest['sha256'])
    bad_substr = ("RTTI_", "::`vftable'", "::`RTTI",
                  "type_info::", "`typeinfo for", "anonymous namespace",
                  "`vector-deleting-destructor", "<lambda_")
    name_rx = re.compile(r"^[A-Za-z_][\w:]*$")
    normalized: dict[str, set[int]] = {}
    for raw, rva in rows.items():
        if any(b in raw for b in bad_substr):
            continue
        qname = raw.split("(", 1)[0].strip()
        if (not qname or "<" in qname or ">" in qname or
                not name_rx.match(qname)):
            continue
        normalized.setdefault(qname, set()).add(rva)
    return {name: next(iter(rvas)) for name, rvas in normalized.items()
            if len(rvas) == 1}


def run(targets: list[str], emit_addrlib: bool = False,
        allow_disjoint: bool = False) -> None:
    print("=== Fallout 4 cross-version byte-signature port ===")

    # Source binary preference: AE first (has IDA fallback names), then NG
    # (shares the same ID namespace as AE).  NG is a useful fallback when
    # the user only has the NG patch installed locally.
    src_ver = None
    src_path = None
    for cand in ("ae", "ng"):
        p = _binary_for(cand)
        if p is not None and p.is_file():
            src_ver, src_path = cand, p
            break
    if src_ver is None:
        print("  Neither AE nor NG binary present in exes/f4/ — skipping "
              "byte-sig port (OG/VR will have types-only coverage).")
        return
    print(f"  Source binary: F4 {src_ver.upper()} ({src_path.name})")

    name_to_src_rva: dict[str, int] = {}
    primary = _load_commonlib_f4_names(src_ver)
    print(f"  CommonLibImport_F4_{src_ver.upper()}.py: {len(primary):,} names")
    name_to_src_rva.update(primary)

    if src_ver == "ae":
        ida = _load_ida_names(inspect_pe(str(src_path)))
        new_ida = sum(1 for n in ida if n not in name_to_src_rva)
        print(f"  IDAImportNames_1.11.191.0.py: {len(ida):,} names ({new_ida} new)")
        for n, rva in ida.items():
            name_to_src_rva.setdefault(n, rva)

    print(f"  Source name pool: {len(name_to_src_rva):,} unique")

    # For --emit-addrlib: build name->id from the source SYMBOLS (only CommonLib
    # entries carry address-library IDs; IDA/PDB names don't and are dropped).
    name_to_id: dict[str, int] = {}
    ambiguous: set[str] = set()
    if emit_addrlib:
        _src_script = GENERATED_DIR / f"CommonLibImport_F4_{src_ver.upper()}.py"
        src_symbols = ((_extract_symbols_array(
            _src_script.read_text(encoding="utf-8"), "SYMBOLS")
            if _src_script.is_file() else None) or [])
        name_to_id, ambiguous = build_name_to_id(src_symbols)
        print(f"  [addrlib] source name->id: {len(name_to_id):,} "
              f"({len(ambiguous)} ambiguous names dropped)")

    print(f"  Loading source binary: {src_path}")
    src_manifest = inspect_pe(str(src_path))
    src_function_sizes, _src_function_starts = _runtime_boundaries(src_path)
    _, src_text_rva, src_text = load_pe_text(str(src_path))
    print(f"    .text RVA={src_text_rva:#x} size={len(src_text):,}")

    src_rvas = list(name_to_src_rva.items())

    # Cache masked source signatures across the target loop -- Capstone
    # disasm of N source RVAs is otherwise repeated per target.
    src_sig_cache_ae: dict[int, tuple] = {}
    target_manifests: dict[str, dict] = {}
    touched_targets: set[str] = set()

    for tgt in targets:
        if tgt == src_ver:
            continue  # don't port a binary to itself
        tgt_path = _binary_for(tgt)
        if tgt_path is None or not tgt_path.is_file():
            print(f"  {tgt.upper()}: binary not present in exes/f4/{tgt}/ — "
                  f"skipping")
            continue
        print(f"\n  --- {src_ver.upper()} -> {tgt.upper()} ---")
        print(f"  Loading {tgt.upper()} binary: {tgt_path.name}")
        target_manifest = inspect_pe(str(tgt_path))
        _target_sizes, target_function_starts = _runtime_boundaries(tgt_path)
        target_manifests[tgt] = target_manifest
        _, tgt_text_rva, tgt_text = load_pe_text(str(tgt_path))
        print("  Building prefix index ...")
        tgt_idx = build_prefix_index(tgt_text, k=6)
        print(f"    {len(tgt_idx):,} unique 6-byte prefixes")

        print("  Pass 1: exact 32-byte match ...")
        ported, stats = port_symbols(
            src_rvas, src_text_rva, src_text,
            tgt_text_rva, tgt_text, tgt_idx,
            window=32, prefix_k=6, masked=False, progress_every=0,
            src_function_sizes=src_function_sizes,
            target_function_starts=target_function_starts)
        print(f"    exact: ok={stats['ok']:,} no_prefix={stats['no_prefix']:,} "
              f"ambig={stats['ambiguous_or_zero']:,} miss_src={stats['missing_src']:,}")

        ported_names = {n for n, _ in ported}
        unmatched = [(n, r) for (n, r) in src_rvas if n not in ported_names]
        if unmatched:
            print(f"  Pass 2: masked 48-byte retry on {len(unmatched):,} unmatched ...")
            try:
                ported2, stats2 = port_symbols(
                    unmatched, src_text_rva, src_text,
                    tgt_text_rva, tgt_text, tgt_idx,
                    window=48, prefix_k=6, masked=True, progress_every=0,
                    src_sig_cache=src_sig_cache_ae,
                    src_function_sizes=src_function_sizes,
                    target_function_starts=target_function_starts)
                ported.extend(ported2)
                print(f"    masked: ok={stats2['ok']:,} "
                      f"no_prefix={stats2['no_prefix']:,} "
                      f"ambig={stats2['ambiguous_or_zero']:,}")
            except ImportError as e:
                print(f"    SKIPPED ({e}) — install capstone+numpy for the "
                      f"cross-build masked-retry pass")

        ported = _reconcile_pairs(ported)
        evidence_path = (_SCRIPT_DIR / 'refs' /
                         f'bytesig_ported_{tgt}.csv')
        persist_bytesig_evidence(
            evidence_path, ported, '{}-bytesig-port'.format(src_ver.upper()),
            src_manifest, target_manifest, source_rvas=name_to_src_rva)
        touched_targets.add(tgt)
        if emit_addrlib:
            _emit_addrlib_supplement(tgt, ported, name_to_id, ambiguous,
                                     allow_disjoint)

    # --- 1.11.221 PDB-public source pass ---
    # The reviewed community corpus has ~25k reciprocal-unique `.pdata`
    # function starts for 1.11.221 after ambiguity quarantine.
    # Most names aren't in CommonLibF4 / IDA's AE source pool, so an
    # AE-side port misses them entirely.  Run a second pass with the 221
    # binary as the source so OG / NG / AE / VR each inherit the PDB
    # names CommonLibF4 doesn't document.
    src221_path = _binary_for("221")
    pdb_names = (_load_f4_221_pdb_names(src221_path)
                 if src221_path is not None and src221_path.is_file() else {})
    if not pdb_names and src221_path is not None and src221_path.is_file():
        print("\n  No 1.11.221 PDB-public source pool — skip 221-source pass.")
    elif src221_path is None or not src221_path.is_file():
        print(f"\n  exes/f4/221/Fallout4.exe not present — skip 221-source pass.")
    else:
        print(f"\n=== 1.11.221 PDB-public source pass ===")
        print(f"  Source binary: F4 221 ({src221_path.name})")
        print(f"  Source name pool: {len(pdb_names):,} unique PDB publics")
        print(f"  Loading source binary: {src221_path}")
        src221_manifest = inspect_pe(str(src221_path))
        src221_function_sizes, _ = _runtime_boundaries(src221_path)
        _, src221_text_rva, src221_text = load_pe_text(str(src221_path))
        print(f"    .text RVA={src221_text_rva:#x} size={len(src221_text):,}")
        src221_rvas = list(pdb_names.items())

        # Same cache trick for the 221-source pass.
        src_sig_cache_221: dict[int, tuple] = {}

        for tgt in targets:
            if tgt == "221":
                continue  # already named directly by parse_commonlib_types
            tgt_path = _binary_for(tgt)
            if tgt_path is None or not tgt_path.is_file():
                print(f"  {tgt.upper()}: binary not present in exes/f4/{tgt}/ — "
                      f"skipping")
                continue
            print(f"\n  --- 221 -> {tgt.upper()} ---")
            target_manifest = target_manifests.get(tgt) or inspect_pe(str(tgt_path))
            target_manifests[tgt] = target_manifest
            _, target_function_starts = _runtime_boundaries(tgt_path)
            _, tgt_text_rva, tgt_text = load_pe_text(str(tgt_path))
            tgt_idx = build_prefix_index(tgt_text, k=6)
            print(f"    {len(tgt_idx):,} unique 6-byte prefixes")
            print("  Pass 1: exact 32-byte match ...")
            ported, stats = port_symbols(
                src221_rvas, src221_text_rva, src221_text,
                tgt_text_rva, tgt_text, tgt_idx,
                window=32, prefix_k=6, masked=False, progress_every=0,
                src_function_sizes=src221_function_sizes,
                target_function_starts=target_function_starts)
            print(f"    exact: ok={stats['ok']:,} no_prefix={stats['no_prefix']:,} "
                  f"ambig={stats['ambiguous_or_zero']:,}")
            ported_names = {n for n, _ in ported}
            unmatched = [(n, r) for (n, r) in src221_rvas if n not in ported_names]
            if unmatched:
                print(f"  Pass 2: masked 48-byte retry on {len(unmatched):,} unmatched ...")
                try:
                    ported2, stats2 = port_symbols(
                        unmatched, src221_text_rva, src221_text,
                        tgt_text_rva, tgt_text, tgt_idx,
                        window=48, prefix_k=6, masked=True, progress_every=0,
                        src_sig_cache=src_sig_cache_221,
                        src_function_sizes=src221_function_sizes,
                        target_function_starts=target_function_starts)
                    ported.extend(ported2)
                    print(f"    masked: ok={stats2['ok']:,} "
                          f"no_prefix={stats2['no_prefix']:,} "
                          f"ambig={stats2['ambiguous_or_zero']:,}")
                except ImportError as e:
                    print(f"    SKIPPED ({e})")
            ported = _reconcile_pairs(ported)
            evidence_path = (_SCRIPT_DIR / 'refs' /
                             f'bytesig_ported_{tgt}.csv')
            persist_bytesig_evidence(
                evidence_path, ported, '221-PDB-bytesig-port',
                src221_manifest, target_manifest, source_rvas=pdb_names)
            touched_targets.add(tgt)

    # Consume exactly the reconciled, target-bound artifact.  This final pass
    # handles conflicts not only between exact/masked matches but also between
    # the AE/NG and 221 source corpora.
    for tgt in sorted(touched_targets):
        evidence_path = _SCRIPT_DIR / 'refs' / f'bytesig_ported_{tgt}.csv'
        rows, _identity = load_bytesig_evidence(
            evidence_path, target_manifests[tgt])
        safe_pairs = sorted({(row['name'], row['target_rva']) for row in rows})
        _merge_into_script(
            tgt, TARGET_TO_RVA_KEY[tgt], safe_pairs, target_manifests[tgt])


def main() -> None:
    raw = list(sys.argv[1:])
    emit_addrlib   = "--emit-addrlib" in raw
    allow_disjoint = "--allow-disjoint-namespace" in raw
    args = [a.lower() for a in raw if not a.startswith("--")] or \
        ["og", "ng", "vr", "221"]
    bad = [a for a in args if a not in ("og", "ng", "ae", "vr", "221")]
    if bad:
        print(f"Unknown target(s): {bad}")
        print("Usage: python run_bytesig_port.py [og] [ng] [vr] [221] "
              "[--emit-addrlib] [--allow-disjoint-namespace]")
        sys.exit(2)
    run(args, emit_addrlib=emit_addrlib, allow_disjoint=allow_disjoint)


if __name__ == "__main__":
    main()
