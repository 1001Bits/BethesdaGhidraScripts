#!/usr/bin/env python3
"""Byte-signature port directly against Ghidra programs in a combined
project — no exe files required.

Uses the identity-bound 1.11.221 community public-symbol corpus by default
(~31k publics, much richer than CommonLibF4 alone) and ports matching
names into the other Fallout 4 binaries imported in the same Ghidra
project (OG / NG / AE / VR).  Renames functions in place so no separate
apply pass is needed.

For each target the .text bytes are pulled straight out of the program
via Memory.getBytes; source-name bytes come from the source program's
.text at each name's RVA.  Exact 32-byte match (Pass 1) plus masked
48-byte retry wildcarding rel32 / rip-rel operands (Pass 2) -- same
algorithm as scripts/core/bytesig_port.py.

Usage:
  python scripts/commonlibf4/bytesig_port_combined.py
       --project-dir <dir> --project-name <name>
       [--source 221] [--targets og ng ae vr]

The project is explicit so a similarly named developer-local project is
never selected or mutated implicitly.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import json
import os
import re
import sys
from pathlib import Path

REPO_DIR     = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR   = REPO_DIR / "tools" / "ghidra"
GENERATED    = REPO_DIR / "ghidrascripts"
PDB_PUBLICS  = REPO_DIR / "scripts" / "commonlibf4" / "refs" / "f4_221_pdb_publics.txt"

sys.path.insert(0, str(REPO_DIR / "scripts" / "core"))
from bytesig_port import build_prefix_index, port_symbols  # noqa: E402
from importer_binding import (                         # noqa: E402
    accepts_manifest,
    extract_target_manifests,
)
from bytesig_evidence import (                         # noqa: E402
    load_validated as load_bytesig_evidence,
    persist as persist_bytesig_evidence,
)


# Version → (CommonLibImport filename, [path-substring hints used to find
# the binary inside a combined project]).  Mirrors apply_f4_to_user_project.
VERSIONS = {
    'og':  ('CommonLibImport_F4_OG.py',  ['_og_', '_og.', '/og/', '1_10_163', '1.10.163']),
    'ng':  ('CommonLibImport_F4_NG.py',  ['_ng_', '_ng.', '/ng/', '1_10_984', '1.10.984',
                                          '1_10_980', '1.10.980']),
    'ae':  ('CommonLibImport_F4_AE.py',  ['_ae_', '_ae.', ' ae.exe', '/ae/', '1_11_191', '1.11.191']),
    'vr':  ('CommonLibImport_F4_VR.py',  ['fallout4vr', 'fallout4_vr', '/vr/', '1_2_72', '1.2.72']),
    # '/221/' covers this repo's own import layout (exes/f4/221/Fallout4.exe imports as
    # /f4/221/Fallout4.exe.unpacked.exe); the underscore forms cover hand-named binaries.
    '221': ('CommonLibImport_F4_221.py',
            ['_221.exe', '_221_', '/221/', '1_11_221', '1.11.221']),
}

VERSION_TO_RVA_KEY = {'og': 'og', 'ng': 'ng', 'ae': 'a', 'vr': 'v', '221': '221'}

_JSON_LOADS_RE = re.compile(r"^_json(?:_sym)?\.loads\((.+)\)$")


def _read_symbols_from_script(version: str) -> dict[str, int]:
    """{name: rva} from CommonLibImport_F4_<VER>.py SYMBOLS array.

    Tolerates both the raw-JSON and ``_json_sym.loads(...)`` wrapped
    forms emitted by ghidra_import_gen.py.
    """
    script_name = VERSIONS[version][0]
    p = GENERATED / script_name
    if not p.is_file():
        return {}
    content = p.read_text(encoding="utf-8")
    m = re.search(r"^SYMBOLS = (.+?)$", content, re.M)
    if not m:
        return {}
    val = m.group(1).strip()
    wrap = _JSON_LOADS_RE.match(val)
    if wrap is not None:
        val = ast.literal_eval(wrap.group(1))
    syms = json.loads(val)
    rva_key = VERSION_TO_RVA_KEY[version]
    out: dict[str, int] = {}
    for s in syms:
        if s.get('t') != 'func':
            continue
        rva = s.get(rva_key)
        name = s.get('n', '')
        if not rva or not name or '<' in name or '>' in name:
            continue
        out.setdefault(name, rva)
    return out


def _read_f4_221_pdb_publics(source_sha256: str) -> dict[str, int]:
    """Load PDB names only through its exact PE/CodeView-bound loader."""
    from pdb_publics_f4_221 import load_executable_name_rvas
    candidates = []
    exes_root = REPO_DIR / 'exes' / 'f4' / '221'
    if exes_root.is_dir():
        import hashlib
        for path in sorted(exes_root.glob('*.exe')):
            if hashlib.sha256(path.read_bytes()).hexdigest() == source_sha256:
                candidates.append(path)
    if len(candidates) != 1:
        print('  detached F4 221 PDB dump disabled: no single exact local '
              'PE/CodeView source for Ghidra SHA {}'.format(source_sha256))
        return {}
    rows = load_executable_name_rvas(str(candidates[0]), source_sha256)
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
        normalized.setdefault(qname, set()).add(int(rva))
    return {name: next(iter(rvas)) for name, rvas in normalized.items()
            if len(rvas) == 1}


def _find_program(root, hints: list[str], stem: str = "Fallout4",
                  exact_path: str | None = None):
    """Find one program by hint substrings OR by exact path.

    ``exact_path`` (e.g. ``/Fallout4/Fallout4_AE_1_11_191.exe``) bypasses
    hint matching entirely -- useful when two binaries share the same
    hints (e.g. NG 1.10.984 and 1.10.980, or Steam vs GOG variants) and
    the caller wants a specific one.  Returns ``(full_path, domain_file)``
    on a single match, ``None`` otherwise.
    """
    matches = []

    def walk(folder, prefix=""):
        for f in folder.getFiles():
            n = f.getName()
            full = prefix + "/" + n
            if exact_path is not None:
                if full == exact_path:
                    matches.append((full, f))
            else:
                if not n.lower().endswith('.exe'):
                    continue
                if any(h in full.lower() for h in hints):
                    matches.append((full, f))
        for sub in folder.getFolders():
            walk(sub, prefix + "/" + sub.getName())

    walk(root)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(f"  AMBIGUOUS: {len(matches)} candidates matched "
              f"{'hint' if exact_path is None else 'exact path'}; pick one via "
              f"--source-path / --target-paths:")
        for path, _ in matches:
            print(f"    {path}")
    return None


def _section_for_rva(manifest, rva):
    for section in manifest.get('sections', []):
        start = int(section.get('rva', 0))
        end = start + max(int(section.get('virtual_size', 0)),
                          int(section.get('raw_size', 0)))
        if start <= rva < end:
            return section.get('name', '')
    return ''


def _bound_script_manifest(script, program_manifest):
    sha = program_manifest['sha256'].lower()
    candidates = [item for item in extract_target_manifests(script)
                  if item['sha256'].lower() == sha]
    if len(candidates) != 1:
        raise RuntimeError('{} is not bound to Ghidra target {}'.format(
            script.name, sha))
    return accepts_manifest(script, candidates[0])


def _merge_into_target_script(target: str, ported: list[tuple[str, int]],
                              src_tag: str, source_manifest: dict,
                              target_manifest: dict,
                              source_rvas: dict[str, int]) -> int:
    """Merge (name, target_rva) entries into CommonLibImport_F4_<TARGET>.py's
    SYMBOLS array.  Tolerates raw-JSON or _json_sym.loads-wrapped literal;
    re-emits the wrapped form so JSON booleans round-trip safely.
    """
    refs_csv = (REPO_DIR / "scripts" / "commonlibf4" / "refs" /
                f"bytesig_ported_{target}.csv")
    persist_bytesig_evidence(
        refs_csv, ported, src_tag, source_manifest, target_manifest,
        source_rvas=source_rvas)
    rows, _ = load_bytesig_evidence(refs_csv, target_manifest)
    # Multiple independent sources may corroborate the same pair.  Apply it
    # once after the artifact-wide reciprocal conflict check.
    ported = sorted({(row['name'], row['target_rva']) for row in rows})

    rva_key = VERSION_TO_RVA_KEY[target]
    script_name = VERSIONS[target][0]
    p = GENERATED / script_name
    if not p.is_file():
        print(f"  {script_name}: not found, skipping write-back")
        return 0
    target_manifest = _bound_script_manifest(p, target_manifest)
    content = p.read_text(encoding="utf-8")
    m = re.search(r"^SYMBOLS = (.+?)$", content, re.M)
    if not m:
        print(f"  {script_name}: no SYMBOLS array, skipping write-back")
        return 0
    val = m.group(1).strip()
    wrap = _JSON_LOADS_RE.match(val)
    if wrap is not None:
        syms = json.loads(ast.literal_eval(wrap.group(1)))
    else:
        syms = json.loads(val)

    by_name = {s["n"]: s for s in syms if s.get("t") == "func"}
    by_rva = {s.get(rva_key): s for s in syms
              if s.get('t') == 'func' and s.get(rva_key)}
    added = augmented = 0
    for name, rva in ported:
        existing = by_name.get(name)
        occupant = by_rva.get(rva)
        if occupant is not None and occupant.get('n') != name:
            continue
        if existing is not None:
            if existing.get(rva_key) not in (None, rva):
                continue
            if rva_key not in existing:
                existing[rva_key] = rva
                existing.setdefault("src_bytesig", src_tag)
                existing.setdefault('target_sha256', {})[rva_key] = \
                    target_manifest['sha256']
                section = _section_for_rva(target_manifest, rva)
                if section:
                    existing.setdefault('sections', {})[rva_key] = section
                augmented += 1
            continue
        entry = {
            "n": name, "t": "func", "sig": "",
            rva_key: rva, "src": src_tag,
            'target_sha256': {rva_key: target_manifest['sha256']},
        }
        section = _section_for_rva(target_manifest, rva)
        if section:
            entry['sections'] = {rva_key: section}
        syms.append(entry)
        by_name[name] = entry
        by_rva[rva] = entry
        added += 1
    if added == 0 and augmented == 0:
        print(f"  {script_name}: no new SYMBOLS to merge")
        return 0
    symbols_json = json.dumps(syms, separators=(",", ":"))
    new_blob = "SYMBOLS = _json_sym.loads(" + repr(symbols_json) + ")"
    content = content[:m.start()] + new_blob + content[m.end():]
    temporary = p.with_name(p.name + '.tmp')
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, p)
    print(f"  {script_name}: merged {augmented} augmented + {added} new "
          f"entries ({len(ported)} ported)")

    return augmented + added


def _persist_ported_csv(refs_csv: Path, ported: list[tuple[str, int]],
                        src_tag: str, source_manifest: dict,
                        target_manifest: dict,
                        source_rvas: dict[str, int] | None = None):
    """Compatibility wrapper for the identity-bound evidence writer."""
    rows = persist_bytesig_evidence(
        refs_csv, ported, src_tag, source_manifest, target_manifest,
        source_rvas=source_rvas)
    print(f"  persisted {len(rows):,} identity-bound pairs -> {refs_csv}")
    return rows


def _load_text_block(program):
    """Return (image_base, text_rva, text_bytes) for the .text block.

    Reads via a Java byte[] in 64 KB chunks (a Python bytearray passes
    by value and stays all zeros, and a one-shot 37 MB JArray sometimes
    fails class resolution depending on JVM init order).  Mirrors the
    chunked pattern in core/run_vtable_pipeline.py.
    """
    import jpype
    mem = program.getMemory()
    block = mem.getBlock('.text')
    if block is None:
        raise RuntimeError(f"{program.getName()}: no .text block")
    image_base = program.getImageBase().getOffset() & 0xFFFFFFFFFFFFFFFF
    start_addr = block.getStart()
    text_rva = (start_addr.getOffset() & 0xFFFFFFFFFFFFFFFF) - image_base
    size = block.getSize()

    ByteArray = jpype.JArray(jpype.JByte)
    CHUNK = 64 * 1024
    out = bytearray(size)
    for off in range(0, size, CHUNK):
        n = min(CHUNK, size - off)
        buf = ByteArray(n)
        block.getBytes(start_addr.add(off), buf, 0, n)
        # bytes(buf) uses JPype's buffer-protocol bulk-copy (C memcpy)
        # instead of a per-byte Python loop -- ~100x faster for 37 MB.
        out[off:off + n] = bytes(buf)
    return image_base, text_rva, bytes(out)


def _rename_in_program(program, ported: list[tuple[str, int]]) -> dict[str, int]:
    """Apply (name, rva) renames in-place.  Returns stat counters."""
    from ghidra.program.model.symbol import SourceType
    fm = program.getFunctionManager()
    base = program.getImageBase()
    stats = {'renamed': 0, 'already_named': 0, 'no_func': 0, 'errored': 0}
    for name, rva in ported:
        try:
            addr = base.add(int(rva))
            f = fm.getFunctionAt(addr)
            if f is None:
                stats['no_func'] += 1
                continue
            curr = f.getName()
            if f.getSymbol().getSource() in (
                    SourceType.USER_DEFINED, SourceType.IMPORTED):
                stats['already_named'] += 1
                continue
            if not (curr.startswith('FUN_') or curr.startswith('sub_')):
                stats['already_named'] += 1
                continue
            f.setName(name, SourceType.ANALYSIS)
            stats['renamed'] += 1
        except Exception:
            # e.g. DuplicateNameException when the name exists elsewhere in
            # the program; skip this symbol rather than voiding the batch.
            stats['errored'] += 1
    return stats


def _filter_function_entries(program, pairs):
    """Require Ghidra function-entry boundaries and a one-to-one mapping."""
    fm = program.getFunctionManager()
    base = program.getImageBase()
    names = Counter(name for name, _ in pairs)
    rvas = Counter(rva for _, rva in pairs)
    out = []
    for name, rva in pairs:
        if names[name] != 1 or rvas[rva] != 1:
            continue
        if fm.getFunctionAt(base.add(int(rva))) is None:
            continue
        out.append((name, rva))
    return out


def _program_manifest(program, program_path):
    sha = (program.getExecutableSHA256() or '').lower()
    if len(sha) != 64:
        raise RuntimeError(
            '{} lacks executable SHA-256 metadata'.format(program_path))
    base = program.getImageBase().getOffset() & 0xFFFFFFFFFFFFFFFF
    sections = []
    for block in program.getMemory().getBlocks():
        sections.append({
            'name': block.getName(),
            'rva': (block.getStart().getOffset() & 0xFFFFFFFFFFFFFFFF) - base,
            'size': int(block.getSize()),
            'executable': bool(block.isExecute()),
        })
    return {
        'sha256': sha,
        'identity_kind': 'ghidra_program',
        'program_path': program_path,
        'image_base': base,
        'sections': sections,
    }


def _function_boundaries(program):
    base = program.getImageBase().getOffset() & 0xFFFFFFFFFFFFFFFF
    starts = set()
    sizes = {}
    for function in program.getFunctionManager().getFunctions(True):
        entry = function.getEntryPoint().getOffset() & 0xFFFFFFFFFFFFFFFF
        rva = entry - base
        starts.add(rva)
        try:
            body = function.getBody()
            size = (body.getMaxAddress().getOffset() -
                    body.getMinAddress().getOffset() + 1)
            if size > 0:
                sizes[rva] = size
        except Exception:
            pass
    return sizes, starts


def _reconcile_pairs(pairs):
    unique = set(pairs)
    names = Counter(name for name, _ in unique)
    rvas = Counter(rva for _, rva in unique)
    return sorted((name, rva) for name, rva in unique
                  if names[name] == 1 and rvas[rva] == 1)


def _port_pair(src_name_to_rva, src_text_rva, src_text,
               tgt_text_rva, tgt_text, src_sig_cache=None,
               src_function_sizes=None, target_function_starts=None):
    """Run Pass 1 (exact 32 B) + Pass 2 (masked 48 B) and return ported list.

    ``src_sig_cache`` is shared across the target loop so Capstone disasm
    only happens once per source RVA (otherwise repeated per target).
    """
    src_pairs = list(src_name_to_rva.items())
    tgt_idx = build_prefix_index(tgt_text, k=6)
    ported, stats = port_symbols(
        src_pairs, src_text_rva, src_text,
        tgt_text_rva, tgt_text, tgt_idx,
        window=32, prefix_k=6, masked=False, progress_every=0,
        src_function_sizes=src_function_sizes,
        target_function_starts=target_function_starts)
    print(f"    exact: ok={stats['ok']:,} no_prefix={stats['no_prefix']:,} "
          f"ambig={stats['ambiguous_or_zero']:,} miss_src={stats['missing_src']:,}")
    ported_names = {n for n, _ in ported}
    unmatched = [(n, r) for n, r in src_pairs if n not in ported_names]
    if unmatched:
        print(f"  Pass 2: masked 48-byte retry on {len(unmatched):,} ...")
        try:
            ported2, stats2 = port_symbols(
                unmatched, src_text_rva, src_text,
                tgt_text_rva, tgt_text, tgt_idx,
                window=48, prefix_k=6, masked=True, progress_every=0,
                src_sig_cache=src_sig_cache,
                src_function_sizes=src_function_sizes,
                target_function_starts=target_function_starts)
            ported.extend(ported2)
            print(f"    masked: ok={stats2['ok']:,} "
                  f"no_prefix={stats2['no_prefix']:,} "
                  f"ambig={stats2['ambiguous_or_zero']:,}")
        except ImportError as e:
            print(f"    SKIPPED ({e}) — install capstone+numpy for Pass 2")
    return _reconcile_pairs(ported)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir', required=True)
    ap.add_argument('--project-name', required=True)
    ap.add_argument('--source', default='221', choices=sorted(VERSIONS),
                    help="Source F4 variant whose name pool drives the port "
                         "(default 221 — has the richest PDB pool)")
    ap.add_argument('--targets', nargs='+', default=['og', 'ng', 'ae', 'vr'],
                    choices=sorted(VERSIONS),
                    help="Target F4 variants to improve (default: all except 221)")
    ap.add_argument('--source-path', default=None,
                    help="Exact source program path (overrides hint match)")
    ap.add_argument('--target-paths', nargs='+', default=None,
                    metavar='VER=PATH',
                    help="Exact target program path(s) keyed by version, e.g. "
                         "ae=/Fallout4/Fallout4_AE_1_11_191.exe")
    ap.add_argument('--write-back-script', action='store_true',
                    help="Merge ported (name, target_rva) pairs into the "
                         "target's CommonLibImport_F4_<VER>.py SYMBOLS array")
    ap.add_argument('--no-apply', action='store_true',
                    help="Skip the in-Ghidra rename pass")
    args = ap.parse_args()

    if args.source in args.targets:
        args.targets = [t for t in args.targets if t != args.source]

    # Parse --target-paths VER=PATH overrides into {version: path}
    target_path_overrides: dict[str, str] = {}
    if args.target_paths:
        for spec in args.target_paths:
            if '=' not in spec:
                print(f"  WARNING: --target-paths entry {spec!r} lacks '='; ignoring")
                continue
            ver, path = spec.split('=', 1)
            if ver not in VERSIONS:
                print(f"  WARNING: unknown version {ver!r} in --target-paths; ignoring")
                continue
            target_path_overrides[ver] = path

    src_names = _read_symbols_from_script(args.source)
    print(f"Source: F4 {args.source.upper()}")
    print(f"  CommonLibImport_F4_{args.source.upper()}.py SYMBOLS: {len(src_names):,}")
    print(f"  Initial source name pool: {len(src_names):,} unique")

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    print(f"\nOpening project: {args.project_dir}/{args.project_name}.gpr")
    with pyghidra.open_project(args.project_dir, args.project_name, create=False) as project:
        root = project.getProjectData().getRootFolder()

        # Source program (read-only: just need .text bytes)
        src_hint = VERSIONS[args.source][1]
        src_match = _find_program(root, src_hint, exact_path=args.source_path)
        if src_match is None:
            print(f"ERROR: source {args.source} program not found in project.")
            sys.exit(1)
        src_path, src_df = src_match
        print(f"Source program: {src_path}")

        consumer = java.lang.Object()
        src_prog = src_df.getDomainObject(consumer, False, False, monitor)
        try:
            source_manifest = _program_manifest(src_prog, src_path)
            source_script = GENERATED / VERSIONS[args.source][0]
            _bound_script_manifest(source_script, source_manifest)
            if args.source == '221':
                pdb = _read_f4_221_pdb_publics(source_manifest['sha256'])
                new_pdb = sum(1 for name in pdb if name not in src_names)
                for name, rva in pdb.items():
                    src_names.setdefault(name, rva)
                print(f"  + identity-validated 1.11.221 PDB publics: "
                      f"{len(pdb):,} ({new_pdb} new)")
            source_pairs = _filter_function_entries(
                src_prog, list(src_names.items()))
            src_names = dict(source_pairs)
            print(f"  source symbols at exact function entries: {len(src_names):,}")
            src_function_sizes, _ = _function_boundaries(src_prog)
            _, src_text_rva, src_text = _load_text_block(src_prog)
            print(f"  source .text rva={src_text_rva:#x} size={len(src_text):,}")
        finally:
            src_prog.release(consumer)

        # Target programs
        grand_total = 0
        # Cache masked source signatures across the target loop -- Capstone
        # disasm of 90k+ source RVAs is otherwise repeated per target.
        src_sig_cache: dict[int, tuple] = {}
        for tgt in args.targets:
            tgt_hint = VERSIONS[tgt][1]
            tgt_match = _find_program(root, tgt_hint,
                                      exact_path=target_path_overrides.get(tgt))
            if tgt_match is None:
                print(f"\n  {tgt.upper()}: program not found in project — skip")
                continue
            tgt_path, tgt_df = tgt_match
            print(f"\n--- {args.source.upper()} -> {tgt.upper()}  ({tgt_path}) ---")

            tgt_prog = tgt_df.getDomainObject(consumer, True, False, monitor)
            try:
                target_manifest = _program_manifest(tgt_prog, tgt_path)
                _, target_function_starts = _function_boundaries(tgt_prog)
                _, tgt_text_rva, tgt_text = _load_text_block(tgt_prog)
                print(f"  target .text rva={tgt_text_rva:#x} size={len(tgt_text):,}")
                print("  Pass 1: exact 32-byte match ...")
                ported = _port_pair(src_names, src_text_rva, src_text,
                                    tgt_text_rva, tgt_text,
                                    src_sig_cache=src_sig_cache,
                                    src_function_sizes=src_function_sizes,
                                    target_function_starts=target_function_starts)
                ported = _filter_function_entries(tgt_prog, ported)
                if not ported:
                    print("  no matches — nothing to apply")
                    continue
                if args.no_apply:
                    print(f"  --no-apply: skipping in-Ghidra rename "
                          f"({len(ported):,} would-be renames)")
                else:
                    print(f"  Applying {len(ported):,} renames to {tgt_path} ...")
                    tx = tgt_prog.startTransaction(
                        f"bytesig port {args.source}->{tgt}")
                    commit = False
                    try:
                        stats = _rename_in_program(tgt_prog, ported)
                        commit = True
                    finally:
                        tgt_prog.endTransaction(tx, commit)
                    print(f"  renamed={stats['renamed']:,} "
                          f"already_named={stats['already_named']:,} "
                          f"no_func={stats['no_func']:,} "
                          f"errored={stats['errored']:,}")
                    grand_total += stats['renamed']
                    tgt_prog.save(f"bytesig port {args.source}->{tgt}", monitor)
                if args.write_back_script:
                    _merge_into_target_script(
                        tgt, ported,
                        src_tag=f'{args.source.upper()}-PDB-bytesig-port',
                        source_manifest=source_manifest,
                        target_manifest=target_manifest,
                        source_rvas=src_names)
            finally:
                tgt_prog.release(consumer)

        print(f"\nTOTAL renames applied across {len(args.targets)} target(s): "
              f"{grand_total:,}")


if __name__ == '__main__':
    main()
