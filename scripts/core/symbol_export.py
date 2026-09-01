#!/usr/bin/env python3
"""Export an improved Ghidra program's symbols to distributable formats.

Produces, for a program that this pipeline (or any analysis) has already
named/typed, three baseline sibling files in ``out_dir``:

  - ``<module>.symbols.json`` -- full map: image base + functions / data
    labels / vtables, each with module-relative RVA (and optional prototype).
  - ``<module>.map``          -- plain ``<rva>  <name>`` lines, sorted by RVA
    (human-readable; greppable; loads into many tools).
  - ``<module>.dd64``         -- x64dbg JSON database (``labels`` array, keyed
    by module + RVA) that x64dbg imports directly (File > Database > Import).

With ``--pdb`` it also emits stable FakePDB v0.3 input and a real, exact-PE
GUID/age-bound public-symbol PDB.  The result is round-trip checked before it
is installed.  ``--package`` adds a versioned ZIP for sharing.  Synthetic PDBs
carry names/RVAs only; the JSON remains authoritative for prototypes and other
rich metadata.  This script does not add analysis and never modifies the
project.

Usage:
  python symbol_export.py <project_dir> <project_name> <program_path> <out_dir>
                          [--module name.exe] [--signatures]
                          [--pdb] [--package] [--include-analysis]

``program_path`` is the in-project path (e.g. ``/Starfield/Starfield 1.16.236``)
or just a program name; resolution mirrors dump_named_funcs.py.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from ghidra_project import open_user_project
from provenance import (PROGRAM_INFO_KEY, pdb_canary_name, validate_manifest)

REPO_DIR   = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))

# Default-generated names carry no information -- drop them from every output.
# Checked against BOTH the leaf and the full (namespaced) name, so a label like
# ``switchD_1402aa534::switchdataD_...`` is caught via its namespace root.
_NOISE_PREFIXES = (
    "FUN_", "thunk_FUN_", "sub_", "LAB_", "DAT_", "UNK_", "SUB_",
    "switchD_", "switchdataD_", "caseD_", "PTR_", "u_", "s_", "j_",
)


def _is_noise(name: str) -> bool:
    return name.startswith(_NOISE_PREFIXES)


def _classify_label(name: str) -> str:
    """Bucket a non-function label for the JSON output."""
    if name.startswith("VTABLE_"):
        return "vtable"
    if name.startswith(("RTTI_", "NiRTTI_")):
        return "rtti"
    return "data"


def _module_basename(module):
    value = os.path.basename(str(module).replace("\\", "/")).strip()
    if value in ("", ".", ".."):
        raise ValueError("module must contain a filename")
    return value


def _public_target_manifest(target_manifest):
    """Strip executable bytes/function indexes from distributable metadata."""
    if not isinstance(target_manifest, dict):
        return None
    keys = ("schema", "file_name", "file_size", "machine", "machine_name",
            "pointer_size", "image_base", "image_size", "timestamp",
            "file_version", "version_string", "sha256")
    public = {key: target_manifest[key] for key in keys
              if key in target_manifest}
    if isinstance(target_manifest.get("sections"), list):
        section_keys = ("name", "rva", "virtual_size", "raw_size",
                        "raw_offset", "characteristics", "readable",
                        "writable", "executable")
        public["sections"] = [
            {key: section[key] for key in section_keys if key in section}
            for section in target_manifest["sections"]]
    return public


def _resolve_program(project, program_path, monitor):
    import java.lang  # noqa: F401
    pd = project.getProjectData()
    df = None
    if program_path.startswith("/"):
        df = pd.getFile(program_path)
    if df is None:
        target = program_path.lstrip("/").split("/")[-1]

        matches = []

        def walk(folder):
            for f in folder.getFiles():
                if f.getName() == target:
                    matches.append(f)
            for sub in folder.getFolders():
                walk(sub)

        walk(pd.getRootFolder())
        if len(matches) > 1:
            raise RuntimeError(
                "ambiguous program basename {!r}; pass its exact project "
                "path".format(target))
        df = matches[0] if matches else None
    return df


def collect(program, want_sigs=False, image_size=None):
    """Walk the program once; return (image_base, functions, labels)."""
    from ghidra.program.model.symbol import SourceType, SymbolType

    image_base = program.getImageBase().getOffset()
    default_space = program.getAddressFactory().getDefaultAddressSpace()

    def rva_of(addr):
        if addr is None or addr.getAddressSpace() != default_space:
            return None
        return addr.getOffset() - image_base

    # --- functions -------------------------------------------------------
    functions = []
    fm = program.getFunctionManager()
    for func in fm.getFunctions(True):
        leaf = func.getName()
        symbol = func.getSymbol()
        if (symbol is None or
                (symbol.getSource() == SourceType.DEFAULT and _is_noise(leaf))):
            continue
        rva = rva_of(func.getEntryPoint())
        if (rva is None or rva < 0 or
                (image_size is not None and rva >= image_size)):
            continue
        entry = {"rva": rva, "name": func.getName(True),
                 "source": str(symbol.getSource().name())}
        if want_sigs:
            try:
                entry["proto"] = func.getSignature().getPrototypeString(False)
            except Exception:  # noqa: BLE001
                pass
        functions.append(entry)

    # --- data / vtable / rtti labels ------------------------------------
    # Non-default symbols that are not functions: globals, VTABLE_*, RTTI_*,
    # singletons, etc.  Source==DEFAULT means Ghidra auto-named it -> skip.
    labels = []
    st = program.getSymbolTable()
    seen = set()
    for sym in st.getAllSymbols(False):  # False = exclude dynamic/default
        if sym.getSymbolType() == SymbolType.FUNCTION:
            continue
        if sym.getSource() == SourceType.DEFAULT:
            continue
        leaf = sym.getName()
        full = sym.getName(True)
        # Ghidra analysis labels (s_*, u_*, PTR_*, caseD_*, ...) carry
        # ANALYSIS source, not DEFAULT -- filter by shape or they flood
        # the .map/.dd64 baselines.
        if _is_noise(leaf) or _is_noise(full):
            continue
        rva = rva_of(sym.getAddress())
        if (rva is None or rva < 0 or
                (image_size is not None and rva >= image_size)):
            continue
        key = (rva, full)
        if key in seen:
            continue
        seen.add(key)
        labels.append({"rva": rva, "name": full,
                       "kind": _classify_label(leaf),
                       "source": str(sym.getSource().name())})

    functions.sort(key=lambda e: e["rva"])
    labels.sort(key=lambda e: e["rva"])
    return image_base, functions, labels


def _write_text_atomic(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def write_outputs(out_dir, module, image_base, functions, labels,
                  target_manifest=None, bgs_provenance=None):
    module = _module_basename(module)
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.join(out_dir, os.path.splitext(module)[0])

    # 1) JSON symbol map -------------------------------------------------
    vtables = [l for l in labels if l["kind"] == "vtable"]
    data_lbls = [l for l in labels if l["kind"] != "vtable"]
    public_target = _public_target_manifest(target_manifest)
    doc = {
        "module": module,
        "image_base": "0x%X" % image_base,
        "target": public_target,
        "counts": {"functions": len(functions),
                   "labels": len(data_lbls), "vtables": len(vtables)},
        "functions": [{"rva": "0x%X" % f["rva"], **{k: v for k, v in f.items()
                                                    if k != "rva"}}
                      for f in functions],
        "labels": [{"rva": "0x%X" % l["rva"], "name": l["name"],
                    "kind": l["kind"],
                    **({"source": l["source"]} if l.get("source") else {})}
                   for l in data_lbls],
        "vtables": [{"rva": "0x%X" % l["rva"], "name": l["name"],
                     **({"source": l["source"]} if l.get("source") else {})}
                    for l in vtables],
    }
    if bgs_provenance is not None:
        doc["bgs_provenance"] = validate_manifest(bgs_provenance)
    json_path = stem + ".symbols.json"
    _write_text_atomic(json_path, json.dumps(doc, indent=1) + "\n")

    # 2) Plain .map ------------------------------------------------------
    map_path = stem + ".map"
    rows = ([(f["rva"], f["name"]) for f in functions]
            + [(l["rva"], l["name"]) for l in labels])
    rows.sort()
    target_sha = ((public_target or {}).get("sha256") or "unknown")
    map_lines = ["; %s  image_base=0x%X  target_sha256=%s  rva<TAB>name" %
                 (module, image_base, target_sha)]
    map_lines.extend("0x%08X\t%s" % (rva, name) for rva, name in rows)
    _write_text_atomic(map_path, "\n".join(map_lines) + "\n")

    # 3) x64dbg .dd64 ----------------------------------------------------
    # x64dbg database JSON: labels keyed by (module, RVA-as-hex-string).
    # x64dbg matches the module name case-insensitively against its modules
    # list, and treats "address" as the module-relative RVA.
    mod = module.lower()
    dd_labels = [{"module": mod, "address": "0x%X" % rva,
                  "manual": True, "text": name}
                 for rva, name in rows]
    dd_path = stem + ".dd64"
    _write_text_atomic(dd_path, json.dumps({"labels": dd_labels}, indent=1) + "\n")

    identity = {
        "schema": 1,
        "kind": "symbol_export",
        "target": public_target,
        "outputs": {},
    }
    if bgs_provenance is not None:
        identity["bgs_provenance"] = validate_manifest(bgs_provenance)
    for output in (json_path, map_path, dd_path):
        identity["outputs"][os.path.basename(output)] = hashlib.sha256(
            Path(output).read_bytes()).hexdigest()
    _write_text_atomic(
        stem + ".export.identity.json",
        json.dumps(identity, indent=2, sort_keys=True) + "\n")

    return json_path, map_path, dd_path


def collect_segments(target_manifest):
    """Exact PE sections in the stable FakePDB v0.3 JSON schema."""
    if not isinstance(target_manifest, dict):
        raise ValueError("FakePDB segments require a verified PE manifest")
    image_size = int(target_manifest["image_size"])
    segs = []
    previous_end = 0
    for selector, section in enumerate(target_manifest.get("sections", []), 1):
        rva_start = int(section.get("rva", 0))
        span = max(int(section.get("virtual_size", 0)),
                   int(section.get("raw_size", 0)))
        if span <= 0 or rva_start < 0 or rva_start >= image_size:
            raise ValueError("invalid PE section cannot form FakePDB segment")
        rva_end = min(image_size, rva_start + span)
        if rva_start < previous_end:
            raise ValueError("overlapping PE sections cannot form FakePDB segments")
        segs.append({"name": section.get("name") or "section",
                     "start_rva": rva_start, "selector": selector,
                     "type": "CODE" if section.get("executable") else "DATA"})
        previous_end = rva_end
    return segs


def build_fakepdb_root(module, bitness, segments, functions, labels,
                       image_size=None):
    """Assemble the stable FakePDB v0.3 input document.

    v0.3 requires the exact executable on its command line and takes GUID,
    age, machine, and section headers from that PE.  No synthetic identity is
    accepted from JSON.
    """
    del image_size
    return {
        "general": {"filename": module, "architecture": "x86", "bitness": bitness},
        "segments": segments,
        "exports": [],
        "functions": [{"start_rva": f["rva"], "name": f["name"],
                       "is_public": True, "is_autonamed": False, "labels": []}
                      for f in functions],
        "names": [{"rva": l["rva"], "name": l["name"],
                   "is_public": True, "is_func": False} for l in labels],
    }


def add_pdb_provenance_canary(functions, labels, bgs_provenance):
    """Add a transparent PDB alias at an existing real symbol RVA."""
    result = list(labels)
    if bgs_provenance is None:
        return result
    validate_manifest(bgs_provenance)
    candidates = list(functions) + list(labels)
    if not candidates:
        return result
    result.append({"rva": int(candidates[0]["rva"]),
                   "name": pdb_canary_name(bgs_provenance),
                   "source": "BGS_PROVENANCE", "kind": "data"})
    return result


def read_program_provenance(program):
    """Read and fail closed on an invalid stored importer manifest."""
    from ghidra.program.model.listing import Program
    raw = program.getOptions(Program.PROGRAM_INFO).getString(
        PROGRAM_INFO_KEY, "")
    if not raw:
        return None
    return validate_manifest(json.loads(str(raw)))


def _manifest_section(target_manifest, rva):
    for section in target_manifest.get("sections", []):
        start = int(section["rva"])
        span = max(int(section["virtual_size"]), int(section["raw_size"]))
        if start <= int(rva) < start + span:
            return section
    return None


def select_shareable_symbols(functions, labels, target_manifest,
                             include_analysis=False):
    """Select only mapped, reciprocal-unique symbols for a public PDB.

    ``IMPORTED`` and ``USER_DEFINED`` symbols are the safe default.  Analysis
    names can be included explicitly for a research/community snapshot, but
    address/name ambiguity is always quarantined.
    """
    accepted_sources = {"IMPORTED", "USER_DEFINED"}
    if include_analysis:
        accepted_sources.add("ANALYSIS")
    report = {
        "input_functions": len(functions), "input_labels": len(labels),
        "source_filtered": 0, "location_filtered": 0,
        "same_rva_alias_groups": 0, "same_name_multi_rva_groups": 0,
        "quarantined_records": 0,
    }
    candidates = {}
    for kind, entries in (("function", functions), ("label", labels)):
        for entry in entries:
            name = str(entry.get("name") or "").strip()
            source = str(entry.get("source") or "")
            leaf = name.rsplit("::", 1)[-1]
            if not name or _is_noise(name) or _is_noise(leaf):
                report["source_filtered"] += 1
                continue
            if source and source not in accepted_sources:
                report["source_filtered"] += 1
                continue
            rva = int(entry.get("rva", -1))
            section = _manifest_section(target_manifest, rva)
            if section is None or (kind == "function" and
                                   not section.get("executable")):
                report["location_filtered"] += 1
                continue
            key = (rva, name)
            current = candidates.get(key)
            if current is None or kind == "function":
                candidates[key] = (kind, entry)
    by_rva = {}
    by_name = {}
    for rva, name in candidates:
        by_rva.setdefault(rva, set()).add(name)
        by_name.setdefault(name, set()).add(rva)
    ambiguous_rvas = {rva for rva, names in by_rva.items() if len(names) > 1}
    ambiguous_names = {
        name for name, rvas in by_name.items() if len(rvas) > 1}
    report["same_rva_alias_groups"] = len(ambiguous_rvas)
    report["same_name_multi_rva_groups"] = len(ambiguous_names)
    safe_functions = []
    safe_labels = []
    for (rva, name), (kind, entry) in sorted(candidates.items()):
        if rva in ambiguous_rvas or name in ambiguous_names:
            report["quarantined_records"] += 1
            continue
        selected = {"rva": rva, "name": name,
                    "source": entry.get("source", "")}
        if kind == "function":
            safe_functions.append(selected)
        else:
            selected["kind"] = entry.get("kind", "data")
            safe_labels.append(selected)
    report["selected_functions"] = len(safe_functions)
    report["selected_labels"] = len(safe_labels)
    return safe_functions, safe_labels, report


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _verify_generated_pdb(executable, pdb_path, functions, labels,
                          target_manifest):
    from pdb_identity import read_pe_codeview
    from pdb_msf import read_pdb_publics

    expected_identity = read_pe_codeview(str(executable))
    corpus = read_pdb_publics(str(pdb_path))
    if (corpus.guid != expected_identity["guid"] or
            corpus.age != int(expected_identity["age"]) or
            corpus.machine != int(target_manifest["machine"])):
        raise RuntimeError("generated PDB identity does not match target PE")
    manifest_sections = target_manifest.get("sections", [])
    if len(corpus.sections) != len(manifest_sections):
        raise RuntimeError("generated PDB section count differs from target PE")
    for pdb_section, pe_section in zip(corpus.sections, manifest_sections):
        if (pdb_section.name != pe_section["name"] or
                pdb_section.rva != int(pe_section["rva"]) or
                pdb_section.virtual_size != int(pe_section["virtual_size"]) or
                pdb_section.raw_size != int(pe_section["raw_size"]) or
                pdb_section.raw_offset != int(pe_section["raw_offset"]) or
                pdb_section.characteristics !=
                int(pe_section["characteristics"])):
            raise RuntimeError("generated PDB sections differ from target PE")
    expected_functions = {(int(row["rva"]), row["name"])
                          for row in functions}
    expected_labels = {(int(row["rva"]), row["name"]) for row in labels}
    expected = expected_functions | expected_labels
    actual = {(row.rva, row.name) for row in corpus.publics}
    if len(corpus.publics) != len(actual) or actual != expected:
        raise RuntimeError("generated PDB public-symbol round trip differs")
    by_key = {(row.rva, row.name): row for row in corpus.publics}
    if any(not (by_key[key].flags & 0x2) for key in expected_functions):
        raise RuntimeError("generated PDB lost function classification")
    if any(by_key[key].flags & 0x3 for key in expected_labels):
        raise RuntimeError("generated PDB incorrectly classified a data label")
    if corpus.type_record_count or corpus.module_info_size:
        raise RuntimeError("unexpected type/module records in public-only PDB")
    return corpus, expected_identity


def generate_shareable_pdb(executable, fakepdb_json, output_path,
                           functions, labels, target_manifest,
                           selection_report, source_provenance=None):
    """Generate, round-trip validate, and atomically install a synthetic PDB."""
    from fakepdb_tool import validate_fakepdb_install

    tool = validate_fakepdb_install(REPO_DIR)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=output_path.stem + ".", suffix=".pdb",
        dir=str(output_path.parent))
    os.close(fd)
    os.unlink(temporary_name)
    temporary = Path(temporary_name)
    try:
        result = subprocess.run(
            [str(tool), "pdb_generate", str(executable),
             str(fakepdb_json), str(temporary)],
            capture_output=True, text=True, check=False)
        if result.returncode != 0 or not temporary.is_file() \
                or temporary.stat().st_size == 0:
            detail = (result.stderr or result.stdout or "no output").strip()
            raise RuntimeError(
                "FakePDB generation failed (exit {}): {}".format(
                    result.returncode, detail))
        corpus, codeview = _verify_generated_pdb(
            executable, temporary, functions, labels, target_manifest)
        os.replace(temporary, output_path)
    finally:
        if temporary.exists():
            temporary.unlink()
    lock = json.loads((REPO_DIR / "toolchain.lock.json").read_text(
        encoding="utf-8"))["fakepdb"]
    public_target = _public_target_manifest(target_manifest)
    identity = {
        "schema": 1,
        "kind": "community_public_symbols_pdb",
        "synthetic": True,
        "limitations": [
            "public names and RVAs only",
            "no types, prototypes, locals, compilands, source lines, or ranges",
            "GUID/age intentionally match the target and may collide in caches",
        ],
        "target": public_target,
        "codeview": {"guid": codeview["guid"], "age": codeview["age"],
                     "expected_pdb": os.path.basename(
                         str(codeview.get("pdb_path") or ""))},
        "pdb": {"file": output_path.name,
                "sha256": _sha256_file(output_path),
                "size": output_path.stat().st_size,
                "publics": len(corpus.publics),
                "functions": len(functions), "labels": len(labels)},
        "selection": selection_report,
        "input_json": {"file": Path(fakepdb_json).name,
                       "sha256": _sha256_file(fakepdb_json)},
        "generator": {
            "name": "FakePDB", "version": lock["version"],
            "release_tag": lock["release_tag"],
            "source_commit": lock["source_commit"],
            "asset_sha256": lock["sha256"],
            "executable_sha256": lock["executable_sha256"],
            "license": lock["license"],
        },
    }
    if source_provenance is not None:
        identity["source_provenance"] = source_provenance
        identity["bgs_provenance"] = validate_manifest(source_provenance)
    identity_path = Path(str(output_path) + ".identity.json")
    _write_text_atomic(identity_path,
                       json.dumps(identity, indent=2, sort_keys=True) + "\n")
    return output_path, identity_path


def package_symbol_bundle(out_dir, module, pdb_path, pdb_identity_path,
                          symbols_json, target_manifest, revision=1,
                          bgs_provenance=None):
    """Create one versioned ZIP suitable for sharing with other authors."""
    revision = int(revision)
    if revision < 1:
        raise ValueError("symbol-bundle revision must be positive")
    target = _public_target_manifest(target_manifest)
    version = str(target.get("version_string") or "unknown")
    digest = str(target.get("sha256") or "unknown")
    stem = os.path.splitext(_module_basename(module))[0]
    bundle_name = "{}-{}-{}-community-symbols-r{}.zip".format(
        stem, version, digest[:12], revision)
    bundle = Path(out_dir) / bundle_name
    fd, temporary_name = tempfile.mkstemp(
        prefix=bundle.stem + ".", suffix=".zip", dir=str(bundle.parent))
    os.close(fd)
    temporary = Path(temporary_name)
    readme = (
        "Community synthetic symbols for {module}\n\n"
        "Exact target SHA-256: {sha}\n"
        "Target version: {version}\n\n"
        "Symbol bundle revision: r{revision}\n\n"
        "The PDB contains public names at RVAs only. It has no compiler types, "
        "locals, source files, line tables, function ranges, or prototypes. "
        "Its GUID and age intentionally match the target executable, so do not "
        "mix revisions in one debugger symbol cache. The JSON preserves richer "
        "metadata that the public-only PDB format cannot carry.\n\n"
        "Review the PDB identity sidecar's source provenance and distribution "
        "rights before publishing a bundle derived from third-party names.\n\n"
        "Generated with FakePDB v0.3 (Apache-2.0): "
        "https://github.com/Mixaill/FakePDB\n").format(
            module=module, sha=digest, version=version,
            revision=revision)
    try:
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.write(pdb_path, arcname=Path(pdb_path).name)
            archive.write(pdb_identity_path,
                          arcname=Path(pdb_identity_path).name)
            archive.write(symbols_json, arcname=Path(symbols_json).name)
            if bgs_provenance is not None:
                archive.writestr(
                    "BGS_PROVENANCE.json",
                    json.dumps(validate_manifest(bgs_provenance),
                               indent=2, sort_keys=True) + "\n")
            archive.writestr("README.txt", readme)
        os.replace(temporary, bundle)
    finally:
        if temporary.exists():
            temporary.unlink()
    _write_text_atomic(Path(str(bundle) + ".sha256"),
                       _sha256_file(bundle) + "  " + bundle.name + "\n")
    return bundle


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project_dir")
    ap.add_argument("project_name")
    ap.add_argument("program_path")
    ap.add_argument("out_dir")
    ap.add_argument("--module", default=None,
                    help="module name for x64dbg (default: program exe name)")
    ap.add_argument("--signatures", action="store_true",
                    help="include function prototypes in the JSON (slower)")
    ap.add_argument("--fakepdb-json", action="store_true",
                    help="emit stable FakePDB v0.3 JSON")
    ap.add_argument("--pdb", action="store_true",
                    help="generate and round-trip validate a synthetic PDB")
    ap.add_argument("--package", action="store_true",
                    help="package PDB + rich JSON + provenance for sharing")
    ap.add_argument("--include-analysis", action="store_true",
                    help="include ANALYSIS-source names in the PDB; the safe "
                         "default is IMPORTED + USER_DEFINED only")
    ap.add_argument("--target-pe", action="append", default=None,
                    metavar="EXE",
                    help="candidate backing executable for when the recorded "
                         "import path no longer exists; repeatable.  The one "
                         "whose SHA-256 matches the Program's import hash is "
                         "used, and none is trusted without that match.")
    args = ap.parse_args()

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    pdir, pname = args.project_dir, args.project_name
    if "/" in pname:
        pdir = pdir + "/" + pname.rsplit("/", 1)[0]
        pname = pname.rsplit("/", 1)[1]

    fpj = pdb_output = pdb_identity = bundle = None
    with open_user_project(pdir, pname) as project:
        df = _resolve_program(project, args.program_path, monitor)
        if df is None:
            print("ERROR: program not found: %s" % args.program_path)
            sys.exit(3)
        consumer = java.lang.Object()
        program = df.getDomainObject(consumer, False, False, monitor)
        try:
            from binary_identity import (inspect_pe, verify_ghidra_program,
                                         _program_executable_path)
            executable = _program_executable_path(program)
            if not (executable and os.path.isfile(executable)):
                # Ghidra projects outlive import paths.  Accept a candidate
                # only when its hash equals the Program's import-time SHA-256.
                stored = (program.getExecutableSHA256() or "").lower()
                executable = None
                for candidate in (args.target_pe or []):
                    if not os.path.isfile(candidate):
                        continue
                    if inspect_pe(candidate).get("sha256", "").lower() == stored:
                        executable = candidate
                        break
                if executable is None:
                    print("ERROR: the recorded backing executable is gone and "
                          "no --target-pe candidate matches the Program's "
                          "import SHA-256 (%s)." % (stored or "unknown"))
                    sys.exit(4)
            target_manifest = inspect_pe(executable)
            verify_ghidra_program(program, [target_manifest])
            module = args.module
            if not module:
                exe = program.getExecutablePath() or program.getName()
                module = os.path.basename(exe.replace("\\", "/")) or program.getName()
                if not os.path.splitext(module)[1]:
                    module += ".exe"
            module = _module_basename(module)
            image_base, functions, labels = collect(
                program, args.signatures,
                image_size=int(target_manifest['image_size']))
            bgs_provenance = read_program_provenance(program)
            jp, mp, dp = write_outputs(args.out_dir, module, image_base,
                                       functions, labels, target_manifest,
                                       bgs_provenance=bgs_provenance)
            if args.fakepdb_json or args.pdb or args.package:
                safe_functions, safe_labels, selection = \
                    select_shareable_symbols(
                        functions, labels, target_manifest,
                        include_analysis=args.include_analysis)
                bitness = program.getDefaultPointerSize() * 8
                segments = collect_segments(target_manifest)
                pdb_labels = add_pdb_provenance_canary(
                    safe_functions, safe_labels, bgs_provenance)
                root = build_fakepdb_root(module, bitness, segments,
                                          safe_functions, pdb_labels,
                                          image_size=int(
                                              target_manifest['image_size']))
                fpj = Path(args.out_dir) / (
                    os.path.splitext(module)[0] + ".fakepdb.json")
                _write_text_atomic(fpj, json.dumps(root) + "\n")
                _write_text_atomic(
                    Path(str(fpj) + ".identity.json"),
                    json.dumps({
                        "schema": 1,
                        "kind": "fakepdb_v0.3_input",
                        "target": _public_target_manifest(target_manifest),
                        "selection": selection,
                        "content_sha256": hashlib.sha256(
                            Path(fpj).read_bytes()).hexdigest(),
                    }, indent=2, sort_keys=True) + "\n")
                if args.pdb or args.package:
                    from pdb_identity import read_pe_codeview
                    codeview = read_pe_codeview(executable)
                    pdb_name = _module_basename(
                        os.path.basename(str(codeview["pdb_path"]).replace(
                            "\\", "/")))
                    pdb_output, pdb_identity = generate_shareable_pdb(
                        executable, fpj, Path(args.out_dir) / pdb_name,
                        safe_functions, pdb_labels, target_manifest,
                        selection, source_provenance=bgs_provenance)
                    if args.package:
                        bundle = package_symbol_bundle(
                            args.out_dir, module, pdb_output, pdb_identity,
                            jp, target_manifest,
                            bgs_provenance=bgs_provenance)
        finally:
            program.release(consumer)

    print("Module: %s  (image_base=0x%X)" % (module, image_base))
    print("  functions: %d   labels: %d" % (len(functions), len(labels)))
    print("  wrote:\n    %s\n    %s\n    %s" % (jp, mp, dp))
    if fpj:
        print("    %s (%d safe functions, %d safe labels)" % (
            fpj, len(safe_functions), len(safe_labels)))
    if pdb_output:
        print("    %s\n    %s" % (pdb_output, pdb_identity))
    if bundle:
        print("    %s\n    %s.sha256" % (bundle, bundle))


if __name__ == "__main__":
    main()
