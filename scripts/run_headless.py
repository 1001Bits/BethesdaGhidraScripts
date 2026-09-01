#!/usr/bin/env python3
"""
Headless PyGhidra runner — imports each .exe under exes/<game>/<version>/ into
a single shared Ghidra project and applies the matching CommonLibImport_*.py
script.

Usage:
  python scripts/run_headless.py                 # run all
  python scripts/run_headless.py skyrim          # all skyrim versions
  python scripts/run_headless.py skyrim ae       # specific
  python scripts/run_headless.py f4 ae

Layout:
  exes/skyrim/se/SkyrimSE.exe              -> CommonLibImport_SE.py
  exes/skyrim/ae/SkyrimSE.exe              -> CommonLibImport_AE.py
  exes/skyrim/17104/SkyrimSE.exe           -> CommonLibImport_AE_1_7_104.py
  exes/skyrim/vr/SkyrimVR.exe              -> CommonLibImport_VR.py
  exes/f4/og/Fallout4.exe                  -> CommonLibImport_F4_OG.py
  exes/f4/ng/Fallout4.exe                  -> CommonLibImport_F4_NG.py
  exes/f4/ae/Fallout4.exe                  -> CommonLibImport_F4_AE.py
  exes/f4/221/Fallout4.exe                 -> CommonLibImport_F4_221.py
  exes/f4/240/Fallout4.exe                 -> CommonLibImport_F4_240.py
  exes/f4/vr/Fallout4VR.exe                -> CommonLibImport_F4_VR.py
  exes/starfield/sf/Starfield.exe          -> CommonLibImport_SF.py
  exes/fnv/og/FalloutNV.exe                -> CommonLibImport_FNV.py

All binaries are stored in one Ghidra project under /<game>/<version>/ folders.
"""
import os
import json
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPO_DIR       = Path(__file__).parent.parent
GHIDRA_DIR     = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))
EXES_ROOT      = REPO_DIR / "exes"
SCRIPTS_DIR    = REPO_DIR / "ghidrascripts"
PROJECTS_DIR   = REPO_DIR / "ghidraprojects"
STEAMLESS_CLI  = REPO_DIR / "tools" / "Steamless" / "Steamless.CLI.exe"

GHIDRA_PROJECT_NAME = "BethesdaGhidraScripts"
PIPELINE_STAGE_GENERIC = "generic-v2"
PIPELINE_STAGE_ENRICHED = "enriched-v2:"

PROJECT_NAME = {
    'skyrim':    'SkyrimSE',
    'f4':        'Fallout4',
    'starfield': 'Starfield',
    'fnv':       'FalloutNV',
}

SPOT_CHECKS = {
    'skyrim': {
        'types': [
            ("Actor",           "/CommonLibSSE/RE", 680,  85),
            ("TESObjectREFR",   "/CommonLibSSE/RE", 140,  18),
            ("PlayerCharacter", "/CommonLibSSE/RE", 3000, 260),
            ("ActorValue",      "/CommonLibSSE/RE",    4,   0),
        ],
        'labels':    [],
        # Individual CommonLib function names are not stable across source
        # revisions and target builds.  The current 1.7.104 importer contains
        # neither of the historical AbsorbEffect checks, so treating those
        # names as universal rolled back otherwise valid imports.  Structural
        # type checks and named-function totals remain strict below.
        'functions': [],
        'min_named': 12000, 'min_enums': 300, 'min_structs': 4500, 'min_syms': 250000,
    },
    'f4': {
        'types': [
            ("ActorMovementData", "/CommonLibF4/RE", 70,  1),
            ("BGSEquipType",      "/CommonLibF4/RE", 10,  1),
            ("Actor_vtbl",        "/CommonLibF4/RE", 800, 100),
        ],
        # VTABLE_* labels live in the low/mid ID range and resolve in every
        # F4 address-library DB; RTTI_* labels use IDs >= 4M which only
        # exist in meh321's AE generation (and largely in NG).  Per-version
        # overrides below drop RTTI_* from the OG / VR / NG expectation.
        'labels':    ["VTABLE_Actor", "VTABLE_ActiveEffect", "RTTI_Actor"],
        'functions': [],
        'min_named': 200, 'min_enums': 100, 'min_structs': 500, 'min_syms': 0,
    },
    'starfield': {
        # CommonLibSF uses C++23 features that may defeat the AST parse
        # on first run; if so the script emits labels-only and these type
        # spot-checks are skipped (set to [] until the parse is verified).
        # Once CommonLibSF parses cleanly, restore representative types here.
        'types':     [],
        'labels':    ["RTTI_Actor", "VTABLE_Actor"],
        'functions': [],
        'min_named': 1000, 'min_enums': 0, 'min_structs': 0, 'min_syms': 0,
    },
    'fnv': {
        # FNV uses xNVSE headers (no namespace prefix; category is
        # /xNVSE).  176-symbol baseline -- single hand-written corpus,
        # users can grow it via refs/fnv_names.csv overlay.  Type spot-
        # checks are intentionally empty for v1 since xNVSE struct names
        # may shift as the submodule updates; once the type pipeline
        # stabilizes, restore representative checks here.
        'types':     [],
        'labels':    [],
        'functions': [],
        'min_named': 50, 'min_enums': 0, 'min_structs': 0, 'min_syms': 0,
    },
}


# Per-version overlays applied on top of the per-game baseline.  RTTI_* IDs
# (>= 4M) only exist in meh321's AE address library generation, so the
# other F4 patches drop that label expectation.  OG / VR also have weaker
# function-name coverage than AE/NG (some names come from cross-version
# byte-sig porting), so the min_named floor is lowered to a value attainable
# with the byte-sig pass alone.
SPOT_CHECKS_OVERRIDES = {
    ('f4', 'og'): {
        'labels':    ["VTABLE_Actor", "VTABLE_ActiveEffect"],
        'min_named': 100,
    },
    ('f4', 'ng'): {
        'labels':    ["VTABLE_Actor", "VTABLE_ActiveEffect"],
    },
    ('f4', 'vr'): {
        'labels':    ["VTABLE_Actor", "VTABLE_ActiveEffect"],
        'min_named': 100,
    },
    # 1.11.221 now has meh321's version-1-11-221-0.bin (same ID namespace as
    # AE) plus identity-bound community PDB publics merged as fallback symbols.
    # VTABLE_* labels resolve identically to AE; function-name count tracks
    # AE primary (~25k) plus ~22k PDB-only publics.
    ('f4', '221'): {
        'labels':    ["VTABLE_Actor", "VTABLE_ActiveEffect"],
        'min_named': 30000,
    },
    ('f4', '240'): {
        'labels':    ["VTABLE_Actor", "VTABLE_ActiveEffect"],
        'min_named': 200,
    },
}


sys.path.insert(0, str(REPO_DIR / "scripts" / "core"))
from binary_identity import (  # noqa: E402
    canonical_identity,
    inspect_pe,
    manifest_matches,
)
from steamless import ensure_unpacked as _ensure_unpacked_impl  # noqa: E402
from importer_binding import (  # noqa: E402
    ImporterBindingError,
    accepts_manifest as _importer_accepts_manifest,
)
from pyghidra_result import (  # noqa: E402
    end_outer_transaction,
    require_script_success,
)


def _ensure_unpacked(binary: Path) -> Path:
    return _ensure_unpacked_impl(binary, STEAMLESS_CLI)


def _enrichment_stage_action(stage: str, script_sha: str,
                             newly_imported: bool) -> str:
    """Return ``apply``/``skip`` or reject an unsafe project baseline."""
    expected = PIPELINE_STAGE_ENRICHED + script_sha
    if stage == expected:
        return "skip"
    if newly_imported and not stage:
        return "apply"
    if stage == PIPELINE_STAGE_GENERIC:
        return "apply"
    if not stage:
        raise RuntimeError(
            "existing program has no pipeline-stage provenance; it may "
            "contain prior improvement. Clean/reimport it before applying an "
            "importer.")
    # "enriched" is the on-disk stage stamp (PIPELINE_STAGE_ENRICHED), not the
    # word we now use for it -- programs already carry it, so it stays.
    if stage.startswith("enriched"):
        raise RuntimeError(
            "project was improved by a different or legacy importer "
            "({}); clean/reimport it before applying {}".format(
                stage, script_sha))
    raise RuntimeError(
        "unknown pipeline stage {!r}; clean/reimport before mutation".format(
            stage))


def script_for(game: str, version: str) -> Path:
    if game == 'f4':
        return SCRIPTS_DIR / f"CommonLibImport_F4_{version.upper()}.py"
    if game == 'skyrim' and version == '17104':
        return SCRIPTS_DIR / "CommonLibImport_AE_1_7_104.py"
    if game == 'starfield':
        # Single-version pipeline; <version> directory name (e.g. "sf" or
        # "1-16-236-0") is ignored at script-lookup time.
        return SCRIPTS_DIR / "CommonLibImport_SF.py"
    if game == 'fnv':
        # Single-version pipeline (FNV 1.4.0.525 is the only build); the
        # <version> directory name is ignored.
        return SCRIPTS_DIR / "CommonLibImport_FNV.py"
    return SCRIPTS_DIR / f"CommonLibImport_{version.upper()}.py"


def discover_targets(filter_game=None, filter_ver=None):
    targets = []
    if not EXES_ROOT.is_dir():
        return targets
    for game_dir in sorted(EXES_ROOT.iterdir()):
        if not game_dir.is_dir():
            continue
        game = game_dir.name
        if filter_game and filter_game != game:
            continue
        for ver_dir in sorted(game_dir.iterdir()):
            if not ver_dir.is_dir():
                continue
            version = ver_dir.name
            if filter_ver and filter_ver != version:
                continue
            exes = [p for p in sorted(ver_dir.glob("*.exe"))
                    if "unpacked" not in p.name.lower()]
            if not exes:
                continue
            if len(exes) != 1:
                raise RuntimeError(
                    "ambiguous target folder {}: expected one original .exe, found {}"
                    .format(ver_dir, ", ".join(p.name for p in exes)))
            if game not in PROJECT_NAME:
                continue
            targets.append((game, version, exes[0]))
    return targets


def _verify(program, game, version):
    fm        = program.getFunctionManager()
    dtm       = program.getDataTypeManager()
    sym_table = program.getSymbolTable()
    spec = dict(SPOT_CHECKS[game])
    override = SPOT_CHECKS_OVERRIDES.get((game, version))
    if override:
        spec.update(override)

    total_funcs  = fm.getFunctionCount()
    named_funcs  = sum(1 for f in fm.getFunctions(True)
                       if not f.getName().startswith("FUN_") and not f.getName().startswith("sub_"))
    scoped_funcs = sum(1 for f in fm.getFunctions(True) if "::" in f.getName())
    enum_count = struct_count = 0
    for dt in dtm.getAllDataTypes():
        s = dt.getClass().getSimpleName()
        if s == "EnumDB":         enum_count   += 1
        elif s == "StructureDB":  struct_count += 1
    sym_count    = sum(1 for _ in sym_table.getAllSymbols(True))
    sigs_applied = sum(1 for f in fm.getFunctions(True)
                       if f.getSignature().getReturnType().getClass().getSimpleName() != "DefaultDataType")

    print("\n=== Verification Summary ===")
    print(f"  Total functions       : {total_funcs:>8,}")
    print(f"  Named functions       : {named_funcs:>8,}")
    print(f"    Scoped (Class::Fn)  : {scoped_funcs:>8,}")
    print(f"  Signatures set        : {sigs_applied:>8,}")
    print(f"    Enums               : {enum_count:>8,}")
    print(f"    Structs/Classes     : {struct_count:>8,}")
    print(f"  Total symbols         : {sym_count:>8,}")

    spot_ok = True

    if spec['types']:
        print("\n--- Type spot-checks ---")
        from ghidra.program.model.data import CategoryPath
        for type_name, cat_path, min_bytes, min_comps in spec['types']:
            dt = dtm.getDataType(CategoryPath(cat_path), type_name)
            if dt is None:
                print(f"  MISSING: {type_name} in {cat_path}")
                spot_ok = False
            else:
                comps = dt.getComponents() if hasattr(dt, "getComponents") else []
                size  = dt.getLength()
                ok    = size >= min_bytes and len(comps) >= min_comps
                mark  = "OK" if ok else "FAIL"
                named = len([x for x in comps if x.getFieldName()])
                print(f"  [{mark}] {type_name}: {size} bytes, {len(comps)} components ({named} named)")
                if not ok:
                    spot_ok = False

    if spec['labels']:
        print("\n--- Label spot-checks ---")
        for lname in spec['labels']:
            syms = list(sym_table.getSymbols(lname))
            if syms:
                print(f"  [OK] {lname} @ {syms[0].getAddress()}")
            else:
                print(f"  [MISSING] {lname}")
                spot_ok = False

    if spec['functions']:
        print("\n--- Function spot-checks ---")
        for fname in spec['functions']:
            syms = list(sym_table.getSymbols(fname))
            if syms:
                f = fm.getFunctionAt(syms[0].getAddress())
                ret    = f.getReturnType().getName() if f else "?"
                params = f.getParameterCount()       if f else "?"
                print(f"  [OK] {fname} @ {syms[0].getAddress()} ret={ret} params={params}")
            else:
                print(f"  [MISSING] {fname}")
                spot_ok = False

    print("\n--- Diagnostic baselines ---")
    errors, warnings = _evaluate_sanity(
        spec, named_funcs, enum_count, struct_count, sym_count, spot_ok)

    if warnings:
        print("\nVerification warnings (non-fatal):")
        for warning in warnings:
            print(f"  - {warning}")
    if errors:
        print("\n!!! VERIFICATION FAILURES !!!")
        for e in errors:
            print(f"  - {e}")
        return False
    print("\nAll verification checks passed.")
    return True


def _evaluate_sanity(spec, named_funcs, enum_count, struct_count, sym_count,
                     spot_ok):
    """Report historical importer baselines without rejecting valid output.

    These totals include Ghidra-managed state and CommonLib names/layouts that
    legitimately change across Ghidra, source, and target revisions.  Script
    exceptions, exact target identity, transaction integrity, and generation-
    time vtable anchors are the deterministic fatal checks; this function is
    deliberately diagnostic-only.
    """
    errors = []
    warnings = []
    if named_funcs < spec['min_named']:
        warnings.append(
            f"Named functions below historical baseline: {named_funcs:,} "
            f"(historical >={spec['min_named']:,})")
    if enum_count < spec['min_enums']:
        warnings.append(
            f"Enum count below historical baseline: {enum_count} "
            f"(historical >={spec['min_enums']})")
    if struct_count < spec['min_structs']:
        warnings.append(
            f"Struct count below historical baseline: {struct_count} "
            f"(historical >={spec['min_structs']})")
    if spec['min_syms'] and sym_count < spec['min_syms']:
        # getAllSymbols() includes analyzer-generated labels whose count changes
        # across Ghidra releases and analysis settings.  It is useful telemetry,
        # but not evidence that the target-bound importer failed.
        warnings.append(
            f"Symbol count below historical baseline: {sym_count:,} "
            f"(historical >={spec['min_syms']:,})")
    if not spot_ok:
        warnings.append(
            "One or more historical spot-checks did not match (see above)")
    return errors, warnings


def _get_folder(root_folder, game, version):
    """Get or create /<game>/<version>/ folder in the project."""
    game_folder = root_folder.getFolder(game)
    if game_folder is None:
        game_folder = root_folder.createFolder(game)
    ver_folder = game_folder.getFolder(version)
    if ver_folder is None:
        ver_folder = game_folder.createFolder(version)
    return ver_folder


# Ghidra log lines that are routine + unactionable for Bethesda binaries:
#   - PDB Universal: Bethesda never ships PDBs, so the "no PDB found" warning
#     is guaranteed noise for every import.
#   - Demangler Microsoft "Apply failure": MFC-style mangled local-dtor names
#     (?dtor$1@?0??...) demangle correctly but Ghidra can't apply the
#     resulting DemangledVariable as data when the target is already code.
#     Routine and not worth surfacing.
_NOISE_PATTERNS = (
    "PDB Universal>",
    "Demangler Microsoft> Apply failure",
)


def _filter_noise(text: str) -> str:
    if not text:
        return text
    return "\n".join(line for line in text.splitlines()
                     if not any(p in line for p in _NOISE_PATTERNS))


def _disable_noisy_analyzers(program):
    """Disable analyzers that would emit noise on Bethesda binaries.

    PDB Universal: Bethesda's shipped exes have no PDB — the analyzer warns
    on every import.  Demangler Microsoft sometimes fails to apply MFC dtor
    symbols to existing-code addresses; we don't ship MFC, so the warnings
    are unactionable.

    Ghidra 12.1 removed ``SubOptions.getName(String)`` (no overloads, only
    the no-arg form remains); the old "look up display name per key" check
    crashes the entire script-apply step there.  We skip the lookup --
    ``setBoolean`` on a non-existent option is a no-op for analyzers not
    registered yet, and the try/except keeps unexpected backend changes
    from blowing up the import.
    """
    from ghidra.program.model.listing import Program
    opts = program.getOptions(Program.ANALYSIS_PROPERTIES)
    for name in ("PDB Universal", "Demangler Microsoft"):
        try:
            opts.setBoolean(name, False)
        except Exception:
            pass


_BGS_MANIFEST_OPTION = "BGS Target Manifest"


def _validate_and_bind_program(program, binary: Path, newly_imported: bool):
    """Fail closed when a project program is not the exact input PE.

    Ghidra normally records an executable SHA-256 during import.  We also
    persist our full canonical PE identity so subsequent runs validate the
    architecture, image layout, timestamp and version as well as content.
    Legacy projects are accepted only when Ghidra's own SHA-256 matches.
    """
    from ghidra.program.model.listing import Program

    expected = inspect_pe(str(binary))
    info = program.getOptions(Program.PROGRAM_INFO)
    raw = info.getString(_BGS_MANIFEST_OPTION, "")
    if raw:
        try:
            recorded = json.loads(raw)
        except Exception as exc:
            raise RuntimeError("invalid stored BGS target manifest: {}".format(exc))
        ok, reasons = manifest_matches(recorded, expected)
        if not ok:
            raise RuntimeError(
                "project program does not match {}:\n  {}\n"
                "Refusing to mutate stale analysis. Reimport into a new folder "
                "or run `python run.py clean`.".format(
                    binary, "\n  ".join(reasons)))
    elif not newly_imported:
        ghidra_sha = (info.getString("Executable SHA256", "") or "").lower()
        if not ghidra_sha or ghidra_sha != expected["sha256"].lower():
            detail = "missing Ghidra import hash" if not ghidra_sha else (
                "SHA-256 expected {}, project has {}".format(
                    expected["sha256"], ghidra_sha))
            raise RuntimeError(
                "cannot prove existing project program identity ({}). "
                "Refusing to mutate it; reimport or clean the pipeline project."
                .format(detail))

    pointer_size = int(program.getDefaultPointerSize())
    if pointer_size != expected["pointer_size"]:
        raise RuntimeError("program pointer size {} does not match PE {}".format(
            pointer_size, expected["pointer_size"]))
    if int(program.getImageBase().getOffset()) != expected["image_base"]:
        raise RuntimeError("program image base does not match PE manifest")

    # Binding is intentionally performed only after every check passed.
    info.setString(_BGS_MANIFEST_OPTION,
                   json.dumps(canonical_identity(expected), sort_keys=True))
    return expected


def _run_one(project, game, version, binary, script_path, monitor,
             import_only=False):
    from ghidra.app.util.importer import MessageLog
    import ghidra
    import java.io
    import java.lang
    import pyghidra

    root_folder = project.getProjectData().getRootFolder()
    folder = _get_folder(root_folder, game, version)
    folder_path = f"/{game}/{version}"
    project_name = PROJECT_NAME[game]

    domain_file = None
    for cand in (binary.name, binary.stem, project_name):
        domain_file = folder.getFile(cand)
        if domain_file is not None:
            break

    newly_imported = domain_file is None
    if newly_imported:
        print(f"Importing {binary} ...")
        msg_log         = MessageLog()
        jfile           = java.io.File(str(binary))
        import_consumer = java.lang.Object()
        load_results = ghidra.app.util.importer.AutoImporter.importByUsingBestGuess(
            jfile, project, folder_path, import_consumer, msg_log, monitor
        )
        if not load_results:
            raise RuntimeError("Import returned no results.")
        print(f"Import complete. Loaded {load_results.size()} program(s).")
        load_results.save(monitor)
        load_results.close()
        for cand in (binary.name, binary.stem, project_name):
            domain_file = folder.getFile(cand)
            if domain_file is not None:
                break
        if domain_file is None:
            files = [f.getName() for f in folder.getFiles()]
            if not files:
                raise RuntimeError("No files found in project after import.")
            domain_file = folder.getFile(files[0])
    else:
        print(f"Program '{domain_file.getName()}' already in project, skipping import.")

    consumer = java.lang.Object()
    program  = domain_file.getDomainObject(consumer, True, False, monitor)
    try:
        setup_tx = program.startTransaction("Bind exact pipeline target")
        setup_commit = False
        try:
            manifest = _validate_and_bind_program(
                program, binary, newly_imported)
            # Suppress noisy analyzers before our script triggers any further
            # auto-analysis (and persist the off-state so later opens stay quiet).
            _disable_noisy_analyzers(program)
            setup_commit = True
        finally:
            end_outer_transaction(
                program, setup_tx, setup_commit, "target identity binding")
        print("Target identity: {} {}-bit sha256={}...".format(
            manifest["machine_name"], manifest["pointer_size"] * 8,
            manifest["sha256"][:16]))
        if import_only:
            from ghidra.program.model.listing import Program
            info = program.getOptions(Program.PROGRAM_INFO)
            stage = info.getString("BGS Pipeline Stage", "") or ""
            if not newly_imported and not stage:
                raise RuntimeError(
                    "existing program has no pipeline-stage provenance; it may "
                    "contain prior improvement. Refusing to use it as a clean "
                    "Starfield shift preflight. Run `python run.py clean`.")
            if stage.startswith("enriched"):   # the on-disk stamp; see above
                raise RuntimeError(
                    "shift preflight requires a clean generic import, but this "
                    "program is already improved. Clean/reimport before deriving "
                    "a new shift map.")
            stage_tx = program.startTransaction("Record clean generic stage")
            stage_commit = False
            try:
                info.setString("BGS Pipeline Stage", PIPELINE_STAGE_GENERIC)
                stage_commit = True
            finally:
                end_outer_transaction(
                    program, stage_tx, stage_commit, "generic stage binding")
            program.save("identity-bound generic import", monitor)
            print("Generic import ready; no improvement script was applied.")
            return True
        try:
            _importer_accepts_manifest(script_path, manifest)
        except ImporterBindingError as exc:
            raise RuntimeError(
                "refusing to run this import script.\n\n{}".format(exc))
        from ghidra.program.model.listing import Program
        import hashlib
        script_sha = hashlib.sha256(script_path.read_bytes()).hexdigest()
        info = program.getOptions(Program.PROGRAM_INFO)
        stage = info.getString("BGS Pipeline Stage", "") or ""
        if newly_imported and not stage:
            baseline_tx = program.startTransaction(
                "Record clean pre-improvement baseline")
            baseline_commit = False
            try:
                info.setString("BGS Pipeline Stage", PIPELINE_STAGE_GENERIC)
                baseline_commit = True
            finally:
                end_outer_transaction(
                    program, baseline_tx, baseline_commit,
                    "generic baseline binding")
            program.save("exact identity-bound generic baseline", monitor)
            stage = PIPELINE_STAGE_GENERIC
        action = _enrichment_stage_action(stage, script_sha, newly_imported)
        if action == "skip":
            print("Exact importer already applied; verifying without re-applying.")
            return _verify(program, game, version)

        print(f"Running {script_path.name} ...")
        outer_tx = program.startTransaction(
            "Atomic CommonLib importer " + script_path.name)
        commit = False
        try:
            stdout, stderr = pyghidra.ghidra_script(
                script_path, project, program,
                echo_stdout=False, echo_stderr=False)
            stdout = _filter_noise(stdout)
            stderr = _filter_noise(stderr)
            if stdout:
                print(stdout)
            require_script_success(stderr, script_path.name)
            if not _verify(program, game, version):
                raise RuntimeError(
                    "post-import verification failed; all importer changes "
                    "were rolled back")
            info.setString(
                "BGS Pipeline Stage", PIPELINE_STAGE_ENRICHED + script_sha)
            commit = True
        finally:
            end_outer_transaction(
                program, outer_tx, commit, script_path.name)
        program.save(f"CommonLib {game} {version} import", monitor)
        print("Saved.")
        return True
    finally:
        program.release(consumer)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('game', nargs='?')
    ap.add_argument('version', nargs='?')
    ap.add_argument('--import-only', action='store_true',
                    help='identity-bind and save a generic import; do not improve')
    args = ap.parse_args()
    fg = args.game
    fv = args.version
    targets = discover_targets(fg, fv)
    if not targets:
        print(f"No targets found in {EXES_ROOT}")
        sys.exit(1)

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    monitor = ConsoleTaskMonitor()

    project_dir = PROJECTS_DIR / GHIDRA_PROJECT_NAME
    project_dir.mkdir(parents=True, exist_ok=True)

    gpr = project_dir / f"{GHIDRA_PROJECT_NAME}.gpr"
    rep = project_dir / f"{GHIDRA_PROJECT_NAME}.rep"
    if rep.exists() and not gpr.exists():
        try:
            rep.resolve().relative_to(project_dir.resolve())
        except (OSError, ValueError) as exc:
            raise RuntimeError(
                "refusing to remove a project repository outside {}".format(
                    project_dir.resolve())) from exc
        shutil.rmtree(rep)

    failures = []
    try:
        with pyghidra.open_project(project_dir, GHIDRA_PROJECT_NAME, create=True) as project:
            for game, version, binary in targets:
                print("\n" + "=" * 60)
                print(f"  {game.upper()} / {version.upper()}: {binary}")
                print("=" * 60)
                binary = _ensure_unpacked(binary)
                script_path = script_for(game, version)
                if not args.import_only and not script_path.is_file():
                    print(f"SKIP: script not found at {script_path}")
                    failures.append((game, version, "missing script"))
                    continue
                try:
                    ok = _run_one(project, game, version, binary, script_path,
                                  monitor, import_only=args.import_only)
                    if not ok:
                        failures.append((game, version, "verification failed"))
                except Exception as e:
                    print(f"ERROR: {e}")
                    failures.append((game, version, str(e)))
    except Exception as e:
        print(f"ERROR opening project: {e}")
        sys.exit(1)

    print("\n" + "=" * 60)
    if failures:
        print("FAILURES:")
        for g, v, msg in failures:
            print(f"  {g}/{v}: {msg}")
        sys.exit(1)
    print(f"All {len(targets)} headless run(s) passed.")


if __name__ == "__main__":
    main()
