#!/usr/bin/env python3
"""
Interactive launcher for Bethesda Ghidra Scripts.

Presents a menu of actions: update submodules, rebuild import scripts,
run the headless Ghidra import, open Ghidra, etc.

Usage:
  python run.py            Interactive menu
  python run.py setup      Install prerequisites + tools (non-interactive)
  python run.py build      Generate scripts + headless import (non-interactive)
  python run.py all        Full pipeline: setup + build + open Ghidra
"""
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

REPO_DIR      = Path(__file__).resolve().parent
EXES_ROOT     = REPO_DIR / "exes"
SCRIPTS_DIR   = REPO_DIR / "scripts"
TOOLS_DIR     = REPO_DIR / "tools"
GHIDRA_DIR    = TOOLS_DIR / "ghidra"
STEAMLESS_DIR = TOOLS_DIR / "Steamless"
LLVM_DIR      = TOOLS_DIR / "llvm"

GHIDRA_SCRIPTS_DIR  = REPO_DIR / "ghidrascripts"
PROJECTS_DIR        = REPO_DIR / "ghidraprojects"
GHIDRA_PROJECT_NAME = "BethesdaGhidraScripts"
STATE_FILE          = REPO_DIR / ".last_run_state"

GHIDRA_RELEASES_URL    = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
STEAMLESS_RELEASES_URL = "https://api.github.com/repos/atom0s/Steamless/releases/latest"
LLVM_RELEASES_URL      = "https://api.github.com/repos/llvm/llvm-project/releases/latest"

REQUIRED_PACKAGES = {
    "pyghidra": "pyghidra",
    # capstone + numpy are only consumed by scripts/commonlibf4/run_bytesig_port.py
    # for the masked-retry pass that wildcards rel32 / rip-rel operands on
    # cross-build matches (AE -> OG / VR).  Without them the byte-sig port still
    # works for exact 32-byte matches; masked Pass 2 is skipped with a notice.
    "capstone": "capstone",
    "numpy":    "numpy",
}

# Best-effort only -- NEVER fatal.  pdbparse depends on an old `construct` that
# does `import imp`, a module removed in Python 3.12+, so it fails to build on
# modern Python (ModuleNotFoundError: No module named 'imp').  The PDB scripts
# (pdb_symbols.py / pdb_publics_skyrim.py) guard the import and fall back to an
# llvm-pdbutil `pretty --externals` dump, so pdbparse is a pure enhancement for
# Python <= 3.11 and must not block setup on newer interpreters.
OPTIONAL_PACKAGES = {
    "pdbparse": "pdbparse",
}


# Supported runtime versions.  Entries marked "fork" are added by this fork
# on top of doodlum's upstream (which ships SE/AE + F4 AE only).
# Each tuple: (key, game, version_label, exe_subdir, script_name, source)
VERSION_CATALOG = [
    ("se",    "skyrim",    "Skyrim SE 1.5.97",     "skyrim/se",    "CommonLibImport_SE.py",    "upstream"),
    ("ae",    "skyrim",    "Skyrim AE 1.6.1170",   "skyrim/ae",    "CommonLibImport_AE.py",    "upstream"),
    ("svr",   "skyrim",    "Skyrim VR 1.4.15",     "skyrim/vr",    "CommonLibImport_VR.py",    "fork"),
    ("f4og",  "f4",        "Fallout 4 OG 1.10.163","f4/og",        "CommonLibImport_F4_OG.py", "fork"),
    ("f4ng",  "f4",        "Fallout 4 NG 1.10.984","f4/ng",        "CommonLibImport_F4_NG.py", "fork"),
    ("f4ae",  "f4",        "Fallout 4 AE 1.11.191","f4/ae",        "CommonLibImport_F4_AE.py", "upstream"),
    ("f4221", "f4",        "Fallout 4 1.11.221",   "f4/221",       "CommonLibImport_F4_221.py","fork"),
    ("f4vr",  "f4",        "Fallout 4 VR 1.2.72",  "f4/vr",        "CommonLibImport_F4_VR.py", "fork"),
    ("fnv",   "fnv",       "Fallout NV 1.4.0.525", "fnv/og",       "CommonLibImport_FNV.py",   "fork"),
    ("sf",    "starfield", "Starfield 1.16.236 / 1.16.242 / 1.16.244", "starfield/sf", "CommonLibImport_SF.py",    "fork"),
]

API_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "BethesdaGhidraScripts",
}


# =====================================================================
#  Helpers
# =====================================================================

def _header(msg):
    print(f"\n{'=' * 60}\n  {msg}\n{'=' * 60}")


def _download(url, dest, label="Downloading"):
    with urllib.request.urlopen(url) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        done = 0
        with open(dest, "wb") as f:
            while chunk := resp.read(1024 * 1024):
                f.write(chunk)
                done += len(chunk)
                if total:
                    print(f"\r  {label}: {done * 100 // total}%", end="", flush=True)
        if total:
            print()


def _can_import(name):
    try:
        __import__(name)
        return True
    except ImportError:
        return False


# =====================================================================
#  Status detection
# =====================================================================

def _ghidra_version(path):
    props = path / "Ghidra" / "application.properties"
    if props.is_file():
        for line in props.read_text().splitlines():
            if line.startswith("application.version="):
                return line.split("=", 1)[1]
    return None


def _clang_version():
    clang_name = "clang.exe" if sys.platform == "win32" else "clang"
    local_clang = LLVM_DIR / "bin" / clang_name
    if local_clang.is_file():
        os.environ["PATH"] = str(LLVM_DIR / "bin") + os.pathsep + os.environ.get("PATH", "")
    try:
        r = subprocess.run(
            ["clang", "--version"], capture_output=True, text=True, check=True)
        return r.stdout.strip().splitlines()[0]
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def _discover_exes():
    """Return list of (game, version, exe_path) tuples."""
    found = []
    if not EXES_ROOT.is_dir():
        return found
    for game_dir in sorted(EXES_ROOT.iterdir()):
        if not game_dir.is_dir():
            continue
        for ver_dir in sorted(game_dir.iterdir()):
            if not ver_dir.is_dir():
                continue
            exes = [f for f in sorted(ver_dir.glob("*.exe"))
                    if "unpacked" not in f.name.lower()]
            if exes:
                found.append((game_dir.name, ver_dir.name, exes[0]))
    return found


def _discover_games():
    return {g for g, _, _ in _discover_exes()}


def _project_exists():
    gpr = PROJECTS_DIR / GHIDRA_PROJECT_NAME / f"{GHIDRA_PROJECT_NAME}.gpr"
    return gpr.is_file()


def _scripts_exist(games):
    # One parse pass per game emits scripts for every version that game's
    # CommonLib + address libraries support, so check the full set.
    if "skyrim" in games:
        for name in ("CommonLibImport_SE.py",
                     "CommonLibImport_AE.py",
                     "CommonLibImport_VR.py"):
            if not (GHIDRA_SCRIPTS_DIR / name).is_file():
                return False
    if "f4" in games:
        for name in ("CommonLibImport_F4_OG.py",
                     "CommonLibImport_F4_NG.py",
                     "CommonLibImport_F4_AE.py",
                     "CommonLibImport_F4_VR.py"):
            if not (GHIDRA_SCRIPTS_DIR / name).is_file():
                return False
    if "starfield" in games:
        if not (GHIDRA_SCRIPTS_DIR / "CommonLibImport_SF.py").is_file():
            return False
    if "fnv" in games:
        if not (GHIDRA_SCRIPTS_DIR / "CommonLibImport_FNV.py").is_file():
            return False
    return True


def _get_submodule_hashes():
    r = subprocess.run(
        ["git", "submodule", "status", "--recursive"],
        cwd=str(REPO_DIR), capture_output=True, text=True, check=True)
    hashes = {}
    for line in r.stdout.strip().splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            hashes[parts[1]] = parts[0].lstrip("+-")
    return hashes


def _get_exe_fingerprints():
    fps = {}
    if EXES_ROOT.is_dir():
        for exe in EXES_ROOT.rglob("*.exe"):
            if "unpacked" in exe.name:
                continue
            rel = exe.relative_to(EXES_ROOT).as_posix()
            st = exe.stat()
            fps[rel] = {"mtime": st.st_mtime, "size": st.st_size}
    return fps


def _load_state():
    if STATE_FILE.is_file():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_state(submodules, exes):
    STATE_FILE.write_text(json.dumps(
        {"submodules": submodules, "exes": exes}, indent=2))


# =====================================================================
#  Actions
# =====================================================================

def check_prerequisites():
    _header("Prerequisites")
    if sys.version_info < (3, 10):
        print(f"  ERROR: Python 3.10+ required (found {sys.version})")
        sys.exit(1)
    print(f"  Python {sys.version.split()[0]}")

    missing = [pkg for imp, pkg in REQUIRED_PACKAGES.items()
               if not _can_import(imp)]
    if missing:
        print(f"  Installing: {', '.join(missing)} ...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", *missing])

    # Optional packages: attempt, but never abort setup if the build fails
    # (e.g. pdbparse on Python 3.12+ -- it pulls in `construct`/`imp`).
    for imp, pkg in OPTIONAL_PACKAGES.items():
        if _can_import(imp):
            continue
        print(f"  Installing optional: {pkg} ...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", pkg])
        except subprocess.CalledProcessError:
            print(f"  NOTE: optional '{pkg}' could not be installed on this "
                  f"Python ({sys.version.split()[0]}); the pipeline falls back "
                  f"to llvm-pdbutil, so this is safe to ignore.")
    print("  Python packages: OK")


def update_submodules():
    _header("Update Submodules")
    subprocess.run(
        ["git", "submodule", "update", "--init", "--recursive", "--remote"],
        cwd=str(REPO_DIR), check=True)
    print("  Up to date.")


def setup_ghidra():
    _header("Ghidra")

    old_ghidra = REPO_DIR / "ghidra"
    if not GHIDRA_DIR.exists() and old_ghidra.exists() and _ghidra_version(old_ghidra):
        print("  Migrating Ghidra to tools/ ...")
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        shutil.move(str(old_ghidra), str(GHIDRA_DIR))

    ver = _ghidra_version(GHIDRA_DIR)
    if ver:
        print(f"  Ghidra {ver} (installed)")
        return

    print("  Fetching latest release ...")
    req = urllib.request.Request(GHIDRA_RELEASES_URL, headers=API_HEADERS)
    with urllib.request.urlopen(req) as resp:
        release = json.loads(resp.read())

    asset = next(
        (a for a in release.get("assets", [])
         if a["name"].endswith(".zip") and "ghidra" in a["name"].lower()),
        None)
    if not asset:
        print("  ERROR: no Ghidra zip found in latest release")
        sys.exit(1)

    size_mb = asset.get("size", 0) / 1024 / 1024
    print(f"  {asset['name']} ({size_mb:.0f} MB)")

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _download(asset["browser_download_url"], tmp_path)
        print("  Extracting ...")
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(tmp_path) as zf:
                zf.extractall(tmpdir)
            roots = [p for p in Path(tmpdir).iterdir() if p.is_dir()]
            src = roots[0] if len(roots) == 1 else Path(tmpdir)
            TOOLS_DIR.mkdir(parents=True, exist_ok=True)
            if GHIDRA_DIR.exists():
                shutil.rmtree(GHIDRA_DIR)
            shutil.copytree(str(src), str(GHIDRA_DIR))
    finally:
        tmp_path.unlink(missing_ok=True)

    ver = _ghidra_version(GHIDRA_DIR)
    print(f"  Ghidra {ver or '?'} installed")


def setup_steamless():
    if sys.platform != "win32":
        return

    _header("Steamless")
    cli = STEAMLESS_DIR / "Steamless.CLI.exe"
    if cli.is_file():
        print("  Steamless CLI: OK")
        return

    print("  Fetching latest release ...")
    req = urllib.request.Request(STEAMLESS_RELEASES_URL, headers=API_HEADERS)
    try:
        with urllib.request.urlopen(req) as resp:
            release = json.loads(resp.read())
    except Exception as e:
        print(f"  WARNING: could not fetch Steamless ({e}); DRM removal skipped")
        return

    asset = next(
        (a for a in release.get("assets", []) if a["name"].endswith(".zip")),
        None)
    if not asset:
        print("  WARNING: no zip in latest release; DRM removal skipped")
        return

    print(f"  {asset['name']}")
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _download(asset["browser_download_url"], tmp_path)
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(tmp_path) as zf:
                zf.extractall(tmpdir)
            hits = list(Path(tmpdir).rglob("Steamless.CLI.exe"))
            if not hits:
                print("  WARNING: Steamless.CLI.exe not found in archive")
                return
            src = hits[0].parent
            STEAMLESS_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copytree(str(src), str(STEAMLESS_DIR), dirs_exist_ok=True)
    finally:
        tmp_path.unlink(missing_ok=True)

    print("  Steamless CLI installed")


def _ensure_clang():
    clang_name = "clang.exe" if sys.platform == "win32" else "clang"
    local_clang = LLVM_DIR / "bin" / clang_name

    if local_clang.is_file():
        os.environ["PATH"] = str(LLVM_DIR / "bin") + os.pathsep + os.environ["PATH"]
        ver = _clang_version()
        if ver:
            print(f"  {ver}")
            return

    ver = _clang_version()
    if ver:
        print(f"  {ver}")
        return

    _download_llvm()
    os.environ["PATH"] = str(LLVM_DIR / "bin") + os.pathsep + os.environ["PATH"]
    ver = _clang_version()
    if ver:
        print(f"  {ver}")
    else:
        print("  ERROR: clang not working after LLVM install")
        sys.exit(1)


def _download_llvm():
    print("  clang not found; downloading LLVM ...")

    req = urllib.request.Request(LLVM_RELEASES_URL, headers=API_HEADERS)
    with urllib.request.urlopen(req) as resp:
        release = json.loads(resp.read())

    if sys.platform == "win32":
        machine = platform.machine().lower()
        arch = "x86_64" if machine in ("amd64", "x86_64") else "aarch64"
        suffix = f"{arch}-pc-windows-msvc.tar.xz"
    elif sys.platform == "darwin":
        machine = platform.machine().lower()
        arch = "ARM64" if machine == "arm64" else "X64"
        suffix = f"macOS-{arch}.tar.xz"
    else:
        machine = platform.machine().lower()
        arch = "ARM64" if machine == "aarch64" else "X64"
        suffix = f"Linux-{arch}.tar.xz"

    asset = next(
        (a for a in release.get("assets", [])
         if a["name"].endswith(suffix) and a["name"].endswith(".tar.xz")),
        None)
    if not asset:
        print(f"  ERROR: no LLVM asset matching *{suffix}")
        print("  Install LLVM/Clang manually and add clang to PATH.")
        sys.exit(1)

    size_mb = asset.get("size", 0) / 1024 / 1024
    print(f"  {asset['name']} ({size_mb:.0f} MB)")

    with tempfile.NamedTemporaryFile(suffix=".tar.xz", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _download(asset["browser_download_url"], tmp_path)
        print("  Extracting (this may take several minutes) ...")
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tmp_path, "r:xz") as tar:
            try:
                tar.extractall(TOOLS_DIR, filter="data")
            except TypeError:
                tar.extractall(TOOLS_DIR)
        for d in TOOLS_DIR.iterdir():
            if d.is_dir() and d != LLVM_DIR and (
                    "clang+llvm" in d.name or "LLVM" in d.name):
                if LLVM_DIR.exists():
                    shutil.rmtree(LLVM_DIR)
                d.rename(LLVM_DIR)
                break
    finally:
        tmp_path.unlink(missing_ok=True)

    clang_name = "clang.exe" if sys.platform == "win32" else "clang"
    if not (LLVM_DIR / "bin" / clang_name).is_file():
        print("  ERROR: clang not found after LLVM extraction")
        sys.exit(1)
    print("  LLVM installed")


def generate_scripts(games=None):
    if games is None:
        games = _discover_games()
    if not games:
        print("  No executables found -- nothing to generate.")
        return

    _header("Generating Import Scripts")
    _ensure_clang()

    if "skyrim" in games:
        print("  Skyrim SE / AE / VR ...")
        subprocess.run(
            [sys.executable,
             str(SCRIPTS_DIR / "commonlibsse" / "parse_commonlib_types.py")],
            cwd=str(REPO_DIR), check=True)
    if "f4" in games:
        print("  Fallout 4 OG / NG / AE / VR ...")
        subprocess.run(
            [sys.executable,
             str(SCRIPTS_DIR / "commonlibf4" / "parse_commonlib_types.py")],
            cwd=str(REPO_DIR), check=True)
        # F4 OG and VR use disjoint ID namespaces from NG/AE -- CommonLibF4
        # IDs don't resolve there.  When AE (or NG) and OG/VR binaries are
        # both present, port AE-known function names across via masked
        # byte-signature matching so OG/VR scripts apply function names
        # instead of types-only.  Skipped when the helper script isn't
        # present (e.g. on a branch where the F4 OG/NG/VR support hasn't
        # landed yet); no-op when AE/NG inputs aren't installed.
        bytesig_port = SCRIPTS_DIR / "commonlibf4" / "run_bytesig_port.py"
        if bytesig_port.is_file():
            print("  Fallout 4 cross-version byte-signature port ...")
            subprocess.run(
                [sys.executable, str(bytesig_port)],
                cwd=str(REPO_DIR), check=False)
    if "starfield" in games:
        print("  Starfield (auto-detect 1.16.x) ...")
        subprocess.run(
            [sys.executable,
             str(SCRIPTS_DIR / "commonlibsf" / "parse_commonlib_types.py")],
            cwd=str(REPO_DIR), check=True)
    if "fnv" in games:
        print("  Fallout New Vegas 1.4.0.525 (x86) ...")
        subprocess.run(
            [sys.executable,
             str(SCRIPTS_DIR / "commonlibnvse" / "parse_commonlib_types.py")],
            cwd=str(REPO_DIR), check=True)


def run_headless():
    _header("Headless Ghidra Import")
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "run_headless.py")],
        cwd=str(REPO_DIR)).returncode


def sf_shift_check():
    """Post-pipeline SF shift-map check.

    Idempotent: cheap no-op when the user's SF PE version already has
    matching reference + shift artifacts.  First run on a non-1.16.236
    build dumps vtable layouts (~30s) and builds refs/shift_sf.json
    against the committed 1.16.236 reference; user re-runs `python
    run.py build` to apply the slot shifts at the next script-gen pass.
    """
    sf_dir = EXES_ROOT / "starfield" / "sf"
    if not sf_dir.is_dir() or not any(sf_dir.glob("*.exe")):
        return  # No SF binary, skip entirely
    _header("SF Shift-Map Check")
    subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "commonlibsf" / "sf_shift_check.py")],
        cwd=str(REPO_DIR))


def launch_ghidra():
    _header("Launching Ghidra")
    if sys.platform == "win32":
        launcher = GHIDRA_DIR / "ghidraRun.bat"
    else:
        launcher = GHIDRA_DIR / "ghidraRun"
    if not launcher.is_file():
        print(f"  WARNING: {launcher.name} not found")
        return

    project_dir = PROJECTS_DIR / GHIDRA_PROJECT_NAME
    gpr = project_dir / f"{GHIDRA_PROJECT_NAME}.gpr"

    lock = project_dir / f"{GHIDRA_PROJECT_NAME}.lock"
    if lock.exists():
        try:
            lock.unlink()
        except OSError:
            pass

    print(f"  Project: {project_dir.relative_to(REPO_DIR)}/")
    if sys.platform == "win32":
        subprocess.Popen(
            [str(launcher), str(gpr)],
            cwd=str(GHIDRA_DIR),
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    else:
        subprocess.Popen(
            [str(launcher), str(gpr)],
            cwd=str(GHIDRA_DIR),
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)


def clean_project():
    _header("Clean Ghidra Project")
    project_dir = PROJECTS_DIR / GHIDRA_PROJECT_NAME
    if project_dir.exists():
        shutil.rmtree(project_dir)
        print("  Removed project directory.")
    if STATE_FILE.is_file():
        STATE_FILE.unlink()
        print("  Removed state file.")
    print("  Done. Next import will start fresh.")


# =====================================================================
#  Status display
# =====================================================================

def _version_status(entry):
    """Return (exe_present, script_present, exe_path) for a catalog entry."""
    _, game, _, subdir, script_name, _ = entry
    ver_dir = EXES_ROOT / subdir
    exe = None
    if ver_dir.is_dir():
        exes = [f for f in sorted(ver_dir.glob("*.exe"))
                if "unpacked" not in f.name.lower()]
        if exes:
            exe = exes[0]
    script_present = (GHIDRA_SCRIPTS_DIR / script_name).is_file()
    return (exe is not None), script_present, exe


def _print_status():
    """Print current environment status and return discovered games set."""
    print()
    print("=" * 60)
    print("  Bethesda Ghidra Scripts")
    print("=" * 60)

    # Tools
    ghidra_ver = _ghidra_version(GHIDRA_DIR)
    clang_ver = _clang_version()
    steamless_ok = (STEAMLESS_DIR / "Steamless.CLI.exe").is_file()
    pkgs_ok = all(_can_import(imp) for imp in REQUIRED_PACKAGES)

    print()
    print("  Tools:")
    print(f"    Ghidra      : {ghidra_ver or 'not installed'}")
    print(f"    Clang       : {clang_ver or 'not installed'}")
    if sys.platform == "win32":
        print(f"    Steamless   : {'OK' if steamless_ok else 'not installed'}")
    print(f"    Python pkgs : {'OK' if pkgs_ok else 'missing'}")

    # Versions (catalog-driven)
    print()
    print("  Supported versions  (legend: + fork-added beyond doodlum upstream)")
    print(f"    {'':<25} {'exe':<5} {'script':<7} src")
    for entry in VERSION_CATALOG:
        _, game, label, subdir, script_name, source = entry
        exe_ok, script_ok, _ = _version_status(entry)
        exe_mark    = "✓" if exe_ok else "·"
        script_mark = "✓" if script_ok else "·"
        src_mark    = "+ fork" if source == "fork" else "upstream"
        print(f"    {label:<25} {exe_mark:<5} {script_mark:<7} {src_mark}")

    # Generated scripts + project
    has_project = _project_exists()
    print()
    print("  Output:")
    print(f"    Ghidra project : {'OK' if has_project else 'not created'}")

    return {entry[1] for entry in VERSION_CATALOG
            if _version_status(entry)[0]}


# =====================================================================
#  Menu
# =====================================================================

MENU_ITEMS = [
    ("1", "Install prerequisites (Python packages, Ghidra, Clang, Steamless)"),
    ("2", "Update CommonLib submodules to latest"),
    ("3", "Process a specific version (per-version menu)"),
    ("4", "Generate import scripts (all detected versions)"),
    ("5", "Run headless Ghidra import"),
    ("6", "Open Ghidra"),
    ("7", "Full rebuild (generate + import all)"),
    ("8", "Clean Ghidra project (start fresh)"),
    ("9", "Enrich an existing Ghidra project (RTTI vtable pipeline)"),
    ("10", "Export symbols from an enriched project (JSON / .map / x64dbg)"),
    ("q", "Quit"),
]


# =====================================================================
#  Ghidra project discovery + RTTI vtable enrichment menu
# =====================================================================

EXTERNAL_GHIDRA_ROOTS = [
    Path("C:/GhidraProjects"),
]


def _discover_ghidra_projects():
    """Find all .gpr Ghidra projects in known roots.

    Includes the in-repo project plus any under EXTERNAL_GHIDRA_ROOTS
    (e.g., C:/GhidraProjects/Combined.gpr if the user has a separate
    pre-analyzed corpus).  Returns a list of (display_name, project_dir,
    project_name) tuples.
    """
    out = []
    in_repo_gpr = PROJECTS_DIR / GHIDRA_PROJECT_NAME / f"{GHIDRA_PROJECT_NAME}.gpr"
    if in_repo_gpr.is_file():
        out.append(("(this repo) " + GHIDRA_PROJECT_NAME,
                    str(PROJECTS_DIR / GHIDRA_PROJECT_NAME),
                    GHIDRA_PROJECT_NAME))
    seen = {(in_repo_gpr.parent.resolve())}
    for root in EXTERNAL_GHIDRA_ROOTS:
        if not root.is_dir():
            continue
        for gpr in sorted(root.glob("*.gpr")):
            project_dir = gpr.parent.resolve()
            if project_dir in seen:
                continue
            seen.add(project_dir)
            out.append((gpr.stem, str(project_dir), gpr.stem))
        # Also probe one level down (e.g., C:/GhidraProjects/Fallout/F4VR.gpr)
        for sub in sorted(root.iterdir()):
            if not sub.is_dir():
                continue
            for gpr in sorted(sub.glob("*.gpr")):
                project_dir = gpr.parent.resolve()
                if project_dir in seen:
                    continue
                seen.add(project_dir)
                out.append((f"{sub.name}/{gpr.stem}", str(project_dir), gpr.stem))
    return out


def _project_lock_files(project_dir, project_name):
    """Return a list of any present Ghidra lock files for the project.

    Ghidra writes <project>.lock (and sometimes <project>.lock~) into the
    project directory whenever the project is opened, whether by the GUI
    or a headless/pyghidra session.  Presence of either indicates the
    project is currently held by another JVM.
    """
    base = Path(project_dir) / project_name
    return [p for p in (base.with_suffix(".lock"),
                        Path(str(base) + ".lock~"))
            if p.exists()]


_LOCK_HINTS = ("LockException", "Unable to lock", "already locked",
               "already opened", "is in use", "lock is held")


def _wait_for_unlock(project_dir, project_name, step_label):
    """Block until the project lock is released (or the user skips).

    pyghidra subprocesses sometimes don't release their JVM lock cleanly,
    so a subsequent step run back-to-back hits a LockException.  Rather
    than crash, prompt the user to close any open Ghidra session and
    retry.  Returns True if the project is unlocked (proceed), False if
    the user skipped this step.
    """
    while True:
        locks = _project_lock_files(project_dir, project_name)
        if not locks:
            return True
        print()
        print("=" * 60)
        print(f"  Project {project_name!r} is locked -- cannot run {step_label}.")
        print("  Close any open Ghidra GUI / pyghidra session, then retry.")
        print()
        for p in locks:
            print(f"  Lock file: {p}")
        print("=" * 60)
        print()
        try:
            ans = input("  Press Enter to retry, or 's' to skip this step > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if ans == 's':
            return False


def _list_programs_in_project(project_dir, project_name):
    """Return list of (program_path, ...) tuples, or {"locked": "<reason>"}
    on lock detection, or None on any other failure.
    """
    locks = _project_lock_files(project_dir, project_name)
    if locks:
        return {"locked": f"lock file(s) present: {', '.join(str(p) for p in locks)}"}

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    try:
        import pyghidra
        pyghidra.start(install_dir=GHIDRA_DIR)
        import java.lang  # noqa: F401
        from ghidra.util.task import ConsoleTaskMonitor  # noqa: F401
    except Exception as e:
        print(f"  ERROR starting pyghidra: {e}")
        return None

    programs = []
    try:
        with pyghidra.open_project(project_dir, project_name, create=False) as project:
            root_folder = project.getProjectData().getRootFolder()
            def walk(folder, prefix=""):
                for f in folder.getFiles():
                    if f.getContentType() == "Program":
                        programs.append((prefix + "/" + f.getName(), None))
                for sub in folder.getFolders():
                    walk(sub, prefix + "/" + sub.getName())
            walk(root_folder, "")
    except Exception as e:
        msg = str(e)
        if any(h in msg for h in _LOCK_HINTS):
            return {"locked": msg.splitlines()[0][:200]}
        print(f"  ERROR opening project: {e}")
        return None
    return programs


def _enrich_menu():
    """Submenu: pick a Ghidra project + program, run RTTI vtable pipeline.

    Detects pre-analyzed projects (this repo + C:/GhidraProjects).  Useful
    when you already have a fully-analyzed binary somewhere and just want
    to apply our RTTI-driven vtable expansion to bump its named-function
    count.
    """
    projects = _discover_ghidra_projects()
    if not projects:
        print("  No Ghidra projects discovered.")
        return

    print()
    print("-" * 60)
    print("  Enrich existing Ghidra project — RTTI vtable pipeline")
    print("-" * 60)
    print("  Discovered Ghidra projects:")
    for i, (label, _, _) in enumerate(projects, 1):
        print(f"    {i}) {label}")
    print("    b) Back")
    print("-" * 60)
    try:
        sel = input("\n  project > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if sel == "b" or not sel.isdigit():
        return
    idx = int(sel)
    if not (1 <= idx <= len(projects)):
        print("  Invalid choice.")
        return
    label, pdir, pname = projects[idx - 1]
    print(f"\n  Opening {label} to list programs ...")
    result = _list_programs_in_project(pdir, pname)

    if isinstance(result, dict) and result.get("locked"):
        print()
        print("=" * 60)
        print(f"  Project {label!r} is locked — close Ghidra to continue.")
        print(f"  Close any open CodeBrowser / Ghidra Project Manager that")
        print(f"  has this project open, then try option 9 again.")
        print()
        print(f"  Reason: {result['locked']}")
        print("=" * 60)
        print()
        input("  Press Enter to return to main menu ... ")
        return
    if result is None:
        print()
        print("=" * 60)
        print(f"  Could not open project {label!r}.  See error above.")
        print("=" * 60)
        print()
        input("  Press Enter to return to main menu ... ")
        return
    programs = result
    if not programs:
        print("  No programs in project.")
        input("  Press Enter to return to main menu ... ")
        return

    print()
    print("-" * 60)
    print(f"  Programs in {label}")
    print("-" * 60)
    for i, (path, _) in enumerate(programs, 1):
        print(f"    {i:>3}) {path}")
    print("    b) Back")
    print("-" * 60)
    try:
        sel = input("\n  program > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if sel == "b" or not sel.isdigit():
        return
    pidx = int(sel)
    if not (1 <= pidx <= len(programs)):
        print("  Invalid choice.")
        return
    program_path, _ = programs[pidx - 1]

    # Opt-in: apply the matching CommonLibImport_*.py first.  Names types,
    # enums, vtable structs and tens of thousands of functions/labels --
    # the bulk of the enrichment for projects that have never been touched
    # by the per-version import pass (the RTTI walk only walks vtables).
    _offer_commonlib_apply(pdir, pname, program_path)

    if not _wait_for_unlock(pdir, pname, "RTTI vtable pipeline"):
        return
    args = [sys.executable,
            str(SCRIPTS_DIR / "core" / "run_vtable_pipeline.py"),
            pdir, pname, program_path]
    _header(f"RTTI vtable pipeline: {label} {program_path}")
    subprocess.run(args, check=False)

    # Opt-in: reconcile stale CommonLib-style vtable slot names against
    # today's AST.  Only useful when a prior CommonLibImport_*.py was
    # applied to this project (otherwise everything is FUN_* placeholders
    # and the main import pass would do the job).  Off by default since
    # it rewrites existing names.
    _offer_vtable_reconciler(pdir, pname, program_path)


def _export_menu():
    """Submenu: pick a Ghidra project + program, export its symbols to
    distributable formats (JSON map, plain .map, x64dbg .dd64).

    Light alternative to generating a PDB: serializes the names / data labels
    / vtables an enriched program already carries, for loading into x64dbg,
    Cheat Engine, or other tools.  READ-ONLY against the project.
    """
    projects = _discover_ghidra_projects()
    if not projects:
        print("  No Ghidra projects discovered.")
        return

    print()
    print("-" * 60)
    print("  Export symbols from an enriched Ghidra project")
    print("-" * 60)
    print("  Discovered Ghidra projects:")
    for i, (label, _, _) in enumerate(projects, 1):
        print(f"    {i}) {label}")
    print("    b) Back")
    print("-" * 60)
    try:
        sel = input("\n  project > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if sel == "b" or not sel.isdigit():
        return
    idx = int(sel)
    if not (1 <= idx <= len(projects)):
        print("  Invalid choice.")
        return
    label, pdir, pname = projects[idx - 1]
    print(f"\n  Opening {label} to list programs ...")
    result = _list_programs_in_project(pdir, pname)
    if isinstance(result, dict) and result.get("locked"):
        print(f"\n  Project {label!r} is locked — close Ghidra and retry.")
        print(f"  Reason: {result['locked']}")
        input("  Press Enter to return to main menu ... ")
        return
    if result is None:
        print(f"\n  Could not open project {label!r}.  See error above.")
        input("  Press Enter to return to main menu ... ")
        return
    programs = result
    if not programs:
        print("  No programs in project.")
        input("  Press Enter to return to main menu ... ")
        return

    print()
    print("-" * 60)
    print(f"  Programs in {label}")
    print("-" * 60)
    for i, (path, _) in enumerate(programs, 1):
        print(f"    {i:>3}) {path}")
    print("    b) Back")
    print("-" * 60)
    try:
        sel = input("\n  program > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if sel == "b" or not sel.isdigit():
        return
    pidx = int(sel)
    if not (1 <= pidx <= len(programs)):
        print("  Invalid choice.")
        return
    program_path, _ = programs[pidx - 1]

    default_out = str(Path(__file__).resolve().parent / "symbols")
    try:
        out_dir = input(f"\n  output dir [{default_out}] > ").strip() or default_out
        sig_ans = input("  include function prototypes? (slower) (y/N) > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if not _wait_for_unlock(pdir, pname, "symbol export"):
        return
    args = [sys.executable,
            str(SCRIPTS_DIR / "core" / "symbol_export.py"),
            pdir, pname, program_path, out_dir]
    if sig_ans == "y":
        args.append("--signatures")
    _header(f"Symbol export: {label} {program_path}")
    subprocess.run(args, check=False)
    input("\n  Press Enter to return to main menu ... ")


def _infer_commonlib_script(program_name):
    """Return the best-fit ``CommonLibImport_*.py`` basename for a program.

    Order is specific-to-generic so e.g. ``Fallout4_1_11_221.exe`` resolves
    to the 221 script rather than the catch-all AE one.
    """
    n = program_name.lower()
    if 'starfield' in n:
        return 'CommonLibImport_SF.py'
    if 'fallout4vr' in n or 'fallout4_vr' in n:
        return 'CommonLibImport_F4_VR.py'
    if 'falloutnv' in n:
        return 'CommonLibImport_FNV.py'
    if 'skyrimae' in n and 'gog' in n:
        # GOG builds have different RVAs than Steam 1.6.1170 -- use the
        # relib-re-keyed variant (1.6.1179 is the current GOG release).
        return 'CommonLibImport_AE_GOG_1_6_1179.py'
    if 'skyrimae' in n:
        return 'CommonLibImport_AE.py'
    if 'skyrimse' in n:
        # Bethesda names both SE and AE binaries SkyrimSE.exe; disambiguate
        # by embedded version tag, defaulting to AE (current Steam build).
        if '1_5_97' in n or '1.5.97' in n:
            return 'CommonLibImport_SE.py'
        return 'CommonLibImport_AE.py'
    if 'skyrimvr' in n:
        return 'CommonLibImport_VR.py'
    if 'fallout4' in n:
        # Disambiguate by version tag embedded in the name.
        if '1_11_221' in n or '1.11.221' in n or '_221' in n or n.endswith('221.exe'):
            return 'CommonLibImport_F4_221.py'
        if '1_11_191' in n or '1.11.191' in n or '_ae' in n or ' ae' in n:
            return 'CommonLibImport_F4_AE.py'
        if '1_10_984' in n or '1.10.984' in n or '_ng' in n:
            return 'CommonLibImport_F4_NG.py'
        if '1_10_163' in n or '1.10.163' in n or '_og' in n:
            return 'CommonLibImport_F4_OG.py'
        # Unknown F4 variant -- AE is the most-common modder target.
        return 'CommonLibImport_F4_AE.py'
    return None


# Per-version pyghidra applier in scripts/.  Each takes
# ``--project-dir``, ``--project-name`` and ``--program-path``.  Values are
# (applier_basename, [extra args]); the unified F4 applier accepts
# ``--version`` so all five F4 variants share one entry point.
_COMMONLIB_APPLY_SCRIPTS = {
    'CommonLibImport_SE.py':     ('apply_skyrim_to_user_project.py', ['--version', 'se']),
    'CommonLibImport_AE.py':     ('apply_skyrim_to_user_project.py', ['--version', 'ae']),
    'CommonLibImport_AE_GOG_1_6_1179.py':
        ('apply_skyrim_to_user_project.py',
         ['--version', 'ae', '--script',
          str(GHIDRA_SCRIPTS_DIR / 'CommonLibImport_AE_GOG_1_6_1179.py')]),
    'CommonLibImport_VR.py':     ('apply_skyrim_to_user_project.py', ['--version', 'vr']),
    'CommonLibImport_F4_OG.py':  ('apply_f4_to_user_project.py',  ['--version', 'og']),
    'CommonLibImport_F4_NG.py':  ('apply_f4_to_user_project.py',  ['--version', 'ng']),
    'CommonLibImport_F4_AE.py':  ('apply_f4_to_user_project.py',  ['--version', 'ae']),
    'CommonLibImport_F4_VR.py':  ('apply_f4_to_user_project.py',  ['--version', 'vr']),
    'CommonLibImport_F4_221.py': ('apply_f4_to_user_project.py',  ['--version', '221']),
    'CommonLibImport_FNV.py':    ('apply_fnv_to_user_project.py', []),
    'CommonLibImport_SF.py':     ('apply_sf_to_user_project.py',  []),
}


def _offer_commonlib_apply(pdir, pname, program_path):
    """Optional pre-step: apply CommonLibImport_<inferred>.py via pyghidra.

    Detects the matching import script from the program name and runs the
    per-version applier if one exists.  No-op when there's no applier for
    this version (e.g. F4 OG/NG/AE/VR -- those still go through menu 5's
    headless import path against the in-repo project).
    """
    program_name = Path(program_path).name
    suggested = _infer_commonlib_script(program_name)
    if not suggested:
        return
    import_script = GHIDRA_SCRIPTS_DIR / suggested
    if not import_script.is_file():
        return
    entry = _COMMONLIB_APPLY_SCRIPTS.get(suggested)
    if not entry:
        # No standalone applier for this version yet.
        return
    applier_name, extra_args = entry
    applier = SCRIPTS_DIR / applier_name
    if not applier.is_file():
        return

    print()
    print("-" * 60)
    print(f"  Apply {suggested} first? (recommended)")
    print("-" * 60)
    print(f"  Adds CommonLib enums + struct layouts + function/label names")
    print(f"  to this program before the RTTI vtable walk runs.  Skip if")
    print(f"  you've already applied it to this project.")
    print()
    try:
        ans = input("  Apply now? (Y/n) > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if ans == 'n':
        return

    if not _wait_for_unlock(pdir, pname, f"CommonLib apply ({suggested})"):
        return
    cmd = [sys.executable, str(applier),
           *extra_args,
           '--project-dir',  pdir,
           '--project-name', pname,
           '--program-path', program_path]
    _header(f"CommonLib apply ({suggested})")
    subprocess.run(cmd, check=False)


def _offer_vtable_reconciler(pdir, pname, program_path):
    """Opt-in pass: rewrite stale CommonLib-style vtable slot names.

    Lists available generated import scripts and lets the user pick which
    one's AST-derived VTABLES to reconcile against.  Skipped by default.
    """
    available = sorted(GHIDRA_SCRIPTS_DIR.glob('CommonLibImport_*.py'))
    if not available:
        return  # No generated scripts -- nothing to reconcile against
    print()
    print("-" * 60)
    print("  Reconcile stale CommonLib vtable slot names? (opt-in)")
    print("-" * 60)
    print("  Overwrites function names that look like stale CommonLib")
    print("  labels disagreeing with today's AST (e.g. an older buggy")
    print("  emission named slot 9 with slot 10's method name).  Leaves")
    print("  FUN_*/sub_* placeholders and non-CommonLib-style names alone.")
    print()
    try:
        ans = input("  Run reconciler? (y/N) > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if ans != 'y':
        return

    # Pick the import script whose VTABLES should be the source of truth.
    program_name = Path(program_path).name
    suggested = _infer_commonlib_script(program_name)

    print()
    print("  Available CommonLibImport scripts:")
    for i, p in enumerate(available, 1):
        marker = '  *' if suggested and p.name == suggested else '   '
        print(f"    {i:>2}){marker} {p.name}")
    try:
        sel = input("  script # (Enter for *) > ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not sel:
        chosen = next((p for p in available if p.name == suggested), None)
        if chosen is None:
            print("  No suggestion matched; aborting reconciler.")
            return
    elif sel.isdigit() and 1 <= int(sel) <= len(available):
        chosen = available[int(sel) - 1]
    else:
        print("  Invalid choice; aborting.")
        return

    # Ask for dry-run first (lower-impact default)
    try:
        dry_ans = input("  Dry-run first? (Y/n) > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    dry_run = dry_ans != 'n'

    if not _wait_for_unlock(pdir, pname, f"vtable reconciler ({chosen.name})"):
        return
    cmd = [sys.executable,
           str(SCRIPTS_DIR / 'core' / 'vtable_name_reconciler.py'),
           '--project-dir',  pdir,
           '--project-name', pname,
           '--program',      program_name,
           '--import-script', str(chosen)]
    if dry_run:
        cmd.append('--dry-run')
    _header(f"Vtable name reconciler ({chosen.name}{' [DRY-RUN]' if dry_run else ''})")
    subprocess.run(cmd, check=False)


def _show_menu():
    print()
    print("-" * 40)
    for key, label in MENU_ITEMS:
        print(f"  {key}) {label}")
    print("-" * 40)


def _version_submenu():
    """Per-version action menu.  Lets the user pick one version from the
    catalog and process it end-to-end (generate import script + headless
    Ghidra import).  Useful when only one game/version exe is on disk and
    the user wants to process just that one.
    """
    while True:
        print()
        print("-" * 60)
        print("  Process a specific version")
        print("-" * 60)
        print(f"  {'#':<3} {'version':<25} {'exe':<5} {'script':<7} src")
        for i, entry in enumerate(VERSION_CATALOG, 1):
            _, game, label, subdir, script_name, source = entry
            exe_ok, script_ok, _ = _version_status(entry)
            exe_mark    = "✓" if exe_ok else "·"
            script_mark = "✓" if script_ok else "·"
            src_mark    = "+ fork" if source == "fork" else "upstream"
            print(f"  {i:<3} {label:<25} {exe_mark:<5} {script_mark:<7} {src_mark}")
        print(f"  a   Process all versions whose exe is present")
        print(f"  b   Back to main menu")
        print("-" * 60)

        try:
            choice = input("\n  version > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice == "b":
            return
        if choice == "a":
            present = {entry[1] for entry in VERSION_CATALOG
                       if _version_status(entry)[0]}
            if not present:
                print("  No executables present in exes/ — nothing to process.")
                continue
            generate_scripts(present)
            rc = run_headless()
            if rc == 0:
                sf_shift_check()
                _save_state(_get_submodule_hashes(), _get_exe_fingerprints())
            return
        if not choice.isdigit() or not (1 <= int(choice) <= len(VERSION_CATALOG)):
            print("  Invalid choice.")
            continue

        entry = VERSION_CATALOG[int(choice) - 1]
        _, game, label, subdir, script_name, source = entry
        exe_ok, script_ok, exe_path = _version_status(entry)
        if not exe_ok:
            print(f"  {label}: exe not found at exes/{subdir}/")
            print(f"  Drop a Starfield/Skyrim/Fallout4 .exe in that subdir, then retry.")
            continue
        print(f"  Processing {label} ...")
        # Parsers operate at the game level, not per-runtime, so all versions
        # of a game get regenerated together.  That's still cheap.
        generate_scripts({game})
        rc = run_headless()
        if rc == 0:
            if game == "starfield":
                sf_shift_check()
            _save_state(_get_submodule_hashes(), _get_exe_fingerprints())
        return


def _run_menu():
    _print_status()
    _show_menu()

    while True:
        try:
            choice = input("\n  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice == "q":
            break
        elif choice == "1":
            check_prerequisites()
            setup_ghidra()
            setup_steamless()
            _ensure_clang()
        elif choice == "2":
            update_submodules()
        elif choice == "3":
            _version_submenu()
        elif choice == "4":
            games = _discover_games()
            generate_scripts(games)
        elif choice == "5":
            rc = run_headless()
            if rc == 0:
                sf_shift_check()
                _save_state(_get_submodule_hashes(), _get_exe_fingerprints())
        elif choice == "6":
            launch_ghidra()
            break
        elif choice == "7":
            games = _discover_games()
            generate_scripts(games)
            rc = run_headless()
            if rc == 0:
                sf_shift_check()
                _save_state(_get_submodule_hashes(), _get_exe_fingerprints())
        elif choice == "8":
            clean_project()
        elif choice == "9":
            _enrich_menu()
        elif choice == "10":
            _export_menu()
        else:
            print("  Invalid choice.")
            continue

        _print_status()
        _show_menu()


# =====================================================================
#  CLI subcommands for non-interactive use
# =====================================================================

def _cmd_setup():
    check_prerequisites()
    update_submodules()
    setup_ghidra()
    setup_steamless()


def _cmd_build():
    games = _discover_games()
    if not games:
        print("No executables found.")
        sys.exit(1)
    generate_scripts(games)
    rc = run_headless()
    if rc == 0:
        sf_shift_check()
        _save_state(_get_submodule_hashes(), _get_exe_fingerprints())
    sys.exit(rc)


def _cmd_all():
    _cmd_setup()
    games = _discover_games()
    if not games:
        print("No executables found.")
        sys.exit(1)
    generate_scripts(games)
    rc = run_headless()
    if rc == 0:
        sf_shift_check()
        _save_state(_get_submodule_hashes(), _get_exe_fingerprints())
    launch_ghidra()
    sys.exit(rc)


def _enable_log_tee():
    """Tee stdout+stderr to .last_run.log via FD-level redirect so subprocess
    output (clang, pyghidra, headless import) is captured too.  Original
    streams stay on the terminal; the log is truncated each invocation.
    """
    import threading
    log_path = REPO_DIR / ".last_run.log"
    try:
        log_file = open(log_path, "wb")
    except OSError:
        return  # No-op if the repo is read-only / log path inaccessible.

    try:
        orig_stdout = os.dup(1)
        orig_stderr = os.dup(2)
        out_r, out_w = os.pipe()
        err_r, err_w = os.pipe()
        os.dup2(out_w, 1); os.close(out_w)
        os.dup2(err_w, 2); os.close(err_w)
        sys.stdout = os.fdopen(1, "w", buffering=1, encoding="utf-8", errors="replace")
        sys.stderr = os.fdopen(2, "w", buffering=1, encoding="utf-8", errors="replace")
    except OSError:
        log_file.close()
        return

    def _pump(read_fd, term_fd):
        try:
            while True:
                chunk = os.read(read_fd, 4096)
                if not chunk:
                    break
                os.write(term_fd, chunk)
                log_file.write(chunk)
                log_file.flush()
        except Exception:
            pass

    threading.Thread(target=_pump, args=(out_r, orig_stdout), daemon=True).start()
    threading.Thread(target=_pump, args=(err_r, orig_stderr), daemon=True).start()


def main():
    _enable_log_tee()
    args = sys.argv[1:]
    if not args:
        _run_menu()
    elif args[0] == "setup":
        _cmd_setup()
    elif args[0] == "build":
        _cmd_build()
    elif args[0] == "all":
        _cmd_all()
    else:
        print(f"Unknown command: {args[0]}")
        print("Usage: python run.py [setup|build|all]")
        sys.exit(1)


if __name__ == "__main__":
    main()
