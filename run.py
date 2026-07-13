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
  python run.py clean      Remove only the generated pipeline project/state
"""
import json
import importlib.metadata
import hashlib
import os
import platform
import shutil
import stat
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
FAKEPDB_DIR   = TOOLS_DIR / "fakepdb"

GHIDRA_SCRIPTS_DIR  = REPO_DIR / "ghidrascripts"
PROJECTS_DIR        = REPO_DIR / "ghidraprojects"
GHIDRA_PROJECT_NAME = "BethesdaGhidraScripts"
STATE_FILE          = REPO_DIR / ".last_run_state"
TOOLCHAIN_LOCK_FILE = REPO_DIR / "toolchain.lock.json"

PINNED_GHIDRA_VERSION = "12.0.4"
PINNED_STEAMLESS_VERSION = "3.1.0.5"
PINNED_LLVM_VERSION = "20.1.8"
PINNED_FAKEPDB_VERSION = "0.3"

GHIDRA_RELEASES_URL = (
    "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/"
    "Ghidra_12.0.4_build")
STEAMLESS_RELEASES_URL = (
    "https://api.github.com/repos/atom0s/Steamless/releases/tags/v3.1.0.5")
LLVM_RELEASES_URL = (
    "https://api.github.com/repos/llvm/llvm-project/releases/tags/llvmorg-20.1.8")
FAKEPDB_RELEASES_URL = (
    "https://api.github.com/repos/Mixaill/FakePDB/releases/tags/v0.3")

LOCKED_ASSET_DIGESTS = {
    "ghidra_12.0.4_PUBLIC_20260303.zip":
        "sha256:c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120",
    "Steamless.v3.1.0.5.-.by.atom0s.zip":
        "sha256:e3e2d22e098ff3fb359b2876aa2bed9596f0501e6ff588cbffae90a76d2dc4f5",
    "clang+llvm-20.1.8-x86_64-pc-windows-msvc.tar.xz":
        "sha256:f229769f11d6a6edc8ada599c0cda964b7dee6ab1a08c6cf9dd7f513e85b107f",
    "clang+llvm-20.1.8-aarch64-pc-windows-msvc.tar.xz":
        "sha256:0df3e81e8fe26370dd2b60b9e009d81cd130d3fdc41b257434aa663c5d9f0c13",
    "fakepdb_v0.3.zip":
        "sha256:198708824d69648d5822f7867b09a1f760f15debb0a340925f3a57523a249043",
}
PINNED_STEAMLESS_CLI_SHA256 = (
    "70cd54354865ede605ec0fbfadf15f5302aa85a777394f28b0de6acfd243e795")
PINNED_FAKEPDB_EXE_SHA256 = (
    "576dbe7d9a7154608fe967b8ccde2e7a69799c185c381a43727a283002efe662")

SUPPORTED_PYTHON_MIN = (3, 11)
SUPPORTED_PYTHON_MAX = (3, 14)


def _python_minor(version_info=None):
    version_info = sys.version_info if version_info is None else version_info
    return int(version_info[0]), int(version_info[1])


def _python_compatibility_error(version_info=None, maxsize=None):
    minor = _python_minor(version_info)
    maxsize = sys.maxsize if maxsize is None else maxsize
    if minor < SUPPORTED_PYTHON_MIN:
        return ("CPython 3.11 through 3.14 (64-bit) is required; found "
                "{}.{}.".format(*minor))
    if minor > SUPPORTED_PYTHON_MAX:
        return ("CPython {}.{} is not yet supported by the locked NumPy/JPype "
                "runtime; use CPython 3.11 through 3.14 (64-bit).".format(
                    *minor))
    if maxsize <= 2 ** 32:
        return "64-bit CPython is required by Ghidra and the locked toolchain."
    return None


def _require_supported_python():
    error = _python_compatibility_error()
    if error:
        print("  ERROR: " + error)
        raise SystemExit(1)


def _jpype_requirement(version_info=None):
    # PyGhidra 3.0.2 pins JPype 1.5.2, whose published wheels stop at
    # CPython 3.13.  JPype 1.7.1 fixes the 1.6.0 Windows import race and is
    # the tested compatibility bridge for CPython 3.14.
    if _python_minor(version_info) >= (3, 14):
        return "JPype1==1.7.1"
    return "JPype1==1.5.2"


PYTHON_LOCK_REQUIREMENTS = frozenset({
    "pyghidra==3.0.2",
    "JPype1==1.5.2; python_version < '3.14'",
    "JPype1==1.7.1; python_version >= '3.14' and python_version < '3.15'",
    "packaging==25.0",
    "capstone==5.0.6",
    "numpy==2.4.4",
})

REQUIRED_PACKAGES = {
    "pyghidra": "pyghidra==3.0.2",
    "jpype": _jpype_requirement(),
    "packaging": "packaging==25.0",
    # capstone + numpy are only consumed by scripts/commonlibf4/run_bytesig_port.py
    # for the masked-retry pass that wildcards rel32 / rip-rel operands on
    # cross-build matches (AE -> OG / VR).  Without them the byte-sig port still
    # works for exact 32-byte matches; masked Pass 2 is skipped with a notice.
    "capstone": "capstone==5.0.6",
    "numpy":    "numpy==2.4.4",
}

# Loose core modules are shared by the launcher, generators and PyGhidra
# runner.  Keeping binary identity in one place prevents mtime-only cache and
# stale-project decisions from drifting apart.
sys.path.insert(0, str(SCRIPTS_DIR / "core"))
from binary_identity import canonical_identity, inspect_pe  # noqa: E402
from pdb_identity import (  # noqa: E402
    PDBIdentityError,
    validate_repo_llvm_install,
    write_llvm_install_receipt,
)
from steamless import ensure_unpacked as _ensure_unpacked  # noqa: E402
from fakepdb_tool import (  # noqa: E402
    FakePDBToolError,
    validate_fakepdb_install,
    write_fakepdb_receipt,
)


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


def _download(url, dest, label="Downloading", expected_digest=None):
    digest = hashlib.sha256()
    with urllib.request.urlopen(url) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        done = 0
        with open(dest, "wb") as f:
            while chunk := resp.read(1024 * 1024):
                f.write(chunk)
                digest.update(chunk)
                done += len(chunk)
                if total:
                    print(f"\r  {label}: {done * 100 // total}%", end="", flush=True)
        if total:
            print()
    actual = digest.hexdigest()
    if expected_digest:
        algorithm, _, expected = expected_digest.partition(":")
        if algorithm.lower() != "sha256" or actual.lower() != expected.lower():
            Path(dest).unlink(missing_ok=True)
            raise RuntimeError(
                f"download digest mismatch: expected {expected_digest}, "
                f"got sha256:{actual}")
    return actual


def _inside(root, candidate):
    try:
        Path(candidate).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def _safe_rmtree(root, target, label):
    root = Path(root).resolve()
    target = Path(target)
    try:
        resolved = target.resolve()
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            f"refusing to recursively delete {label} outside {root}: "
            f"{resolved if 'resolved' in locals() else target}") from exc
    if resolved == root:
        raise RuntimeError(f"refusing to recursively delete root {root}")
    shutil.rmtree(target)


def _safe_extract_zip(archive, destination):
    destination = Path(destination)
    for member in archive.infolist():
        target = destination / member.filename
        mode = member.external_attr >> 16
        if not _inside(destination, target) or stat.S_ISLNK(mode):
            raise RuntimeError(f"unsafe zip member: {member.filename}")
    archive.extractall(destination)


def _safe_extract_tar(archive, destination):
    destination = Path(destination)
    try:
        archive.extractall(destination, filter="data")
        return
    except TypeError:  # Python 3.11 compatibility
        pass
    safe = []
    for member in archive.getmembers():
        target = destination / member.name
        if (not _inside(destination, target) or member.issym() or
                member.islnk() or member.isdev()):
            raise RuntimeError(f"unsafe tar member: {member.name}")
        safe.append(member)
    archive.extractall(destination, members=safe)


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


def _clang_version(executable=None):
    command = str(executable) if executable is not None else "clang"
    try:
        r = subprocess.run(
            [command, "--version"], capture_output=True, text=True, check=True)
        return r.stdout.strip().splitlines()[0]
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def _accept_clang_version(version_line):
    if not version_line:
        return False
    if PINNED_LLVM_VERSION in version_line:
        return True
    if os.environ.get("BGS_ALLOW_TOOLCHAIN_DRIFT"):
        print(f"  WARNING: using unpinned toolchain: {version_line}")
        return True
    print(f"  Found {version_line}, but LLVM {PINNED_LLVM_VERSION} is required.")
    return False


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
            if len(exes) > 1:
                raise RuntimeError(
                    f"Ambiguous target directory {ver_dir}: expected one "
                    f"original .exe, found {', '.join(p.name for p in exes)}")
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
                     "CommonLibImport_F4_221.py",
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


def _get_submodule_entries():
    r = subprocess.run(
        ["git", "submodule", "status", "--recursive"],
        cwd=str(REPO_DIR), capture_output=True, text=True, check=True)
    entries = {}
    for raw_line in r.stdout.splitlines():
        prefix = raw_line[0] if raw_line and raw_line[0] in " +-U" else " "
        parts = raw_line.strip().split()
        if len(parts) >= 2:
            entries[parts[1]] = (parts[0].lstrip("+-U"), prefix)
    return entries


def _get_submodule_hashes():
    return {path: commit for path, (commit, _prefix)
            in _get_submodule_entries().items()}


def _assert_submodules_clean():
    entries = _get_submodule_entries()
    try:
        lock = json.loads(TOOLCHAIN_LOCK_FILE.read_text(encoding="utf-8"))
        locked_submodules = lock["submodules"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("invalid or missing toolchain.lock.json") from exc
    actual_hashes = {path: commit for path, (commit, _prefix)
                     in entries.items()}
    lock_mismatch = {
        path for path in set(actual_hashes) | set(locked_submodules)
        if actual_hashes.get(path) != locked_submodules.get(path)
    }
    if lock_mismatch and not os.environ.get("BGS_ALLOW_TOOLCHAIN_DRIFT"):
        raise RuntimeError(
            "submodule gitlinks do not match toolchain.lock.json: " +
            ", ".join(sorted(lock_mismatch)))
    dirty = []
    revision_drift = [path for path, (_commit, prefix) in entries.items()
                      if prefix != " "]
    if revision_drift and not os.environ.get("BGS_ALLOW_TOOLCHAIN_DRIFT"):
        raise RuntimeError(
            "submodule revision differs from the committed gitlink or is "
            "uninitialized: " + ", ".join(sorted(revision_drift)) +
            ". Run `python run.py setup`.")
    for relative in sorted(entries):
        submodule = REPO_DIR / relative
        if not (submodule / ".git").exists():
            raise RuntimeError(
                f"submodule {relative} is not initialized; run `python "
                "run.py setup`")
        result = subprocess.run(
            ["git", "-C", str(submodule), "status", "--porcelain",
             "--untracked-files=all"],
            cwd=str(REPO_DIR), capture_output=True, text=True, check=True)
        if result.stdout.strip():
            dirty.append(relative)
    if dirty and not os.environ.get("BGS_ALLOW_DIRTY_SOURCES"):
        raise RuntimeError(
            "refusing non-reproducible generation from dirty submodule(s): " +
            ", ".join(dirty) + ". Stash/commit them, or set "
            "BGS_ALLOW_DIRTY_SOURCES=1 only for an explicit research build.")
    if dirty:
        print("  WARNING: explicit dirty-source research build: " +
              ", ".join(dirty))
    return {path: commit for path, (commit, _prefix) in entries.items()}


def _get_exe_fingerprints():
    fps = {}
    if EXES_ROOT.is_dir():
        for exe in EXES_ROOT.rglob("*.exe"):
            if "unpacked" in exe.name.lower():
                continue
            rel = exe.relative_to(EXES_ROOT).as_posix()
            fps[rel] = canonical_identity(inspect_pe(str(exe)))
    return fps


def _load_state():
    if STATE_FILE.is_file():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_state(submodules, exes):
    payload = json.dumps(
        {"submodules": submodules, "exes": exes}, indent=2) + "\n"
    fd, temp_name = tempfile.mkstemp(
        prefix=STATE_FILE.name + ".", suffix=".tmp", dir=str(REPO_DIR))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, STATE_FILE)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


# =====================================================================
#  Actions
# =====================================================================

def _ensure_python_packages(*, announce=False):
    """Install the locked runtime into the interpreter running this CLI.

    ``run.bat`` deliberately selects a supported Python version, not a
    particular global site-packages directory.  Every selected interpreter
    therefore has to be bootstrapped before the interactive menu can launch a
    PyGhidra subprocess.
    """
    missing = [pkg for imp, pkg in REQUIRED_PACKAGES.items()
               if not _requirement_satisfied(imp, pkg)]
    if announce or missing:
        _header("Python runtime")
        print(f"  Python {sys.version.split()[0]}")
    if missing:
        print(f"  Installing: {', '.join(missing)} ...")
        # Every direct and transitive runtime dependency is listed explicitly
        # in requirements.lock.txt.  --no-deps is intentional: PyGhidra 3.0.2
        # hard-pins JPype 1.5.2, but CPython 3.14 requires our tested JPype
        # 1.7.1 bridge because 1.5.2 has no cp314 wheel.
        command = [
            sys.executable, "-m", "pip", "install", "--quiet", "--no-deps",
            "--only-binary=:all:", *missing]
        try:
            # uv/python-build-standalone interpreters register with the py
            # launcher but ship without pip; bootstrap it before using it.
            try:
                import pip  # noqa: F401
            except ImportError:
                subprocess.check_call(
                    [sys.executable, "-m", "ensurepip", "--upgrade"])
            subprocess.check_call(command)
        except (OSError, subprocess.CalledProcessError) as exc:
            quoted = subprocess.list2cmdline(command)
            raise RuntimeError(
                "Unable to prepare the selected Python interpreter {}. "
                "Check network/write access, or run this command manually:\n"
                "  {}".format(sys.executable, quoted)) from exc
        remaining = [pkg for imp, pkg in REQUIRED_PACKAGES.items()
                     if not _requirement_satisfied(imp, pkg)]
        if remaining:
            raise RuntimeError(
                "Python dependency installation did not produce the locked "
                "runtime: " + ", ".join(remaining))
    if announce or missing:
        print("  Python packages: OK")


def check_prerequisites():
    _require_supported_python()
    _ensure_python_packages(announce=True)


def update_submodules():
    _header("Update Submodules")
    subprocess.run(
        ["git", "submodule", "update", "--init", "--recursive"],
        cwd=str(REPO_DIR), check=True)
    _assert_submodules_clean()
    print("  Checked out committed submodule revisions.")


def setup_ghidra():
    _header("Ghidra")

    old_ghidra = REPO_DIR / "ghidra"
    if not GHIDRA_DIR.exists() and old_ghidra.exists() and _ghidra_version(old_ghidra):
        print("  Migrating Ghidra to tools/ ...")
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        shutil.move(str(old_ghidra), str(GHIDRA_DIR))

    ver = _ghidra_version(GHIDRA_DIR)
    if ver:
        if (ver != PINNED_GHIDRA_VERSION and
                not os.environ.get("BGS_ALLOW_TOOLCHAIN_DRIFT")):
            raise RuntimeError(
                f"Ghidra {ver} is installed, but this repository is pinned "
                f"to {PINNED_GHIDRA_VERSION}. Set "
                "BGS_ALLOW_TOOLCHAIN_DRIFT=1 only after running the tests.")
        print(f"  Ghidra {ver} (installed)")
        return

    print(f"  Fetching pinned Ghidra {PINNED_GHIDRA_VERSION} ...")
    req = urllib.request.Request(GHIDRA_RELEASES_URL, headers=API_HEADERS)
    with urllib.request.urlopen(req) as resp:
        release = json.loads(resp.read())

    asset = next((a for a in release.get("assets", [])
                  if a["name"] == "ghidra_12.0.4_PUBLIC_20260303.zip"), None)
    if not asset:
        print("  ERROR: no Ghidra zip found in pinned release")
        sys.exit(1)

    size_mb = asset.get("size", 0) / 1024 / 1024
    print(f"  {asset['name']} ({size_mb:.0f} MB)")

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _download(asset["browser_download_url"], tmp_path,
                  expected_digest=LOCKED_ASSET_DIGESTS[asset["name"]])
        print("  Extracting ...")
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(tmp_path) as zf:
                _safe_extract_zip(zf, tmpdir)
            roots = [p for p in Path(tmpdir).iterdir() if p.is_dir()]
            src = roots[0] if len(roots) == 1 else Path(tmpdir)
            TOOLS_DIR.mkdir(parents=True, exist_ok=True)
            if GHIDRA_DIR.exists():
                _safe_rmtree(TOOLS_DIR, GHIDRA_DIR, "Ghidra installation")
            shutil.copytree(str(src), str(GHIDRA_DIR))
    finally:
        tmp_path.unlink(missing_ok=True)

    ver = _ghidra_version(GHIDRA_DIR)
    if ver != PINNED_GHIDRA_VERSION:
        raise RuntimeError(
            f"downloaded Ghidra version {ver!r}; expected {PINNED_GHIDRA_VERSION}")
    print(f"  Ghidra {ver or '?'} installed")


def setup_steamless():
    if sys.platform != "win32":
        return

    _header("Steamless")
    cli = STEAMLESS_DIR / "Steamless.CLI.exe"
    if cli.is_file():
        cli_manifest = inspect_pe(str(cli))
        # The SHA-256 IS the identity.  atom0s ships release v3.1.0.5 with a
        # 3.1.0.0 version resource, so the embedded version is advisory only
        # -- gating on it rejects the exact pinned binary.
        mismatch = (cli_manifest.get("sha256", "").lower() !=
                    PINNED_STEAMLESS_CLI_SHA256)
        if mismatch and not os.environ.get("BGS_ALLOW_TOOLCHAIN_DRIFT"):
            raise RuntimeError(
                "Steamless.CLI.exe SHA-256 {} is installed; expected the "
                "pinned {} binary ({}...).  Delete tools/Steamless to "
                "re-fetch it.".format(
                    (cli_manifest.get("sha256") or "unknown")[:12],
                    PINNED_STEAMLESS_VERSION, PINNED_STEAMLESS_CLI_SHA256[:12]))
        print("  Steamless CLI: OK ({}...)".format(
            PINNED_STEAMLESS_CLI_SHA256[:12]))
        return

    print(f"  Fetching pinned Steamless {PINNED_STEAMLESS_VERSION} ...")
    req = urllib.request.Request(STEAMLESS_RELEASES_URL, headers=API_HEADERS)
    try:
        with urllib.request.urlopen(req) as resp:
            release = json.loads(resp.read())
    except Exception as e:
        raise RuntimeError(f"could not fetch pinned Steamless release: {e}") from e

    asset = next((a for a in release.get("assets", [])
                  if a["name"] == "Steamless.v3.1.0.5.-.by.atom0s.zip"), None)
    if not asset:
        raise RuntimeError("pinned Steamless asset is absent from its release")

    print(f"  {asset['name']}")
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _download(asset["browser_download_url"], tmp_path,
                  expected_digest=LOCKED_ASSET_DIGESTS[asset["name"]])
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(tmp_path) as zf:
                _safe_extract_zip(zf, tmpdir)
            hits = list(Path(tmpdir).rglob("Steamless.CLI.exe"))
            if len(hits) != 1:
                raise RuntimeError(
                    "pinned Steamless archive contains {} CLI candidates; "
                    "expected exactly one".format(len(hits)))
            src = hits[0].parent
            STEAMLESS_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copytree(str(src), str(STEAMLESS_DIR), dirs_exist_ok=True)
    finally:
        tmp_path.unlink(missing_ok=True)

    installed = inspect_pe(str(STEAMLESS_DIR / "Steamless.CLI.exe"))
    if installed.get("sha256", "").lower() != PINNED_STEAMLESS_CLI_SHA256:
        raise RuntimeError("installed Steamless CLI hash does not match lock")
    print("  Steamless CLI installed")
    (STEAMLESS_DIR / ".bgs-version").write_text(
        PINNED_STEAMLESS_VERSION + "\n", encoding="utf-8")


def setup_fakepdb():
    """Install the stable, hash-pinned public-symbol PDB generator."""
    if sys.platform != "win32":
        print("  FakePDB generation is available only on Windows")
        return
    _header("FakePDB")
    try:
        executable = validate_fakepdb_install(REPO_DIR)
        print(f"  FakePDB {PINNED_FAKEPDB_VERSION}: {executable} (verified)")
        return
    except FakePDBToolError as exc:
        print(f"  Local FakePDB is absent/unverified: {exc}")

    req = urllib.request.Request(FAKEPDB_RELEASES_URL, headers=API_HEADERS)
    with urllib.request.urlopen(req) as resp:
        release = json.loads(resp.read())
    asset_name = "fakepdb_v0.3.zip"
    asset = next((candidate for candidate in release.get("assets", [])
                  if candidate.get("name") == asset_name), None)
    if asset is None:
        raise RuntimeError("pinned FakePDB asset is absent from release v0.3")
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temporary:
        archive = Path(temporary.name)
    try:
        archive_hash = _download(
            asset["browser_download_url"], archive,
            expected_digest=LOCKED_ASSET_DIGESTS[asset_name])
        with tempfile.TemporaryDirectory() as extract_dir:
            with zipfile.ZipFile(archive) as zipped:
                _safe_extract_zip(zipped, extract_dir)
            hits = list(Path(extract_dir).rglob("fakepdb.exe"))
            if len(hits) != 1:
                raise RuntimeError(
                    "pinned FakePDB archive contains {} executable candidates; "
                    "expected exactly one".format(len(hits)))
            actual_hash = hashlib.sha256(hits[0].read_bytes()).hexdigest()
            if actual_hash != PINNED_FAKEPDB_EXE_SHA256:
                raise RuntimeError(
                    "FakePDB executable hash does not match toolchain lock")
            if FAKEPDB_DIR.exists():
                _safe_rmtree(TOOLS_DIR, FAKEPDB_DIR, "FakePDB installation")
            FAKEPDB_DIR.mkdir(parents=True)
            shutil.copy2(str(hits[0]), str(FAKEPDB_DIR / "fakepdb.exe"))
        write_fakepdb_receipt(REPO_DIR, archive_hash)
        validate_fakepdb_install(REPO_DIR)
    finally:
        archive.unlink(missing_ok=True)
    print(f"  FakePDB {PINNED_FAKEPDB_VERSION} installed (receipt verified)")


def _ensure_clang():
    clang_name = "clang.exe" if sys.platform == "win32" else "clang"
    local_clang = LLVM_DIR / "bin" / clang_name

    if local_clang.is_file():
        try:
            validate_repo_llvm_install(REPO_DIR)
            ver = _clang_version(local_clang)
            if _accept_clang_version(ver):
                os.environ["PATH"] = (str(LLVM_DIR / "bin") + os.pathsep +
                                      os.environ.get("PATH", ""))
                print(f"  {ver} (receipt verified)")
                return
        except PDBIdentityError as exc:
            print(f"  Local LLVM is unverified: {exc}")

    if os.environ.get("BGS_ALLOW_TOOLCHAIN_DRIFT"):
        ver = _clang_version()
        if _accept_clang_version(ver):
            print(f"  {ver}")
            print("  WARNING: repo llvm-pdbutil remains unavailable until "
                  "the pinned LLVM receipt is installed")
            return

    _download_llvm()
    validate_repo_llvm_install(REPO_DIR)
    os.environ["PATH"] = (str(LLVM_DIR / "bin") + os.pathsep +
                          os.environ.get("PATH", ""))
    ver = _clang_version(local_clang)
    if _accept_clang_version(ver):
        print(f"  {ver}")
    else:
        print("  ERROR: clang not working after LLVM install")
        sys.exit(1)


def _download_llvm():
    print(f"  clang not found; downloading pinned LLVM {PINNED_LLVM_VERSION} ...")

    req = urllib.request.Request(LLVM_RELEASES_URL, headers=API_HEADERS)
    with urllib.request.urlopen(req) as resp:
        release = json.loads(resp.read())

    if sys.platform == "win32":
        machine = platform.machine().lower()
        arch = "x86_64" if machine in ("amd64", "x86_64") else "aarch64"
        platform_key = "windows_" + arch
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
         if a["name"].endswith(suffix) and a["name"] in LOCKED_ASSET_DIGESTS),
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
        _download(asset["browser_download_url"], tmp_path,
                  expected_digest=LOCKED_ASSET_DIGESTS[asset["name"]])
        print("  Extracting (this may take several minutes) ...")
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as extract_dir:
            with tarfile.open(tmp_path, "r:xz") as tar:
                _safe_extract_tar(tar, extract_dir)
            clang_name = "clang.exe" if sys.platform == "win32" else "clang"
            candidates = [p.parent.parent for p in Path(extract_dir).rglob(clang_name)
                          if p.parent.name == "bin" and p.is_file()]
            roots = sorted(set(path.resolve() for path in candidates))
            if len(roots) != 1:
                raise RuntimeError(
                    f"pinned LLVM archive contains {len(roots)} candidate "
                    "toolchain roots; expected exactly one")
            if LLVM_DIR.exists():
                _safe_rmtree(TOOLS_DIR, LLVM_DIR, "LLVM installation")
            shutil.copytree(str(roots[0]), str(LLVM_DIR))
    finally:
        tmp_path.unlink(missing_ok=True)

    clang_name = "clang.exe" if sys.platform == "win32" else "clang"
    if not (LLVM_DIR / "bin" / clang_name).is_file():
        print("  ERROR: clang not found after LLVM extraction")
        sys.exit(1)
    if sys.platform != "win32":
        raise RuntimeError(
            "the current toolchain lock has no receipt identity for this platform")
    _algorithm, _separator, archive_sha256 = \
        LOCKED_ASSET_DIGESTS[asset["name"]].partition(":")
    write_llvm_install_receipt(
        LLVM_DIR, TOOLCHAIN_LOCK_FILE, platform_key,
        asset["name"], archive_sha256)
    validate_repo_llvm_install(REPO_DIR)
    print("  LLVM installed (binary receipt verified)")


def generate_scripts(games=None, only_version=None):
    """Generate import scripts.

    ``only_version`` (e.g. ``"og"``, ``"se"``) restricts the Skyrim/F4 parsers
    to that single runtime.  Each runtime costs a full clang AST + layout
    cycle, so the per-version menu passes it rather than rebuilding every
    sibling of the chosen game.
    """
    if games is None:
        games = _discover_games()
    if not games:
        print("  No executables found -- nothing to generate.")
        return

    _assert_submodules_clean()

    _prepare_binary_artifacts(games)
    prep_rc = _prepare_generation(games)
    if prep_rc != 0:
        raise RuntimeError(
            f"generation prerequisites failed (exit {prep_rc}); no import "
            "scripts were emitted")

    _header("Generating Import Scripts")
    _ensure_clang()

    only = ["--only", only_version] if only_version else []

    if "skyrim" in games:
        print("  Skyrim {} ...".format(only_version.upper() if only_version
                                       else "SE / AE / VR"))
        subprocess.run(
            [sys.executable,
             str(SCRIPTS_DIR / "commonlibsse" / "parse_commonlib_types.py"),
             *only],
            cwd=str(REPO_DIR), check=True)
    if "f4" in games:
        print("  Fallout 4 {} ...".format(only_version.upper() if only_version
                                          else "OG / NG / AE / VR"))
        subprocess.run(
            [sys.executable,
             str(SCRIPTS_DIR / "commonlibf4" / "parse_commonlib_types.py"),
             *only],
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
                cwd=str(REPO_DIR), check=True)
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


def run_headless(game=None, version=None, import_only=False):
    _header("Headless Ghidra Import")
    args = [sys.executable, str(SCRIPTS_DIR / "run_headless.py")]
    if game:
        args.append(str(game))
    if version:
        if not game:
            raise ValueError("a version filter requires a game filter")
        args.append(str(version))
    if import_only:
        args.append("--import-only")
    return subprocess.run(
        args,
        cwd=str(REPO_DIR)).returncode


def _prepare_binary_artifacts(games):
    """Materialize exact Steamless artifacts/lineage before generation."""
    for game, _version, binary in _discover_exes():
        if game not in games:
            continue
        result = _ensure_unpacked(binary, STEAMLESS_DIR / "Steamless.CLI.exe")
        if result != binary:
            print(f"  Prepared identity-bound artifact: {result.name}")


def sf_shift_check(preflight=False):
    """Pre-generation SF shift-map check.

    Idempotent: cheap no-op when the user's SF PE version already has
    matching reference + shift artifacts.  First run on a non-1.16.236
    build creates a clean generic Ghidra analysis, dumps target-bound vtable
    layouts, and builds a versioned map before any CommonLib importer exists.
    """
    sf_dir = EXES_ROOT / "starfield" / "sf"
    if not sf_dir.is_dir() or not any(sf_dir.glob("*.exe")):
        return 0  # No SF binary, skip entirely
    _header("SF Shift-Map Check")
    args = [sys.executable,
            str(SCRIPTS_DIR / "commonlibsf" / "sf_shift_check.py")]
    if preflight:
        args.append("--preflight")
    return subprocess.run(
        args,
        cwd=str(REPO_DIR), check=False).returncode


def _prepare_generation(games):
    """Build/validate derived prerequisites before emitting import scripts."""
    if "starfield" not in games:
        return 0
    # Fast path: a version/hash/layout-bound map (or the anchor reference) is
    # already ready.  Exit 2 asks us to create a clean generic program first.
    rc = sf_shift_check(preflight=True)
    if rc == 0:
        return 0
    if rc != 2:
        return rc
    rc = run_headless("starfield", "sf", import_only=True)
    if rc != 0:
        return rc
    return sf_shift_check(preflight=True)


def _finalize_build(rc, games):
    """Run required postconditions and persist state only for a full success."""
    if rc != 0:
        return rc
    _save_state(_get_submodule_hashes(), _get_exe_fingerprints())
    return 0


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

    locks = _project_lock_files(project_dir, GHIDRA_PROJECT_NAME)
    if locks:
        print("  Refusing to remove an active/stale Ghidra lock automatically.")
        for lock in locks:
            print(f"    {lock}")
        print("  Close the owning Ghidra/PyGhidra process and retry. If the lock")
        print("  is genuinely stale, remove it manually after verifying no owner exists.")
        return False

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
    return True


def _requirement_satisfied(import_name, requirement):
    if "==" not in requirement:
        return _can_import(import_name)
    distribution, expected = requirement.split("==", 1)
    try:
        if importlib.metadata.version(distribution) != expected:
            return False
    except importlib.metadata.PackageNotFoundError:
        return False
    # Check the native import only after the distribution version is known to
    # be the tested one.  Importing an arbitrary JPype build can terminate the
    # process on Windows before setup gets a chance to replace it.
    return _can_import(import_name)


def clean_project():
    _header("Clean Ghidra Project")
    project_dir = PROJECTS_DIR / GHIDRA_PROJECT_NAME
    if project_dir.exists():
        _safe_rmtree(PROJECTS_DIR, project_dir, "generated Ghidra project")
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
    try:
        validate_fakepdb_install(REPO_DIR)
        fakepdb_ok = True
    except FakePDBToolError:
        fakepdb_ok = False
    pkgs_ok = all(_requirement_satisfied(imp, requirement)
                  for imp, requirement in REQUIRED_PACKAGES.items())

    print()
    print("  Tools:")
    print(f"    Ghidra      : {ghidra_ver or 'not installed'}")
    print(f"    Clang       : {clang_ver or 'not installed'}")
    if sys.platform == "win32":
        print(f"    Steamless   : {'OK' if steamless_ok else 'not installed'}")
        print(f"    FakePDB     : {'OK' if fakepdb_ok else 'not installed'}")
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
    ("2", "Restore committed CommonLib submodule revisions"),
    ("3", "Process a specific version (per-version menu)"),
    ("4", "Generate import scripts (all detected versions)"),
    ("5", "Run headless Ghidra import"),
    ("6", "Open Ghidra"),
    ("7", "Full rebuild (generate + import all)"),
    ("8", "Clean Ghidra project (start fresh)"),
    ("9", "Enrich an existing Ghidra project (RTTI vtable pipeline)"),
    ("10", "Export symbols (JSON / .map / x64dbg / validated PDB)"),
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

    _run_enrichment_sequence(label, pdir, pname, program_path)


def _run_enrichment_sequence(label, pdir, pname, program_path):
    """Run option 9's mutators in order, stopping at the first failure."""
    import_script_name = _infer_commonlib_script(Path(program_path).name)
    # The CommonLib apply is the high-coverage precondition.  A failed or
    # deliberately skipped locked-project attempt must not cascade into RTTI
    # or a reconciler against a partial program.
    if not _offer_commonlib_apply(
            pdir, pname, program_path, import_script_name=import_script_name):
        print("  CommonLib pre-apply did not complete; RTTI was not started.")
        return False

    if not _wait_for_unlock(pdir, pname, "RTTI vtable pipeline"):
        return False
    args = [sys.executable,
            str(SCRIPTS_DIR / "core" / "run_vtable_pipeline.py"),
            pdir, pname, program_path]
    for target in _local_target_pe_candidates(program_path):
        args.extend(("--target-pe", str(target)))
    _header(f"RTTI vtable pipeline: {label} {program_path}")
    result = subprocess.run(args, check=False)
    if result.returncode == 3:
        extra = _prompt_for_target_pe(program_path)
        if extra:
            result = subprocess.run(args + ["--target-pe", extra], check=False)
    if result.returncode != 0:
        print(f"  RTTI pipeline failed (exit {result.returncode}); "
              "reconciler was not started.")
        return False

    # Reconcile against the same exact importer chosen above.  The helper
    # preflight-skips importers with no AST slot map or no target binding, so
    # the guided path needs no script-selection or dry-run questions.
    return _run_vtable_reconciler(
        pdir, pname, program_path, import_script_name=import_script_name)


def _export_menu():
    """Submenu: pick a Ghidra project + program, export its symbols to
    distributable formats (JSON map, plain .map, x64dbg .dd64, synthetic PDB).

    Synthetic PDB generation is public-symbol-only; the richer JSON remains the
    lossless exchange format for prototypes, provenance, and classifications.
    READ-ONLY against the project.
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
        pdb_ans = input("  build a validated shareable PDB package? (y/N) > ").strip().lower()
        analysis_ans = "n"
        if pdb_ans == "y":
            analysis_ans = input(
                "  include lower-confidence ANALYSIS names in PDB? (y/N) > "
            ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if not _wait_for_unlock(pdir, pname, "symbol export"):
        return
    args = [sys.executable,
            str(SCRIPTS_DIR / "core" / "symbol_export.py"),
            pdir, pname, program_path, out_dir]
    # A project commonly outlives the import path (moved game install, deleted
    # Steamless temp).  Offer the local exes; the exporter only trusts one
    # whose SHA-256 matches the Program's import hash.
    for target in _local_target_pe_candidates(program_path):
        args.extend(("--target-pe", str(target)))
    if sig_ans == "y":
        args.append("--signatures")
    if pdb_ans == "y":
        setup_fakepdb()
        args.extend(("--pdb", "--package"))
        if analysis_ans == "y":
            args.append("--include-analysis")
    _header(f"Symbol export: {label} {program_path}")
    subprocess.run(args, check=False)
    input("\n  Press Enter to return to main menu ... ")


def _infer_commonlib_script(program_name):
    """Return the best-fit ``CommonLibImport_*.py`` basename for a program.

    Order is specific-to-generic so e.g. ``Fallout4_1_11_221.exe`` resolves
    to the 221 script rather than the catch-all AE one.
    """
    n = program_name.lower()
    if 'starfieldvr' in n or 'starfield_vr' in n:
        return None
    if 'starfield' in n:
        return 'CommonLibImport_SF.py'
    if 'fallout4vr' in n or 'fallout4_vr' in n:
        return 'CommonLibImport_F4_VR.py'
    if 'falloutnv' in n:
        return 'CommonLibImport_FNV.py'
    if 'skyrimae' in n and 'gog' in n:
        # A re-keyed address database is not binary identity.  No importer is
        # emitted until an exact GOG executable is present and bound.
        return None
    if 'skyrimae' in n:
        return 'CommonLibImport_AE.py'
    if 'skyrimse' in n:
        # Bethesda names both SE and AE binaries SkyrimSE.exe.  Automatic
        # mutation requires an explicit version tag; never guess that a bare
        # basename is whichever Steam build happens to be current.
        if '1_5_97' in n or '1.5.97' in n:
            return 'CommonLibImport_SE.py'
        if ('1_6_1170' in n or '1.6.1170' in n or
                '_ae' in n or ' ae' in n):
            return 'CommonLibImport_AE.py'
        return None
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
        # Never guess a build from its basename; the offsets are versioned.
        return None
    return None


def _local_target_pe_candidates(program_path):
    """Return local exact-identity candidates for an option 9 program.

    These paths are evidence candidates, not trusted selections.  The RTTI
    subprocess inspects each PE, then requires one candidate's SHA, anchors,
    sections, image base, and pointer width to attest the live Program.  Both
    packed and identity-bound unpacked files are passed because a Combined
    project commonly records a deleted temporary Steamless path.
    """
    suggested = _infer_commonlib_script(Path(program_path).name)
    matches = [entry for entry in VERSION_CATALOG if entry[4] == suggested]
    if len(matches) == 1:
        target_dir = EXES_ROOT / matches[0][3]
        if target_dir.is_dir():
            found = sorted(path for path in target_dir.glob("*.exe")
                           if path.is_file())
            if found:
                return found
    # No inferred runtime (e.g. a GOG build, or a program named off-catalog):
    # offer every local executable.  These are candidates, not selections --
    # the consumer accepts one only when its SHA-256 attests the Program, so a
    # wider list costs a few hashes and never mis-binds.
    if not EXES_ROOT.is_dir():
        return []
    return sorted(path for path in EXES_ROOT.rglob("*.exe") if path.is_file())


def _prompt_for_target_pe(program_path):
    """Ask the user for the exact backing .exe when none was auto-discovered."""
    name = Path(program_path).name
    print()
    print(f"  The binary {name!r} was imported from was not found on disk, and")
    print("  no staged exe under exes/ matched it.  If you still have the exact")
    print("  .exe this program was imported from, enter its full path below")
    print("  (for a Steam build, the Steamless-unpacked .exe); blank to cancel.")
    try:
        raw = input("  target .exe > ").strip().strip('"')
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_file():
        print(f"  Not a file: {candidate}")
        return None
    return str(candidate)


# Per-version pyghidra applier in scripts/.  Each takes
# ``--project-dir``, ``--project-name`` and ``--program-path``.  Values are
# (applier_basename, [extra args]); the unified F4 applier accepts
# ``--version`` so all five F4 variants share one entry point.
_COMMONLIB_APPLY_SCRIPTS = {
    'CommonLibImport_SE.py':     ('apply_skyrim_to_user_project.py', ['--version', 'se']),
    'CommonLibImport_AE.py':     ('apply_skyrim_to_user_project.py', ['--version', 'ae']),
    'CommonLibImport_VR.py':     ('apply_skyrim_to_user_project.py', ['--version', 'vr']),
    'CommonLibImport_F4_OG.py':  ('apply_f4_to_user_project.py',  ['--version', 'og']),
    'CommonLibImport_F4_NG.py':  ('apply_f4_to_user_project.py',  ['--version', 'ng']),
    'CommonLibImport_F4_AE.py':  ('apply_f4_to_user_project.py',  ['--version', 'ae']),
    'CommonLibImport_F4_VR.py':  ('apply_f4_to_user_project.py',  ['--version', 'vr']),
    'CommonLibImport_F4_221.py': ('apply_f4_to_user_project.py',  ['--version', '221']),
    'CommonLibImport_FNV.py':    ('apply_fnv_to_user_project.py', []),
    'CommonLibImport_SF.py':     ('apply_sf_to_user_project.py',  []),
}


def _offer_commonlib_apply(
        pdir, pname, program_path, *, import_script_name=None):
    """Optional pre-step: apply CommonLibImport_<inferred>.py via pyghidra.

    Detects the matching import script from the program name and runs the
    per-version applier if one exists.  No-op when there's no applier for
    this version (e.g. F4 OG/NG/AE/VR -- those still go through menu 5's
    headless import path against the in-repo project).
    """
    program_name = Path(program_path).name
    suggested = (import_script_name or
                 _infer_commonlib_script(program_name))
    if not suggested:
        return True
    import_script = GHIDRA_SCRIPTS_DIR / suggested
    if not import_script.is_file():
        return True
    entry = _COMMONLIB_APPLY_SCRIPTS.get(suggested)
    if not entry:
        # No standalone applier for this version yet.
        return True
    applier_name, extra_args = entry
    applier = SCRIPTS_DIR / applier_name
    if not applier.is_file():
        return True

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
        return False
    if ans == 'n':
        return True

    if not _wait_for_unlock(pdir, pname, f"CommonLib apply ({suggested})"):
        return False
    cmd = [sys.executable, str(applier),
           *extra_args,
           '--project-dir',  pdir,
           '--project-name', pname,
           '--program-path', program_path]
    _header(f"CommonLib apply ({suggested})")
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        print(f"  CommonLib apply failed (exit {result.returncode}).")
        return False
    return True


def _run_vtable_reconciler(
        pdir, pname, program_path, *, import_script_name=None):
    """Reconcile stale CommonLib slot names with the inferred exact importer.

    The selected program already determines the exact generated importer.
    Never ask the user to choose another game's script or expose the backend's
    developer-only dry-run switch in the guided workflow.
    """
    program_name = Path(program_path).name
    suggested = (import_script_name or
                 _infer_commonlib_script(program_name))
    if not suggested:
        print("  Vtable reconciler skipped: game/version could not be inferred.")
        return True
    chosen = GHIDRA_SCRIPTS_DIR / suggested
    if not chosen.is_file():
        print(f"  Vtable reconciler skipped: {suggested} is not generated.")
        return True

    # Avoid a meaningless prompt when this importer has no AST-derived slot
    # table (currently true for F4 1.11.221).  The generic RTTI pass has still
    # completed; there is simply no older CommonLib slot map to reconcile.
    try:
        from vtable_name_reconciler import (
            _extract_target_manifests,
            _extract_vtables_from_import_script,
        )
        vtables = _extract_vtables_from_import_script(chosen)
    except (OSError, SyntaxError, TypeError, ValueError) as exc:
        print(f"  Vtable reconciler failed: cannot parse {suggested}: {exc}")
        return False
    if not vtables:
        print(f"  Vtable reconciliation not applicable: {suggested} has no "
              "VTABLES entries.")
        return True
    try:
        target_manifests = _extract_target_manifests(chosen)
    except (OSError, SyntaxError, TypeError, ValueError) as exc:
        print(f"  Vtable reconciler failed: cannot read target binding from "
              f"{suggested}: {exc}")
        return False
    if not target_manifests:
        print(f"  Vtable reconciler skipped safely: {suggested} has no exact "
              "TARGET_MANIFESTS binding.")
        return True

    if not _wait_for_unlock(pdir, pname, f"vtable reconciler ({chosen.name})"):
        return False
    cmd = [sys.executable,
           str(SCRIPTS_DIR / 'core' / 'vtable_name_reconciler.py'),
           '--project-dir',  pdir,
           '--project-name', pname,
           '--program',      program_path,
           '--import-script', str(chosen)]
    _header(f"Vtable name reconciler ({chosen.name})")
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        print(f"  Vtable reconciler failed (exit {result.returncode}).")
        return False
    return True


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
            _finalize_build(rc, present)
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
        version = Path(subdir).name
        # Each runtime is a full clang AST + layout cycle, so generate only
        # the one the user picked (Starfield/FNV parsers are single-runtime
        # already and ignore the filter).
        generate_scripts({game}, only_version=version)
        rc = run_headless(game, version)
        _finalize_build(rc, {game})
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
        try:
            if choice == "1":
                check_prerequisites()
                setup_ghidra()
                setup_steamless()
                setup_fakepdb()
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
                _finalize_build(rc, _discover_games())
            elif choice == "6":
                launch_ghidra()
                break
            elif choice == "7":
                games = _discover_games()
                generate_scripts(games)
                rc = run_headless()
                _finalize_build(rc, games)
            elif choice == "8":
                clean_project()
            elif choice == "9":
                _enrich_menu()
            elif choice == "10":
                _export_menu()
            else:
                print("  Invalid choice.")
                continue
        except RuntimeError as exc:
            # e.g. locked-runtime install failure or submodule drift; report
            # and return to the menu instead of crashing out of it.
            print(f"\n  ERROR: {exc}")

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
    setup_fakepdb()
    _ensure_clang()


def _cmd_build():
    games = _discover_games()
    if not games:
        print("No executables found.")
        sys.exit(1)
    generate_scripts(games)
    rc = run_headless()
    rc = _finalize_build(rc, games)
    sys.exit(rc)


def _cmd_all():
    _cmd_setup()
    games = _discover_games()
    if not games:
        print("No executables found.")
        sys.exit(1)
    generate_scripts(games)
    rc = run_headless()
    rc = _finalize_build(rc, games)
    if rc != 0:
        print("Build failed; refusing to open a partial/stale project.")
        sys.exit(rc)
    if launch_ghidra() is not True:
        print("Build succeeded, but Ghidra could not be launched safely.")
        sys.exit(1)
    sys.exit(0)


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


def _configure_utf8_console():
    """Keep FD-level tee output readable on legacy Windows code pages."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        if kernel32.GetConsoleOutputCP():
            kernel32.SetConsoleOutputCP(65001)
        if kernel32.GetConsoleCP():
            kernel32.SetConsoleCP(65001)
    except (AttributeError, OSError):
        pass


def main():
    _require_supported_python()
    _configure_utf8_console()
    _enable_log_tee()
    args = sys.argv[1:]
    if not args:
        # A supported interpreter is not necessarily a prepared interpreter.
        # Bootstrap its exact locked wheels before any menu action can import
        # PyGhidra (or spawn a child using this same sys.executable).
        try:
            _ensure_python_packages()
        except RuntimeError as exc:
            print(f"\n  ERROR: {exc}")
            raise SystemExit(1)
        _run_menu()
    elif args[0] in ("setup", "build", "all", "clean"):
        try:
            {"setup": _cmd_setup, "build": _cmd_build,
             "all": _cmd_all, "clean": clean_project}[args[0]]()
        except RuntimeError as exc:
            print(f"\n  ERROR: {exc}")
            raise SystemExit(1)
    else:
        print(f"Unknown command: {args[0]}")
        print("Usage: python run.py [setup|build|all|clean]")
        sys.exit(1)


if __name__ == "__main__":
    main()
