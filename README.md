# Bethesda Ghidra Scripts

Automatically imports CommonLib type definitions, vtable layouts, function
signatures, and address-library symbols into Ghidra for Bethesda game binaries.

## Quick start

1. Clone the repo:

```bash
git clone https://github.com/1001Bits/BethesdaGhidraScripts.git
cd BethesdaGhidraScripts
```

2. Drop your game executables into the matching folders (any combination):

```
exes/skyrim/se/SkyrimSE.exe       Skyrim SE    (1.5.97)
exes/skyrim/ae/SkyrimSE.exe       Skyrim AE    (1.6.1170+)
exes/skyrim/vr/SkyrimVR.exe       Skyrim VR    (1.4.15)
exes/f4/og/Fallout4.exe           Fallout 4 OG (1.10.163) — types only
exes/f4/ng/Fallout4.exe           Fallout 4 NG (1.10.984)
exes/f4/ae/Fallout4.exe           Fallout 4 AE (1.11.191)
exes/f4/221/Fallout4.exe          Fallout 4 AE (1.11.221)
exes/f4/vr/Fallout4VR.exe         Fallout 4 VR (1.2.72)   — types only
exes/starfield/sf/Starfield.exe   Starfield    (1.16.236 / 1.16.242 / 1.16.244) — labels + vtables
exes/fnv/og/FalloutNV.exe         Fallout NV   (1.4.0.525, x86) — xNVSE-sourced
```

Fallout New Vegas now flows through the same pipeline as the other versions
(symbol source: xNVSE headers + optional `scripts/commonlibnvse/refs/fnv_names.csv`
overlay). Menu option 9 (improve-existing) still works against any other FNV
project you have lying around, but option 7 (full rebuild) handles FNV
end-to-end like Skyrim / F4 / Starfield.

3. Run:

```bash
python run.py
```

This opens an interactive menu:

```
============================================================
  Bethesda Ghidra Scripts
============================================================

  Tools:
    Ghidra      : 12.0.4
    Clang       : clang version 20.1.8
    Steamless   : OK
    Python pkgs : OK

  Executables:
    f4/ae: Fallout4.exe
    f4/vr: Fallout4VR.exe
    skyrim/ae: SkyrimSE.exe
    skyrim/se: SkyrimSE.exe
    skyrim/vr: SkyrimVR.exe
    starfield/sf: Starfield.exe

  Output:
    Import scripts : OK
    Ghidra project : OK

----------------------------------------
  1) Install prerequisites (Python packages, Ghidra, Clang, Steamless)
  2) Restore committed CommonLib submodule revisions
  3) Process a specific version (per-version menu)
  4) Generate import scripts (all detected versions)
  5) Run headless Ghidra import
  6) Open Ghidra
  7) Full rebuild (generate + import all)
  8) Clean Ghidra project (start fresh)
  9) Improve an existing Ghidra project (RTTI vtable pipeline)
 10) Export symbols from an improved project (JSON / .map / x64dbg / PDB)
  q) Quit
----------------------------------------
```

The status panel at the top shows what's installed and detected. Menu options:

| Option | What it does |
|--------|-------------|
| **1** | Installs the locked Python packages and exact Ghidra 12.0.4, LLVM 20.1.8, Steamless 3.1.0.5, and FakePDB 0.3 assets. Downloads and installed native binaries are SHA-256/receipt verified. PDB identity/public extraction uses the repository's strict MSF reader and LLVM tooling; the obsolete `pdbparse` dependency is not installed. |
| **2** | Runs `git submodule update --init --recursive` and restores the reviewed commits recorded by this repository. It does not silently move the evidence base to an unreviewed upstream revision. |
| **3** | Per-version submenu: pick one detected version (e.g. just Skyrim VR, or just Fallout 4 OG) and run a subset of the pipeline against it -- generate only that version's script, import only its binary, etc. Useful when you don't want to rerun every game. |
| **4** | Parses every supported CommonLib's headers with clang and generates the Ghidra import scripts under `ghidrascripts/` for **all** detected versions. Requires clang (option 1 installs it). When a VR executable is staged it additionally parses CommonLibVR / CommonLibF4VR with the VR defines set, producing importers with the real VR struct layouts and vtable slots -- these are emitted only after the slots are checked against a hand-verified anchors CSV for that binary. |
| **5** | Runs exact-target generated importers in headless Ghidra. PE identity, unpacking lineage, importer identity, architecture, sections, and anchors are checked before mutation. Import is transactional; a changed script requires a clean re-import. |
| **6** | Opens Ghidra with the project loaded. |
| **7** | Runs options 4 + 5 back-to-back. Use this after updating submodules or replacing an executable. |
| **8** | Deletes the Ghidra project and state file so the next import starts from scratch. |
| **9** | Picks an existing Ghidra project (yours, not the BGS one) and a program inside it, then runs three steps in order, stopping at the first failure: **(a)** apply the exact CommonLib importer for that build, **(b)** the generic RTTI-walk vtable-naming pipeline, **(c)** the vtable name reconciler. Step (b) works on any MSVC PE that Ghidra has finished auto-analyzing (x64 or x86), including binaries this repo has no CommonLib for -- Fallout New Vegas, modded engine builds, etc. -- and only renames functions still carrying Ghidra's default `FUN_*` placeholder. Step (c) additionally corrects *stale CommonLib slot names* that an older emission got wrong, and leaves hand-typed names alone; it is skipped when the importer has no AST slot map. For Skyrim VR and Fallout 4 VR the flow automatically prefers the true-VR importers (CommonLibVR / CommonLibF4VR) over the flatscreen ones, which emit no VR vtables at all. An importer that is not bound to a build is never applied: you are offered a regeneration instead, and if the executable it was imported from is gone, it can be recovered from the Ghidra project itself (Ghidra stores the imported bytes) and verified against the program's import-time SHA-256. |
| **10** | Exports symbols from an improved project as JSON, map, or x64dbg-compatible data. It can also build, round-trip validate, and package an exact-executable synthetic public-symbol PDB. |

**First-time setup:** run **1**, then **2**, then **7**. After that, **6** opens Ghidra with everything
imported. Option **9** is still available as an improve-only pass against any
externally-prepared Ghidra project (handy when you already have a heavily-
annotated FNV / modded-engine project somewhere else).

### Non-interactive mode

For CI or scripting, pass a subcommand instead of using the menu:

```bash
python run.py setup   # option 1 + 2: install tools, restore committed submodules
python run.py build   # option 7: generate scripts + headless import
python run.py all     # setup + build + open Ghidra
python run.py clean   # remove only this pipeline's generated project/state
```

### Migrating an older checkout

Generated importers, Steamless caches, shift maps, and mined CSVs created by an
older identity-unbound pipeline are intentionally not trusted. Regenerate them
from the exact executables. If an existing pipeline project records a legacy or
different importer stage, run `python run.py clean` before rebuilding; applying
the new script over old symbols could otherwise leave stale names behind.
Research-only legacy corpora remain quarantined until they have exact source,
target, coordinate, and content provenance.

### How it works

All binaries end up in a single Ghidra project at
`ghidraprojects/BethesdaGhidraScripts/`, organized into `/<game>/<version>/`
folders.

The address library for each executable is selected automatically based on
the detected PE version. For Skyrim AE, all versions from 1.6.317 to 1.6.1179
are supported via the AddressLibraryDatabase.

### Requirements

- **CPython 3.11 through 3.14** (64-bit)
- **Git**

Clang, Ghidra, Steamless, and Python packages are all fetched automatically on
first run. Reproducible versions and asset digests live in
`toolchain.lock.json`; Python runtime pins live in `requirements.lock.txt`.
The launcher deliberately uses binary wheels and selects the newest installed
supported CPython instead of blindly using the newest Python on the machine.
It verifies and, when necessary, installs the locked runtime into that selected
interpreter before displaying the menu, so a newly selected Python cannot reach
an improvement action without PyGhidra being present.
For CPython 3.14 it installs PyGhidra 3.0.2 without dependency re-resolution and
uses the tested JPype 1.7.1 bridge; PyGhidra's older JPype 1.5.2 pin has no
CPython 3.14 wheel. Consequently, `pip check` on 3.14 reports PyGhidra's stale
JPype metadata pin even though the locked bridge is intentional and tested.
Python 3.15 is currently a prerelease and remains outside this dependency
matrix: Ghidra and JPype currently advertise support only through Python 3.14,
and compatible CPython 3.15 binary wheels are not yet available for the full
runtime. It fails immediately with a clear version message rather than
attempting an unreproducible native build. Support can be added once the
upstream bridge and wheel set exist and pass the same project-open tests.

The standard-library `imp` module was removed in Python 3.12 (not 3.14). The
legacy `pdbparse` package is tied to Construct 2.9.x, which imports `imp`, so it
is intentionally excluded on every Python version. This does not disable the
maintained PDB path: exact GUID/age validation and public-symbol extraction use
the built-in MSF 7 reader, with LLVM/DIA used where richer records are needed.
Here, “3.11 through 3.14” refers to the **CPython** version; the automatically
installed Ghidra version is separately locked to 12.0.4.

For a manual dependency install, preserve the lock's no-resolution rule:

```bash
python -m pip install --no-deps --only-binary=:all: -r requirements.lock.txt
```

The locked automatic LLVM/Steamless setup currently targets Windows. On another
host, provide LLVM 20.1.8 and an identity-sidecar-bound unpacked PE prepared on
Windows when the source contains a SteamStub `.bind` section.

---

## Supported games

| Game           | Folder              | Address library    | CommonLib                                         |
|----------------|---------------------|--------------------|---------------------------------------------------|
| Skyrim SE      | `exes/skyrim/se`    | `1-5-97-0`         | `powerof3/CommonLibSSE`                           |
| Skyrim AE      | `exes/skyrim/ae`    | `1-6-1170-0`       | `powerof3/CommonLibSSE`                           |
| Skyrim VR      | `exes/skyrim/vr`    | `1-4-15-0` (csv)   | `powerof3/CommonLibSSE` + `alandtse/CommonLibVR` (true VR layouts) |
| Fallout 4 OG   | `exes/f4/og`        | `1-10-163-0`       | `libxse/commonlibf4`                              |
| Fallout 4 NG   | `exes/f4/ng`        | `1-10-984-0`       | `libxse/commonlibf4`                              |
| Fallout 4 AE   | `exes/f4/ae`, `exes/f4/221` | `1-11-191-0` / `1-11-221-0` | `libxse/commonlibf4` (+ 1.11.221 PDB publics) |
| Fallout 4 VR   | `exes/f4/vr`        | `1-2-72-0` (csv)   | `libxse/commonlibf4` + `ArthurHub/CommonLibF4VR` (true VR layouts) |
| Starfield      | `exes/starfield/sf` | `1-16-236-0` / `1-16-242-0` / `1-16-244-0` (V5, auto) | `Starfield-Reverse-Engineering/CommonLibSF`       |
| Fallout NV     | `exes/fnv/og`       | n/a — xNVSE hardcoded VAs | `xNVSE/NVSE` (x86) + optional `refs/fnv_names.csv` |

You don't need all of them. The script detects which executables are present
and only generates and runs what's needed.

Skyrim VR shares the SE-derived ID namespace with SE/AE, so the same
`CommonLibSSE` headers generate a VR-targeting script that resolves SE IDs
against the VR address library.  The VR address library ships as a CSV
(community-maintained) rather than meh321's binary format.

That is not enough on its own: the flatscreen CommonLibs describe VR structs as
if they were SE/OG ones, and they emit no VR vtables at all.  So each VR runtime
is also parsed from a CommonLib that really models it (`alandtse/CommonLibVR`,
`ArthurHub/CommonLibF4VR`), giving the true struct sizes and vtable slots --
checked against a hand-verified anchors CSV before anything is written, and used
by menu option **9** automatically.

CommonLibF4's IDs sit in the NG/AE namespace (1.10.984 / 1.11.191), so those
two versions get full type + function symbol coverage from the address
library alone.  F4 OG (1.10.163) and F4 VR (1.2.72) use disjoint ID
namespaces that CommonLibF4 does not reference; the address library can't
transfer names directly because looking up an AE-namespace ID against the
OG or VR DB only finds coincidental low-ID matches at wrong addresses.

To get function names onto OG and VR anyway, the F4 pipeline runs a
cross-version byte-signature port (`scripts/commonlibf4/run_bytesig_port.py`)
after script generation.  Anchored at AE (or NG when AE is absent), it scans
each AE-named function's first 32 bytes for an exact, unique match in the
OG/VR binary; unmatched names get a 48-byte masked retry that wildcards
rel32 and rip-relative operands so cross-build jump targets stop confusing
the match.  Matched (name, target_rva) pairs are merged back into the
generated `CommonLibImport_F4_OG.py` / `_VR.py` scripts so they apply
function names alongside the types when the script runs.

The byte-sig port only runs when both AE (or NG) and the target binary are
present in `exes/f4/`; without them, OG/VR fall back to types-only coverage.

For 1.11.221, the checked-in community PDB corpus now contains 37,714 exact-RVA
public records from the latest supplied snapshot (4,068 more than the prior
snapshot). It is a synthetic **public-symbol-only** PDB: it contains no compiler
types, locals, private procedure records, source files, or line tables. The
loader quarantines 15 same-RVA alias groups and 60 names used at multiple RVAs;
cross-version byte-signature seeding is further limited to reciprocal-unique
executable `.pdata` starts. The raw third-party PDB is not redistributed while
its author/license are unknown; the derived corpus pins its SHA-256, GUID/age,
target hashes, counts, and extractor hashes.

Starfield uses the `Starfield-Reverse-Engineering/CommonLibSF` headers and
meh321's **V5** address-library binary format (flat `uint32[id]` array
indexed by ID -- much simpler than the V1/V2 delta encoding SSE/F4 use).
Function-name coverage on Starfield is currently bounded by what
CommonLibSF's `IDs.h` / `IDs_RTTI.h` / `IDs_NiRTTI.h` / `IDs_VTABLE.h`
manifests cover plus the vtable-walk pass that names virtual function
implementations from RTTI labels -- ~2,933 named functions on a fresh
Starfield 1.16.236.0 import, versus 299 from auto-analysis alone.

The SF pipeline reads the FileVersion resource from `Starfield.exe`
(SteamStub scrambles `VS_FIXEDFILEINFO`, but the string table is
untouched) and loads the matching `versionlib-X-Y-Z-W.bin` from
`addresslibrary/starfield/`.  1.16.236, 1.16.242 and 1.16.244 ship pre-bundled;
to support a future SF patch, drop the new bin into that directory and
the loader picks it up automatically.  Mismatched builds fail loud
(listing what IS available) instead of silently mis-naming functions.
CommonLibSF's ID manifests are authored against 1.16.236, but meh321's
append-only ID convention keeps those resolutions stable across the
1.16.x line -- only ID-namespace-changing patches (1.15 → 1.16 was one)
break compatibility.

**Auto-generated shift maps for non-1.16.236 builds.** Before generating a
Starfield importer, `run.py` invokes
`scripts/commonlibsf/sf_shift_check.py --preflight`, which:

1. Binds the exact PE hash/version and the exact matching V5 version library.
2. If a validated map is absent, creates a clean, identity-bound generic
   Ghidra import without applying CommonLib names.
3. Dumps the target's physical primary and secondary vtables via a
   small pyghidra script (`scripts/commonlibsf/dump_vtable_layouts.py`,
   using exact version-library addresses plus MSVC COL metadata, not imported
   names as self-confirming evidence.
4. Binds the compressed layout and its version library to sidecar hashes,
   then diffs against the similarly-bound 1.16.236 reference.
5. Writes `refs/shift_sf_<version>.json` only when class, coverage, layout,
   and target-identity checks pass. Generation consumes that exact map in the
   same build, so a second build is not required.

If you're on a build that doesn't have a pre-shipped shift map (e.g.
1.16.242 / 1.16.244 today), please share the dumped
`scripts/commonlibsf/refs/sf_<version>_vtables.csv.gz` in a GitHub
issue so the next release can ship a pre-built shift map for everyone
else on that version.

Fallout NV uses `xNVSE/NVSE` as its symbol/type source. Its reviewed corpus
contains fixed Steam-layout RVAs, so a matching version resource alone is not
accepted. Before generation, the pipeline verifies all 3,269 physical vtables
and 54,346 expected function pointers against the selected PE, including
section roles and file-backed spans. This rejects same-version executables
with a different memory layout. Explicit VA/RVA tags are normalized against
the 0x00400000 image base. Type extraction runs the same libclang
AST + record-layout pipeline as the other versions; xNVSE's game types
live at global scope (no `RE::` namespace) so they land under category
`/xNVSE/` rather than `/CommonLibSSE/RE/`. Names that xNVSE doesn't expose
can be added by dropping a CSV into `scripts/commonlibnvse/refs/fnv_names.csv`
(see `fnv_names.csv.example` for the format).

For any other MSVC-built game we don't have a CommonLib for, menu option 9
still runs the generic RTTI-driven vtable pipeline
(`scripts/core/run_vtable_pipeline.py`) against an existing Ghidra project.
It walks COL/TypeDescriptor pairs that Ghidra's own analyzer found, derives
vtable struct layouts, and renames the virtual function bodies they point
to -- conservatively, only if the function's name is still Ghidra's
`FUN_*`/`thunk_FUN_*` placeholder. Works on both x64 and x86 binaries.

---

## What gets imported

Subject to target-specific source coverage, each binary receives:

- All enums, structs, and classes from CommonLib headers with exact field
  offsets and sizes (parsed via clang `-ast-dump` and `-fdump-record-layouts`)
- Primary and secondary vtable structs for multi-inheritance hierarchies
- Virtual function names from vtable address walks
- Function signatures built from CommonLib type descriptors
- Address-library symbols (function labels, RTTI, vtable pointers)
- Fallback symbols from an exact CodeView-matching PDB or reviewed IDA-derived
  evidence where available; OMAP-remapped PDBs use original section headers
- `Source:` plate comments on named functions showing which symbol table
  provided the name

### Accuracy

The generator fails on partial clang output or architecture disagreement. It
preserves record kind (struct/class/union), arrays, pointer width, base offsets,
and overload signatures. Unresolved storage remains explicit opaque/padding
data instead of receiving an invented semantic type. Symbols are admitted only
inside the asserted section and executable entries are created only from PE
unwind starts, decoded vtable targets, or other source evidence marked as a
verified entry. Generated scripts preflight the exact target before opening a
transaction and roll back types and symbols together on any error.

### Sharing synthetic PDBs

Menu option **10** can create a shareable symbol bundle from any improved
project. It uses the pinned stable FakePDB 0.3 generator with the exact
executable, then re-parses the output and requires the GUID, age, machine,
sections, symbol set, and function/data classification to round-trip exactly
before installing the PDB. The default PDB includes only `IMPORTED` and
`USER_DEFINED` reciprocal-unique names; lower-confidence `ANALYSIS` names are
an explicit opt-in.

The resulting ZIP contains the expected `.pdb` basename, rich
`.symbols.json`, provenance sidecar, and usage notice. This is useful for
WinDbg, Visual Studio, IDA, Ghidra, crash symbolication, and collaboration—but
it is a names-at-RVAs PDB, not a replacement for original compiler debug data.
Function prototypes remain in JSON because FakePDB does not emit TPI/IPI,
locals, ranges, or line records. Synthetic PDBs copy the executable's original
GUID/age for automatic loading, so different revisions collide in debugger
symbol caches; distribute one curated revision per exact executable SHA-256.

---

## Improvement drivers (beyond CommonLib import)

CommonLib import gets you exact types where CommonLib has coverage. On top of
that, the repo ships **binary-derived improvement drivers** that recover names
and types straight from the analyzed binary — valuable where CommonLib is thin
(newer builds, Starfield, FNV) or absent. They run against an exact-identity
analyzed Ghidra
project via `scripts/discover_combined.py` (multi-program sequencer) or
`scripts/apply_enrichment_to_user_project.py` (one driver, one program), and
name mutators preserve analyst/imported symbols unless the selected reviewed
apply workflow explicitly targets a datatype field or evidence decision.

| Driver | What it recovers |
|---|---|
| `string_anchored_rename` | Names `FUN_*` from self-identifying debug/log strings the function references |
| `ctor_mine` / `ctor_apply` | Mines constructors for field names + embedded-object types, applies them to the struct |
| `globals_harvest` / `globals_apply` | Types global singletons by the class whose methods consume them |
| `settings_harvest` | Names + types game-setting value fields (`fXxx`/`bXxx`/`iXxx`) |
| `console_harvest` / `console_harvest_sf` | Names console-command handlers (`Cmd_*`) — table-based, plus Starfield's code-based registration |
| `pe_unwind_enrich` | Recovers validated x64 function starts, chained unwind records, handlers, and unwind comments from the PE exception directory |
| `registration_harvest` | Recovers decoded one-to-one registration/global associations and applies only high-confidence unique names |

Mutation is opt-in by evidence group (`--apply-renames`, `--apply-ctors`,
`--apply-globals`, `--apply-settings`, `--apply-console`, `--apply-metadata`,
`--apply-registries`, or `--apply-all-reviewed`). Applied discovery repeats up
to four passes by default and stops early at a fixed point. Persistent
constructor/global/registration CSVs carry target SHA-256 and
content sidecars; an old or edited artifact is refused until it is regenerated
or explicitly reviewed through the decision file workflow.

---

## Advanced usage

### Running pipeline scripts directly

The `run.py` menu is the recommended interface. If you need to run individual
pipeline steps (e.g. regenerating only one game, or importing a single target):

```bash
# Generate import scripts only (requires clang)
python scripts/commonlibsse/parse_commonlib_types.py   # Skyrim SE + AE
python scripts/commonlibf4/parse_commonlib_types.py    # Fallout 4 AE
python scripts/commonlibsf/parse_commonlib_types.py    # exact detected SF build
python scripts/commonlibnvse/parse_commonlib_types.py  # attested FNV layout

# Run headless Ghidra import (requires generated scripts + Ghidra)
python scripts/run_headless.py                # all targets
python scripts/run_headless.py skyrim         # all skyrim versions
python scripts/run_headless.py skyrim ae      # specific target
python scripts/run_headless.py f4 ae

# Build a clean Starfield layout baseline without applying generated names
python scripts/run_headless.py starfield sf --import-only

# Compile every script, run static safety checks, then run maintained tests
python scripts/quality_gate.py
```

### Symbol priority

Symbols are applied in priority order. Higher-priority sources take precedence:

1. `RELOCATION_ID(SE, AE)` / `REL::ID` macros (CommonLib)
2. `Offsets_RTTI.h`, `Offsets_NiRTTI.h`, `Offsets_VTABLE.h` labels
3. `RE::Offset::` namespace IDs (Skyrim)
4. CommonLibSSE `src/*.cpp` cross-references (Skyrim only)
5. AE rename DB (`skyrimae.rename`) -- Skyrim AE only
6. PDB public symbols (`SkyrimSE.pdb`) -- Skyrim
7. IDA names (`IDAImportNames_1.11.191.0.py`) -- Fallout 4 AE

### Project layout

```
.
├── run.py                           Interactive launcher / menu
├── extern/                          CommonLib submodules (auto-updated)
├── addresslibrary/                  Address library .bin files
├── extras/                          Fallback symbol sources (PDB, IDA)
├── exes/                            Game executables (you provide these)
├── scripts/                         Pipeline source code
│   ├── run_headless.py              Headless Ghidra runner
│   ├── core/                        Shared: clang parser, script emitter
│   ├── commonlibsse/                Skyrim SE/AE pipeline
│   ├── commonlibvr/                 Skyrim VR pipeline (true VR layouts)
│   ├── commonlibf4/                 Fallout 4 OG/NG/AE pipeline
│   ├── commonlibf4vr/               Fallout 4 VR pipeline (true VR layouts)
│   ├── commonlibsf/                 Starfield pipeline
│   └── commonlibnvse/               Fallout New Vegas pipeline (x86)
├── ghidrascripts/                   Generated import scripts (output)
├── ghidraprojects/                  Ghidra project (output)
└── tools/                           Ghidra, Steamless, LLVM, FakePDB (auto-downloaded)
```

---
