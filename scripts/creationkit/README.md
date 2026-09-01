# Creation Kit evidence and cross-binary naming

## Fallout 4 full-analysis workflow

The Fallout 4 workflow is pinned to Steam Creation Kit `1.11.137.0` at
`C:\games\steam\steamapps\common\Fallout 4\CreationKit.exe` (SHA-256
`222fd0aad949e76721d85c922ae508ada6816ba2f3e1fc11647c7239c24c2e13`).
It imports the Program at the unique ExampleProject path
`/Creation Kit/CreationKit Fallout 4 1.11.137.0.exe` and never overwrites the
Skyrim or Starfield editor Programs.

Run the checkpointed generic stages with Ghidra closed:

```powershell
python scripts/creationkit/analyze_fallout4_creationkit.py import
python scripts/creationkit/analyze_fallout4_creationkit.py analyze --label baseline
python scripts/creationkit/analyze_fallout4_creationkit.py unwind
python scripts/creationkit/analyze_fallout4_creationkit.py analyze --label post-unwind
```

Then run Ghidra's native MSVC class recovery in a fresh JVM. The temporary
directory is placed on `D:` to protect the project drive's free-space margin:

```powershell
$env:JAVA_TOOL_OPTIONS = '-Djava.io.tmpdir=D:\GhidraTemp\Fallout4CreationKit -XX:ActiveProcessorCount=4'
& tools\ghidra\support\analyzeHeadless.bat C:\GhidraProjects 'ExampleProject/Creation Kit' `
  -process 'CreationKit Fallout 4 1.11.137.0.exe' -noanalysis `
  -scriptPath tools\ghidra\Ghidra\Features\Decompiler\ghidra_scripts `
  -postScript RecoverClassesFromRTTIScript.java -max-cpu 4
python scripts/creationkit/analyze_fallout4_creationkit.py policy
```

Audit and apply the generic RTTI/vtable pass:

```powershell
python scripts/core/run_vtable_pipeline.py C:/GhidraProjects ExampleProject `
  '/Creation Kit/CreationKit Fallout 4 1.11.137.0.exe' `
  --target-pe 'C:\games\steam\steamapps\common\Fallout 4\CreationKit.exe' --dry-run
python scripts/core/run_vtable_pipeline.py C:/GhidraProjects ExampleProject `
  '/Creation Kit/CreationKit Fallout 4 1.11.137.0.exe' `
  --target-pe 'C:\games\steam\steamapps\common\Fallout 4\CreationKit.exe'
```

Finally, with Ghidra closed, dry-run/review/apply the CKPE evidence, then do
the same for the reciprocal byte-signature ledger:

```powershell
python scripts/creationkit/analyze_fallout4_creationkit.py ckpe-dry
# Review scripts/creationkit/refs/generated/ckpe_fo4_1_11_137_0_*.json/csv
python scripts/creationkit/analyze_fallout4_creationkit.py ckpe-apply
python scripts/creationkit/bytesig_port_fallout4_to_ck.py `
  --project-dir C:/GhidraProjects --project-name ExampleProject
# Review scripts/creationkit/refs/fallout4_to_creationkit_1_11_137_0.csv
python scripts/creationkit/bytesig_port_fallout4_to_ck.py `
  --project-dir C:/GhidraProjects --project-name ExampleProject --apply
python scripts/creationkit/analyze_fallout4_creationkit.py policy
& tools\ghidra\support\analyzeHeadless.bat C:\GhidraProjects 'ExampleProject/Creation Kit' `
  -process 'CreationKit Fallout 4 1.11.137.0.exe' -noanalysis `
  -scriptPath scripts\creationkit `
  -postScript VerifyAndFinalizeFallout4CreationKit.java -max-cpu 4
python scripts/creationkit/analyze_fallout4_creationkit.py metrics
```

The supplied Fallout4 game PDB is not a CK PDB: its CodeView GUID differs, so
it must never be loaded into this Program.

`apply_ckpe_evidence.py` is the shared, exact-version CKPE relocation-evidence
importer. The repository currently locks these targets:

| Entry point | Product | Version | Exact SHA-256 |
| --- | --- | --- | --- |
| `apply_ckpe_evidence.py` | Skyrim Creation Kit | `1.6.1378.1` | `3e8f7215303a82d8991f87fbc42eb84ef2672d5d8ab038212447faecfdf37b23` |
| `apply_fallout4_ckpe_evidence.py` | Fallout 4 Creation Kit | `1.11.137.0` | `222fd0aad949e76721d85c922ae508ada6816ba2f3e1fc11647c7239c24c2e13` |

The apply pass is intentionally annotation-only: it adds neutral evidence
labels, provenance plate comments, and bookmarks. It does not create or rename
functions and never calls `setPrimary`. New labels at function entries are
deliberately skipped because Ghidra may implicitly make such a label primary;
the comment and bookmark still preserve the evidence at those addresses.

Each target is locked by SHA-256, PE size, file version, timestamp, image
layout, and live Ghidra import metadata. CKPE inputs are locked to commit
`cfd8533d7522822242d0b0602fe77d17bc929cea` with canonical content hashes.
Masked signatures are checked against the loaded Program. A mismatching,
unreadable, malformed, or unsupported signature is reported but never
annotated. The Fallout 4 profile uses its own label/bookmark namespace, so its
evidence cannot collide with Skyrim CK annotations.

The Fallout 4 `1.11.137.0` database audit contains 87 `.relb` files and 474
rows. Against the exact executable above, 201 byte masks match and 199
exact-version rows have no mask, for 400 conservatively eligible annotations.
The importer rejects 31 mismatches, 18 unsupported legacy recipes, three mask
length discrepancies, and 22 null RVAs. Of all rows, 362 have a direct use in
the pinned Fallout 4 CKPE patch sources.

The Fallout 4 CK records `CreationKit.pdb` GUID
`DEF076F2-1233-4597-8404-BD4B2DF2A9AA`, age 1. The Fallout 4 game PDB and IDA
maps in `scripts/commonlibf4` describe `Fallout4.exe`, not `CreationKit.exe`;
their RVAs must never be applied directly to the editor. Cross-binary name
transfer is safe only through independently verified, reciprocal-unique byte
signatures with an exact identity sidecar.

## Pinned CKPE checkout

The source is not vendored. Prepare one checkout with the required database
and patch-source directories:

```powershell
git clone --filter=blob:none --no-checkout https://github.com/Perchik71/Creation-Kit-Platform-Extended C:\path\to\ckpe
git -C C:\path\to\ckpe sparse-checkout init --cone
git -C C:\path\to\ckpe sparse-checkout set Database/SSE/1_6_1378_1 CKPE.SkyrimSE/Src/Patches Database/FO4/1_11_137_0 CKPE.Fallout4/Src/Patches
git -C C:\path\to\ckpe checkout cfd8533d7522822242d0b0602fe77d17bc929cea
```

The driver also discovers a checkout at
`third_party/Creation-Kit-Platform-Extended` in this repository or beside the
repository. Otherwise set `BGS_CKPE_ROOT`.

## Run

Run the appropriate entry point against its exact identity-pinned Program.
For Fallout 4 the open target must be
`/Creation Kit/CreationKit Fallout 4 1.11.137.0.exe`. Dry-run is the default:

```python
import os, runpy
os.environ["BGS_CKPE_ROOT"] = r"C:\path\to\ckpe"
runpy.run_path(
    r"C:\Development\Tools\BethesdaGhidraScripts\scripts\creationkit\apply_fallout4_ckpe_evidence.py",
    init_globals={"currentProgram": currentProgram},
)
```

Review the deterministic JSON/CSV report under `refs/generated`, then apply:

```python
os.environ["BGS_CKPE_APPLY"] = "go"
runpy.run_path(
    r"C:\Development\Tools\BethesdaGhidraScripts\scripts\creationkit\apply_fallout4_ckpe_evidence.py",
    init_globals={"currentProgram": currentProgram},
)
```

The shared entry point can select a non-default lock through `BGS_CKPE_LOCK`.
`BGS_CKPE_REPORT_DIR` redirects reports. The apply pass refuses to start while
Ghidra auto-analysis is active and does not save the Program; save explicitly
after reviewing the annotations.

Cross-binary function naming also has separate identity-locked entry points:

- `bytesig_port_skyrim_to_ck.py` uses the analyzed Skyrim runtime sources.
- `bytesig_port_fallout4_to_ck.py` uses the exact ExampleProject paths for analyzed
  Fallout 4 `1.11.221` and `1.10.163` runtimes.

Both wrappers share the reciprocal-unique matcher in
`reciprocal_bytesig_port.py`. Dry-run is the default; `--apply` is required to
save accepted names. Runtime PDB, IDA, and address-library RVAs are never
treated as Creation Kit RVAs.
