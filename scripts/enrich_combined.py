#!/usr/bin/env python3
"""Sequencer: enrich every game/version program inside Combined.gpr.

Runs all currently-supported enrichment passes back-to-back so you
only have to close Ghidra once.  Each step is a subprocess.  The default is
fail-fast because later byte-signature write-back steps depend on names
created by earlier applies; use ``--keep-going`` only for independent
research runs.

Default sequence (use --skip to omit, --only to run a subset):

  1. apply_f4_to_user_project    --version ae       # +~7k names from 221 PDB bytesig
  2. apply_f4_to_user_project    --version 221      # +~2.5k names from AE bytesig
  3. apply_skyrim_to_user_project --version se      # 1.7k enums + 38k structs + 7k symbols
  4. apply_skyrim_to_user_project --version ae      # same gains
  5. apply_skyrim_to_user_project --version vr      # same gains; needs shift_svr fix to be in
  6. commonlibsse/bytesig_port_combined --write-back-script
                                                    # SE -> AE/VR bytesig + merge back into scripts
  7. apply_fnv_to_user_project                      # FNV PC 1.4.0.525
  8. apply_sf_to_user_project                       # Starfield 1.16.236
  9. core/run_vtable_pipeline (per binary, slow)    # RTTI walk; optional via --rtti

Defaults assume C:/GhidraProjects/Combined.gpr with the user's typical
multi-binary layout.  Each step prints full output (no quiet mode) so
progress is visible.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_DIR / "scripts"

# (label, script_relative_to_scripts_dir, extra_args)
APPLY_STEPS = [
    ("F4 AE re-apply",
     "apply_f4_to_user_project.py",
     ["--version", "ae",
      "--program-path", "/Fallout4/Fallout4_AE_1_11_191.exe"]),
    ("F4 1.11.221 re-apply",
     "apply_f4_to_user_project.py",
     ["--version", "221",
      "--program-path", "/Fallout4/Fallout4_1_11_221.exe"]),
    ("Skyrim SE apply",
     "apply_skyrim_to_user_project.py",
     ["--version", "se",
      "--program-path", "/Skyrim/SkyrimSE_1_5_97.exe"]),
    ("Skyrim AE apply",
     "apply_skyrim_to_user_project.py",
     ["--version", "ae",
      "--program-path", "/Skyrim/SkyrimAE_1_6_1170.exe"]),
    ("Skyrim VR apply",
     "apply_skyrim_to_user_project.py",
     ["--version", "vr",
      "--program-path", "/Skyrim/SkyrimVR_1_4_15.exe"]),
    ("Skyrim SE -> AE/VR bytesig port + write-back",
     "commonlibsse/bytesig_port_combined.py",
     # --target-paths so the Steam AE binary is picked unambiguously
     # (Combined.gpr also has a GOG Edition AE that matches the broader
     # 'skyrimae' hints).  --no-apply because the in-place renames have
     # already been done by the prior run -- we only want the write-back.
     ["--write-back-script",
      "--no-apply",
      "--target-paths",
      "ae=/Skyrim/SkyrimAE_1_6_1170.exe",
      "vr=/Skyrim/SkyrimVR_1_4_15.exe"]),
    ("F4 221 -> OG/NG/AE/VR bytesig port + write-back",
     "commonlibf4/bytesig_port_combined.py",
     # The earlier exes/-based run_bytesig_port already did 221->AE +
     # AE->221 script merges via run_bytesig_port.py.  This Combined
     # variant covers OG/NG/VR (binaries not on disk for the standalone
     # run) and also lets the 221 PDB pool reach AE in-place.
     ["--write-back-script", "--no-apply"]),
    # A: FNV (PC build only -- Xbox debug build is PowerPC, skip)
    ("FNV apply",
     "apply_fnv_to_user_project.py",
     ["--program-path", "/FalloutNV/FalloutNV_1_4_0_525.exe"]),
    # B: GOG is intentionally omitted.  A relib-re-keyed database proves
    # offsets, not target identity; an exact GOG-bound importer is required.
    # C: Starfield (PC only).
    # DO NOT apply the SF script to StarfieldVR.exe: it embeds PC 1.16.x
    # offsets and a previous run wrote 62k labels at wrong addresses into
    # the VR program (vtbl read_fail=25,687 -- offsets don't exist there).
    # If that pollution is still present, revert the StarfieldVR.exe
    # program to a pre-2026-06-09 version via its Ghidra history.
    ("Starfield apply -> 1.16.236",
     "apply_sf_to_user_project.py",
     ["--program-path", "/Starfield/Starfield 1.16.236"]),
]

# D: RTTI vtable pipeline -- slow, run only when --rtti is given.
RTTI_TARGETS = [
    "/Fallout4/Fallout4_AE_1_11_191.exe",
    "/Fallout4/Fallout4_1_11_221.exe",
    "/Fallout4/Fallout4_NG_1_10_984.exe",
    "/Fallout4/Fallout4_OG_1_10_163.exe",
    "/Fallout4/Fallout4VR_1_2_72.exe",
    "/Skyrim/SkyrimSE_1_5_97.exe",
    "/Skyrim/SkyrimAE_1_6_1170.exe",
    "/Skyrim/SkyrimAE_GOG Edition.exe",
    "/Skyrim/SkyrimVR_1_4_15.exe",
    "/FalloutNV/FalloutNV_1_4_0_525.exe",
    "/Starfield/Starfield 1.16.236",
    "/Starfield/StarfieldVR.exe",
]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', default="Combined")
    ap.add_argument('--skip', nargs='+', default=[], metavar='STEP',
                    help="Skip apply-step(s) by 1-based index (e.g. --skip 1 2)")
    ap.add_argument('--only', nargs='+', default=None, metavar='STEP',
                    help="Run ONLY apply-step(s) by 1-based index")
    ap.add_argument('--rtti', action='store_true',
                    help="ALSO run RTTI vtable pipeline on each binary "
                         "(adds ~30 min per binary -- expect 3-5 hours)")
    ap.add_argument('--keep-going', action='store_true',
                    help="continue independent research after a failure; "
                         "unsafe dependent write-back steps may still fail")
    args = ap.parse_args()
    skip = {int(s) for s in args.skip if s.isdigit()}
    only = {int(s) for s in args.only} if args.only else None

    common = ['--project-dir', args.project_dir,
              '--project-name', args.project_name]

    overall_start = time.time()
    results = []
    for i, (label, script, extra) in enumerate(APPLY_STEPS, 1):
        if only is not None and i not in only:
            continue
        if i in skip:
            print(f"\n{'=' * 70}\nSTEP {i} SKIPPED: {label}\n{'=' * 70}")
            results.append((label, 'skipped', 0))
            continue
        script_path = SCRIPTS_DIR / script
        cmd = [sys.executable, str(script_path), *common, *extra]
        print(f"\n{'=' * 70}\nSTEP {i}/{len(APPLY_STEPS)}: {label}\n"
              f"  cmd: {' '.join(repr(c) if ' ' in c else c for c in cmd)}\n"
              f"{'=' * 70}")
        step_start = time.time()
        rc = subprocess.run(cmd).returncode
        elapsed = time.time() - step_start
        status = 'OK' if rc == 0 else f'FAIL (rc={rc})'
        results.append((label, status, elapsed))
        print(f"\n--- STEP {i} {status} ({elapsed:.0f}s) ---")
        if rc != 0 and not args.keep_going:
            print("Stopping: later write-back steps depend on successful "
                  "upstream enrichment. Use --keep-going only when those "
                  "dependencies are intentionally out of scope.")
            break

    failed_apply = any(status.startswith('FAIL')
                       for _, status, _ in results)
    if args.rtti and (args.keep_going or not failed_apply):
        rtti_script = SCRIPTS_DIR / "core" / "run_vtable_pipeline.py"
        for prog_path in RTTI_TARGETS:
            label = f"RTTI walk -> {prog_path}"
            cmd = [sys.executable, str(rtti_script),
                   args.project_dir, args.project_name, prog_path]
            print(f"\n{'=' * 70}\n{label}\n  cmd: "
                  f"{' '.join(repr(c) if ' ' in c else c for c in cmd)}\n"
                  f"{'=' * 70}")
            step_start = time.time()
            rc = subprocess.run(cmd).returncode
            elapsed = time.time() - step_start
            status = 'OK' if rc == 0 else f'FAIL (rc={rc})'
            results.append((label, status, elapsed))
            print(f"\n--- {label} {status} ({elapsed:.0f}s) ---")

    total = time.time() - overall_start
    print(f"\n{'=' * 70}\nSUMMARY ({total:.0f}s total)\n{'=' * 70}")
    for i, (label, status, elapsed) in enumerate(results, 1):
        print(f"  {i:>2}. {status:<14}  {elapsed:>6.0f}s  {label}")
    failures = [label for label, status, _ in results
                if status.startswith('FAIL')]
    if failures:
        print(f"\nFAILED: {len(failures)} required enrichment step(s).")
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
