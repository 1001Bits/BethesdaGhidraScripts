#!/usr/bin/env python3
r"""Port names AND prototypes from the PDB-typed Fallout 4 1.10.155 program.

``/Fallout4/Fallout4_1_10_155.exe`` in Combined carries the ground truth of
its full compiler PDB (1.3M type records, ~350k code publics).  This wrapper
of the reciprocal-unique byte-signature matcher
(``creationkit/reciprocal_bytesig_port.py``) carries those names to every other
Fallout 4 build, and to the Skyrim / Starfield programs for the engine code
they share (Ni*/BS*/Havok/Scaleform/CRT), with the same guarantees as the
Creation Kit port: exact source and target SHA-256 pins, a signature unique in
both images, one-to-one name/address ownership, no existing non-default
target name replaced.  With ``copy_prototypes`` the source function's
prototype (and the PDB data types it references) is applied where the target
prototype is not USER_DEFINED/IMPORTED and no referenced type collides with a
different target type of the same path.  Prototypes are copied by default only
to Fallout 4 targets: Skyrim and Starfield share engine code but not the
Fallout 4 PDB's struct layouts (``--prototypes`` opts in explicitly).

Usage (Ghidra GUI closed)::

    python scripts/commonlibf4/bytesig_port_pdb_to_targets.py --target og [--apply]
    python scripts/commonlibf4/bytesig_port_pdb_to_targets.py --target se [--prototypes]
    python scripts/commonlibf4/bytesig_port_pdb_to_targets.py --list
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CK_DIR = SCRIPT_DIR.parent / "creationkit"
if str(CK_DIR) not in sys.path:
    sys.path.insert(0, str(CK_DIR))
import reciprocal_bytesig_port as shared  # noqa: E402

SOURCE_PATH = "/Fallout4/Fallout4_1_10_155.exe"   # sha pinned at run time from the staged exe
EVIDENCE_DIR = SCRIPT_DIR.parents[1] / "build" / "evidence"

# Names whose slot number / address is build-specific are never ported.
EXCLUDED_NAME_RE = r"(?:^|::)(?:Func\d+(?:_v\d+)?|Unk_[0-9A-Fa-f]+|FUN_[0-9A-Fa-f]+)$"

# target key -> (project path, exact executable sha256, display, evidence stem)
TARGETS = {
    "og":  ("/Fallout4/Fallout4_OG_1_10_163.exe",
            "5b2a58004f1856e51235132ab304b20c1434017067703e4282e8b0d5bc539623",
            "Fallout 4 1.10.163"),
    "ng":  ("/Fallout4/Fallout4_NG_1_10_984.exe",
            "6c54e6152b69cc976c3f2aa7bae2b99b86c056c596cbabce09ab8d60974bb537",
            "Fallout 4 1.10.984"),
    "ae":  ("/Fallout4/Fallout4_AE_1_11_191.exe",
            "81694b37816c8045855905a52c5fb13583c5803121fabb5024760892014e9bc6",
            "Fallout 4 1.11.191"),
    "221": ("/Fallout4/Fallout4_1_11_221.exe",
            "488015e2010308bfa164d3720cb618deea7e1c098b1d61af530d258a6f17d27b",
            "Fallout 4 1.11.221"),
    "240": ("/Fallout4/Fallout4_1_11_240.exe",
            "fdcef37ac1230af6d0b0050eb2142b139ef3a867b37b9211fb6edfcc646072f8",
            "Fallout 4 1.11.240"),
    "vr":  ("/Fallout4/Fallout4VR_1_2_72.exe",
            "875a9a3fb50a0c41d8bb20848977106498df1ffa8b4f7d5feda01f6f346c307a",
            "Fallout 4 VR 1.2.72"),
    "se":  ("/Skyrim/SkyrimSE_1_5_97.exe",
            "5666e1bddd01bcab31ecf11691ef1a3f22e1541af79f2bc0e55318533cfe5d12",
            "Skyrim SE 1.5.97"),
    "ae1170": ("/Skyrim/SkyrimAE_1_6_1170.exe",
               "80c1ea737d33c6bfac09b101b8d77ab0f9f6630128c3ed052f9d945bed54e7e4",
               "Skyrim AE 1.6.1170"),
    "16640": ("/Skyrim/SkyrimAE_1_6_640.exe",
              "d3c4f588b942e73a54240497886e35f094a3641ed2a7173332100eaf1c90ea60",
              "Skyrim AE 1.6.640"),
    "17104": ("/Skyrim/SkyrimAE_1_7_104.exe",
              "846efccf0c1374d71f892907f46549560f2fcb0a75cb87a3eed438baa0f1402f",
              "Skyrim AE 1.7.104"),
    "svr": ("/Skyrim/SkyrimVR_1_4_15.exe",
            "8d839e3de9aaf59d4bac94887611d6ac7199c3b601e9e8ff8d567648fc452c9f",
            "Skyrim VR 1.4.15"),
    "sf":  ("/Starfield/Starfield 1.16.236",
            "1d1409ca898ca596a3a605f3ebc5347f72cfd6e47e38020dec158ec9bdd7d351",
            "Starfield 1.16.236"),
}


def _source_sha():
    """The 1.10.155 retail exe staged next to its PDB, hashed at run time."""
    import hashlib
    exe = SCRIPT_DIR.parents[1] / "FO4 PDB" / "Fallout4.exe"
    if not exe.is_file():
        raise SystemExit("FO4 PDB/Fallout4.exe is not present; the source pin "
                         "cannot be established")
    digest = hashlib.sha256()
    with exe.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prototypes_by_default(target: str) -> bool:
    """Only a Fallout 4 build shares the 1.10.155 PDB's data-type layouts."""
    return TARGETS[target][0].startswith("/Fallout4/")


def config_for(target: str, source_sha256: str, copy_prototypes: bool | None = None):
    path, sha, display = TARGETS[target]
    if copy_prototypes is None:
        copy_prototypes = prototypes_by_default(target)
    return shared.PortConfig(
        target_sha256=sha,
        target_product_version=display,
        default_sources=(("Fallout4-1.10.155-PDB", SOURCE_PATH),),
        default_evidence=EVIDENCE_DIR / "pdb_port_155_to_{}.csv".format(target),
        target_display_name=display,
        default_target_path=path,
        transaction_name="Fallout 4 1.10.155 PDB reciprocal byte-signature names",
        save_description="Fallout 4 1.10.155 PDB reciprocal byte-signature names",
        source_help="the PDB-typed 1.10.155 program (identity-pinned)",
        allowed_source_sha256=((SOURCE_PATH, source_sha256),),
        excluded_name_re=EXCLUDED_NAME_RE,
        copy_prototypes=copy_prototypes,
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", choices=sorted(TARGETS))
    ap.add_argument("--list", action="store_true")
    prototypes = ap.add_mutually_exclusive_group()
    prototypes.add_argument("--no-prototypes", action="store_true",
                            help="port names only")
    prototypes.add_argument("--prototypes", action="store_true",
                            help="also copy prototypes to a non-Fallout-4 "
                                 "target (default: Fallout 4 targets only)")
    ap.add_argument("--project-dir", default="C:/GhidraProjects")
    ap.add_argument("--project-name", default="Combined")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)
    if args.list or not args.target:
        for key, (path, sha, display) in TARGETS.items():
            print("{:<7} {:<40} {}  {}".format(key, path, sha[:12], display))
        return 0
    copy = (True if args.prototypes else False if args.no_prototypes
            else None)
    config = config_for(args.target, _source_sha(), copy)
    forwarded = ["--project-dir", args.project_dir, "--project-name", args.project_name]
    if args.apply:
        forwarded.append("--apply")
    return shared.main(forwarded, config=config)


if __name__ == "__main__":
    raise SystemExit(main())
