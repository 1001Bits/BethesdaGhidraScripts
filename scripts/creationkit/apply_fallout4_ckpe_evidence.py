"""Apply exact Fallout 4 Creation Kit 1.11.137.0 CKPE evidence.

This is a convenience entry point for :mod:`apply_ckpe_evidence`; all target,
source, signature, and annotation-only safety checks remain in that shared
driver.  Dry-run remains the default and the Program is never saved here.
"""

from __future__ import annotations

import os
import sys


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from apply_ckpe_evidence import run as run_shared  # noqa: E402


LOCK_PATH = os.path.join(
    SCRIPT_DIR, "refs", "ckpe_fo4_1_11_137_0.lock.json")


def run(program=None):
    return run_shared(program=program, lock_path=LOCK_PATH)


from pyghidra_result import completion_line, script_program  # noqa: E402

if script_program(globals()) is not None:
    run(script_program(globals()))
    # Positive proof of execution; launchers fail closed without it.
    print(completion_line("apply_fallout4_ckpe_evidence"))
