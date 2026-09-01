#!/usr/bin/env python3
"""Diagnose why scan_rtti_vtables_from_program returns 0 for Skyrim VR."""
from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))


def main():
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    import jpype

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    with pyghidra.open_project("C:/GhidraProjects", "ExampleProject", create=False) as project:
        vr_df = project.getProjectData().getFile("/Skyrim/SkyrimVR_1_4_15.exe")
        consumer = java.lang.Object()
        program = vr_df.getDomainObject(consumer, False, False, monitor)
        try:
            memory = program.getMemory()
            af = program.getAddressFactory()
            ds = af.getDefaultAddressSpace()
            image_base = program.getImageBase().getOffset()
            print(f"Image base: 0x{image_base:x}")
            print(f"Program: {program.getName()} md5={program.getExecutableMD5()}")
            print("\nMemory blocks:")
            for b in memory.getBlocks():
                ex = "EXEC" if b.isExecute() else ""
                rd = "R" if b.isRead() else "-"
                wr = "W" if b.isWrite() else "-"
                init = "INIT" if b.isInitialized() else "uninit"
                print(f"  {b.getName():15s} 0x{b.getStart().getOffset():x}-0x{b.getEnd().getOffset():x}  {rd}{wr} {ex} {init}")

            # Try to find rdata-like block and count COL signatures
            ByteArray = jpype.JArray(jpype.JByte)
            for b in memory.getBlocks():
                name = b.getName()
                if "rdata" not in name.lower() and "data" not in name.lower():
                    continue
                if b.isExecute():
                    continue
                size = b.getEnd().getOffset() - b.getStart().getOffset() + 1
                print(f"\nScanning {name} (0x{size:x} bytes) for COLs...")
                # Chunked read
                start = b.getStart().getOffset()
                CHUNK = 64 * 1024
                buf_all = bytearray(size)
                n_unread = 0
                for off in range(0, size, CHUNK):
                    n = min(CHUNK, size - off)
                    buf = ByteArray(n)
                    try:
                        memory.getBytes(ds.getAddress(start + off), buf, 0, n)
                        for i in range(n):
                            buf_all[off + i] = buf[i] & 0xff
                    except Exception:
                        n_unread += n
                if n_unread:
                    print(f"  ({n_unread} bytes unreadable, filled zero)")

                # Count sig==1 occurrences
                n_sig1 = 0
                n_pself_match = 0
                samples = []
                for p in range(0, size - 24, 4):
                    sig = struct.unpack_from("<I", buf_all, p)[0]
                    if sig != 1:
                        continue
                    n_sig1 += 1
                    off, cd, ptd, pcd, pself = struct.unpack_from("<IIIII", buf_all, p + 4)
                    col_rva = (b.getStart().getOffset() - image_base) + p
                    if pself == col_rva:
                        n_pself_match += 1
                        if len(samples) < 5:
                            samples.append((col_rva, off, cd, ptd, pcd, pself))
                print(f"  sig==1 candidates:     {n_sig1}")
                print(f"  + pSelf == col_rva:    {n_pself_match}")
                for s in samples:
                    print(f"    COL@RVA 0x{s[0]:x}  off={s[1]} cd={s[2]} ptd=0x{s[3]:x} pcd=0x{s[4]:x} pself=0x{s[5]:x}")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
