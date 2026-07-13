#!/usr/bin/env python3
"""Build a Skyrim VR vtable shift map by comparing Skyrim AE (reference)
and Skyrim VR (target) vtables in Combined.gpr.

Output: scripts/commonlibsse/refs/shift_svr.json

Pipeline:
  1. Open Combined.gpr.
  2. For Skyrim AE and Skyrim VR programs, RTTI-scan each binary to find
     every vtable + its class name (the MSVC CompleteObjectLocator chain
     is the same trick we used for Starfield).  This is binary-driven so
     it covers EVERY class in the engine, not just the ones CommonLibSSE
     headers document.
  3. For each vtable, walk consecutive 8-byte slots until termination
     (zero, non-.text, or next-known-vtable).  Record
     (class_name, slot_index, function_name_at_slot).
  4. Cross-version match per class: for each AE slot whose function has
     a non-FUN_ name, look up the same function name in the VR class's
     slots.  If it lives at a different slot index, record the shift.
  5. Aggregate to a vtable_matcher-compatible JSON file:
        {
          "reference": "ae",
          "target":    "svr",
          "classes": {
            "<ClassName>": {
              "ref_to_target": { "0x<ae_slot>": "0x<vr_slot>", ... },
              "unmatched_ref_slots": [...],
              "target_only_slots": [...],
              "notes": [...]
            },
            ...
          }
        }

Run from the repo root:
  python scripts/commonlibsse/build_svr_shift_map.py
"""
from __future__ import annotations

import csv
import json
import os
import struct
import sys
from collections import defaultdict
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = REPO_DIR / "tools" / "ghidra"

PROJECT_DIR  = "C:/GhidraProjects"
PROJECT_NAME = "Combined"
AE_PATH      = "/Skyrim/SkyrimAE_1_6_1170.exe"
VR_PATH      = "/Skyrim/SkyrimVR_1_4_15.exe"

OUT_SHIFT    = REPO_DIR / "scripts" / "commonlibsse" / "refs" / "shift_svr.json"
OUT_DUMP_AE  = REPO_DIR / "scripts" / "commonlibsse" / "refs" / "skyrim_ae_vtables.json"
OUT_DUMP_VR  = REPO_DIR / "scripts" / "commonlibsse" / "refs" / "skyrim_vr_vtables.json"

DEFAULT_MAX_SLOTS = 1000

NOISE_PREFIXES = ("FUN_", "thunk_FUN_", "sub_")

# In Combined.gpr's Skyrim VR program, many named functions have a
# trailing _<address> suffix appended (e.g., "Actor::Move_14062F480").
# Strip those before comparing to AE.
import re
_VA_SUFFIX_RE = re.compile(r"_(0x)?1[0-9a-fA-F]{8}$")
_FUNC_SLOT_RE = re.compile(r"^Func[0-9]+_[0-9a-fA-F]+$")
_VF_SUB_RE    = re.compile(r"^.+_vf_sub_[0-9a-fA-F]+$")
_NULLSUB_RE   = re.compile(r"^nullsub_[0-9]+$")


def is_named(leaf):
    if not leaf or any(leaf.startswith(p) for p in NOISE_PREFIXES):
        return False
    if _FUNC_SLOT_RE.match(leaf):    # Class::FuncN_VA placeholder
        return False
    if _VF_SUB_RE.match(leaf):       # Class_vf_sub_VA placeholder
        return False
    if _NULLSUB_RE.match(leaf):      # Ghidra synthetic empty function
        return False
    return True


def normalize_name(full_name):
    """Strip Ghidra address suffixes so VR's 'Actor::Move_140XXXX' matches
    AE's 'Actor::Move'."""
    if not full_name:
        return None
    parts = full_name.split("::")
    parts[-1] = _VA_SUFFIX_RE.sub("", parts[-1])
    return "::".join(parts)


def demangle_class(mangled):
    """Minimal MSVC class TypeDescriptor demangler -- same logic as
    scripts/commonlibsf/find_all_vtables_rtti.py."""
    if mangled.startswith((".?AV", ".?AU", ".?AW")):
        rest = mangled[4:]
    else:
        return mangled
    if rest.endswith("@@"):
        rest = rest[:-2]
    parts = [p for p in rest.split("@") if p]
    if not parts:
        return "UnknownClass"
    if any("?$" in p for p in parts):
        return rest.replace("@", "::").replace("?$", "T_").replace("?", "_")
    return "::".join(reversed(parts))


def rva_to_file(sects, rva):
    for s in sects:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
            return s["rptr"] + (rva - s["vaddr"])
    return None


def parse_pe(path):
    data = path.read_bytes()
    assert data[:2] == b"MZ"
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    coff = pe + 4
    opt_sz = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    sects_off = opt + opt_sz
    n_sec = struct.unpack_from("<H", data, coff + 2)[0]
    sects = []
    for i in range(n_sec):
        so = sects_off + i * 40
        name = data[so:so+8].rstrip(b"\x00").decode("latin-1")
        sects.append({
            "name": name,
            "vaddr": struct.unpack_from("<I", data, so + 12)[0],
            "vsize": struct.unpack_from("<I", data, so + 8)[0],
            "rsize": struct.unpack_from("<I", data, so + 16)[0],
            "rptr":  struct.unpack_from("<I", data, so + 20)[0],
        })
    return image_base, sects, data


def find_section(sects, name):
    for s in sects:
        if s["name"] == name:
            return s
    return None


def scan_rtti_vtables_from_program(program):
    """Return {vtable_va: class_name} for every RTTI-discovered vtable.

    Reads memory directly from the Ghidra Program -- no on-disk .exe
    required.  Slower than parsing the PE file but works for any
    binary that's been imported, regardless of where the original .exe
    lives.
    """
    import jpype
    memory = program.getMemory()
    addr_factory = program.getAddressFactory()
    default_space = addr_factory.getDefaultAddressSpace()

    image_base = program.getImageBase().getOffset()

    # Build a section table from Ghidra memory blocks.  Some unpacked
    # binaries split a single PE section into multiple Ghidra blocks
    # (one initialized + one uninitialized tail), so we treat every
    # initialized, non-executable block as a possible RTTI source.
    sects = []
    scan_blocks = []
    for block in memory.getBlocks():
        name = block.getName()
        start = block.getStart().getOffset()
        end   = block.getEnd().getOffset()
        size  = end - start + 1
        sect = {"name": name, "vaddr": start - image_base, "vsize": size,
                "rsize": size, "block": block, "start_va": start, "end_va": end}
        sects.append(sect)
        if (block.isInitialized() and block.isRead() and not block.isExecute()
                and size > 0x1000):
            scan_blocks.append(sect)

    if not scan_blocks:
        return {}

    # Read every candidate read-only block into one logical buffer keyed
    # by RVA, then collect COLs from all of them.
    ByteArray = jpype.JArray(jpype.JByte)
    CHUNK = 64 * 1024
    block_bytes = {}  # block_index -> bytes
    for sect in scan_blocks:
        size = sect["vsize"]
        start_va = sect["start_va"]
        buf_all = bytearray(size)
        n_unread = 0
        for off in range(0, size, CHUNK):
            n = min(CHUNK, size - off)
            buf = ByteArray(n)
            try:
                memory.getBytes(default_space.getAddress(start_va + off), buf, 0, n)
                for i in range(n):
                    buf_all[off + i] = buf[i] & 0xff
            except Exception:
                n_unread += n
        if n_unread > 0 and n_unread < size:
            print(f"  NOTE: {n_unread:,} bytes of {sect['name']} unreadable; zeros")
        block_bytes[id(sect)] = bytes(buf_all)

    image_rva_max = max(s["vaddr"] + s["vsize"] for s in sects)

    def read_any_rva(rva, n):
        """Read n bytes at image-relative RVA; pulls from our in-memory
        block_bytes if possible, falls back to Ghidra memory."""
        for s in scan_blocks:
            if s["vaddr"] <= rva < s["vaddr"] + s["vsize"]:
                local = rva - s["vaddr"]
                buf = block_bytes[id(s)]
                if local + n <= len(buf):
                    return buf[local:local + n]
        # Fallback: ghidra memory for non-cached blocks (e.g., .data tail)
        target_va = image_base + rva
        for s in sects:
            if s["vaddr"] <= rva < s["vaddr"] + s["vsize"]:
                tmp = ByteArray(n)
                try:
                    memory.getBytes(default_space.getAddress(target_va), tmp, 0, n)
                    return bytes((b & 0xff) for b in tmp)
                except Exception:
                    return None
        return None

    # Pass 1: scan every candidate block for COLs (sig==1 + pSelf == col_rva)
    cols = {}
    for sect in scan_blocks:
        bytes_buf = block_bytes[id(sect)]
        sect_rva = sect["vaddr"]
        for p in range(0, len(bytes_buf) - 24, 4):
            sig = struct.unpack_from("<I", bytes_buf, p)[0]
            if sig != 1:
                continue
            off, cd, ptd, pcd, pself = struct.unpack_from("<IIIII", bytes_buf, p + 4)
            col_rva = sect_rva + p
            if pself != col_rva:
                continue
            if ptd >= image_rva_max or pcd >= image_rva_max:
                continue
            cols[col_rva] = ptd

    # Pass 2: demangle TypeDescriptor names
    name_by_col = {}
    for col_rva, ptd in cols.items():
        # Read 0x20 bytes from the TypeDescriptor (covers vftable + optional spare + name start)
        head = read_any_rva(ptd, 0x20)
        if head is None:
            continue
        prefix_pos = None
        for off2 in (0x08, 0x10):
            if head[off2:off2 + 3] == b".?A":
                prefix_pos = off2
                break
        if prefix_pos is None:
            continue
        # Read up to 256 bytes starting at the name; null-terminate manually.
        name_rva = ptd + prefix_pos
        name_buf = read_any_rva(name_rva, 256)
        if name_buf is None:
            continue
        end = name_buf.find(b"\x00")
        if end == -1:
            continue
        mangled = name_buf[:end].decode("latin-1", errors="replace")
        if not mangled.startswith(".?A"):
            continue
        name_by_col[col_rva] = demangle_class(mangled)

    # Pass 3: scan every candidate block for q where *q points to a known COL
    vtables = {}
    for sect in scan_blocks:
        bytes_buf = block_bytes[id(sect)]
        sect_rva = sect["vaddr"]
        for p in range(0, len(bytes_buf) - 8, 8):
            ptr64 = struct.unpack_from("<Q", bytes_buf, p)[0]
            if ptr64 == 0:
                continue
            col_rva = ptr64 - image_base
            if col_rva not in name_by_col:
                continue
            vt_va = image_base + sect_rva + p + 8
            if vt_va not in vtables:
                vtables[vt_va] = name_by_col[col_rva]
    return vtables


def dump_program_vtables(program):
    """Walk every RTTI vtable in the program's memory, read slot pointers,
    look up function names from the Ghidra program.

    Returns {class_name: {slot_index: function_name_or_None}}.
    """
    vtables = scan_rtti_vtables_from_program(program)
    print(f"  RTTI found {len(vtables)} vtables in {program.getName()}")

    memory = program.getMemory()
    addr_factory = program.getAddressFactory()
    default_space = addr_factory.getDefaultAddressSpace()
    fm = program.getFunctionManager()

    # Determine .text bounds
    text_start = text_end = None
    for block in memory.getBlocks():
        if block.getName() == ".text" or block.isExecute():
            if text_start is None or block.getStart().getOffset() < text_start:
                text_start = block.getStart().getOffset()
            if text_end is None or block.getEnd().getOffset() > text_end:
                text_end = block.getEnd().getOffset()

    vtable_va_set = set(vtables.keys())
    out = defaultdict(dict)
    for vt_va, cls in vtables.items():
        for slot_idx in range(DEFAULT_MAX_SLOTS):
            slot_va = vt_va + slot_idx * 8
            try:
                ptr_val = memory.getLong(default_space.getAddress(slot_va)) & 0xFFFFFFFFFFFFFFFF
            except Exception:
                break
            if ptr_val == 0:
                break
            if not (text_start <= ptr_val < text_end):
                break
            next_va = vt_va + (slot_idx + 1) * 8
            terminate = slot_idx > 0 and next_va in vtable_va_set

            func = fm.getFunctionContaining(default_space.getAddress(ptr_val))
            fn_name = func.getName(True) if func else None
            out[cls][slot_idx] = fn_name
            if terminate:
                break
    return dict(out)


def build_shift_map(ae_dump, vr_dump):
    """Return a vtable_matcher-style shift map.

    Match strategy per class:
      1. Build (normalized_name -> [slots]) dicts for both versions.
      2. For each named AE slot, look up the same normalized name in VR
         and pick the closest slot by distance.
      3. Anything in AE not found in VR -> unmatched_ref_slots.
      4. Anything in VR not consumed by a match -> target_only_slots
         (those are the candidate "VR inserted a new vfunc here" cases).
    """
    classes = {}
    for cls, ae_slots in ae_dump.items():
        if cls not in vr_dump:
            continue
        vr_slots = vr_dump[cls]
        # Normalized name -> [(slot, original_name)]
        vr_name_to_slot = {}
        for s, n in vr_slots.items():
            if n is None:
                continue
            leaf = n.split("::")[-1]
            if not is_named(leaf):
                continue
            key = normalize_name(n)
            vr_name_to_slot.setdefault(key, []).append(s)

        ref_to_target = {}
        unmatched = []
        used_vr_slots = set()
        for s_ae, n_ae in sorted(ae_slots.items()):
            if n_ae is None:
                continue
            leaf = n_ae.split("::")[-1]
            if not is_named(leaf):
                continue
            cands = vr_name_to_slot.get(normalize_name(n_ae))
            if not cands:
                unmatched.append(s_ae)
                continue
            # Pick the closest unused candidate
            free = [c for c in cands if c not in used_vr_slots]
            if not free:
                unmatched.append(s_ae)
                continue
            s_vr = min(free, key=lambda x: abs(x - s_ae))
            ref_to_target[s_ae] = s_vr
            used_vr_slots.add(s_vr)

        # target_only: VR-named slots not consumed by an AE match,
        # and not corresponding to any AE-named slot at the same index.
        ae_named_slots = {s for s, n in ae_slots.items()
                          if n is not None and is_named(n.split("::")[-1])}
        target_only = []
        for s_vr, n_vr in sorted(vr_slots.items()):
            if n_vr is None:
                continue
            leaf = n_vr.split("::")[-1]
            if not is_named(leaf):
                continue
            if s_vr in used_vr_slots:
                continue
            if s_vr in ae_named_slots:
                continue
            target_only.append((s_vr, n_vr))

        if not ref_to_target and not target_only and not unmatched:
            continue
        classes[cls] = {
            "ref_to_target": {hex(k): hex(v) for k, v in sorted(ref_to_target.items())},
            "unmatched_ref_slots": [hex(s) for s in sorted(unmatched)],
            "target_only_slots": [
                {"slot": hex(s), "func_name": n, "func_addr": "0x0"}
                for s, n in target_only
            ],
            "notes": [],
        }
    return {"reference": "ae", "target": "svr", "classes": classes}


def main():
    raise SystemExit(
        'DISABLED: this legacy builder emits an identity-unbound, '
        'coverage-insufficient Skyrim VR shift map. Use the exact '
        'binary-layout pipeline before enabling VR vtable overlays.')
    OUT_SHIFT.parent.mkdir(parents=True, exist_ok=True)

    # Cache hit: if both vtable dumps already exist, skip the (slow)
    # Ghidra phase and re-run only the offline matcher.  Pass --redump
    # to force the Ghidra phase.
    have_cache = OUT_DUMP_AE.is_file() and OUT_DUMP_VR.is_file()
    if have_cache and "--redump" not in sys.argv:
        print(f"Using cached dumps from {OUT_DUMP_AE.parent}")
        with open(OUT_DUMP_AE, encoding="utf-8") as f:
            raw = json.load(f)
            ae_dump = {k: {int(s): n for s, n in v.items()} for k, v in raw.items()}
        with open(OUT_DUMP_VR, encoding="utf-8") as f:
            raw = json.load(f)
            vr_dump = {k: {int(s): n for s, n in v.items()} for k, v in raw.items()}
        _emit_shift(ae_dump, vr_dump)
        return

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    print("Opening Combined.gpr ...")
    with pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=False) as project:
        ae_df = project.getProjectData().getFile(AE_PATH)
        vr_df = project.getProjectData().getFile(VR_PATH)
        if ae_df is None or vr_df is None:
            print(f"  ERROR: missing programs (ae={ae_df}, vr={vr_df})")
            sys.exit(2)

        consumer = java.lang.Object()
        ae_prog = ae_df.getDomainObject(consumer, False, False, monitor)
        try:
            print("\n--- Dumping Skyrim AE vtables ---")
            ae_dump = dump_program_vtables(ae_prog)
            print(f"  classes with named slots: {sum(1 for v in ae_dump.values() if any(n for n in v.values()))}")
        finally:
            ae_prog.release(consumer)

        vr_prog = vr_df.getDomainObject(consumer, False, False, monitor)
        try:
            print("\n--- Dumping Skyrim VR vtables ---")
            vr_dump = dump_program_vtables(vr_prog)
            print(f"  classes with named slots: {sum(1 for v in vr_dump.values() if any(n for n in v.values()))}")
        finally:
            vr_prog.release(consumer)

    # Persist intermediate dumps for debugging / re-runs
    with open(OUT_DUMP_AE, "w", encoding="utf-8") as f:
        json.dump({k: {str(s): n for s, n in v.items()} for k, v in ae_dump.items()},
                  f, indent=2)
    with open(OUT_DUMP_VR, "w", encoding="utf-8") as f:
        json.dump({k: {str(s): n for s, n in v.items()} for k, v in vr_dump.items()},
                  f, indent=2)

    _emit_shift(ae_dump, vr_dump)


def _emit_shift(ae_dump, vr_dump):
    print("\n--- Building shift map ---")
    shift = build_shift_map(ae_dump, vr_dump)

    with open(OUT_SHIFT, "w", encoding="utf-8") as f:
        json.dump(shift, f, indent=2)

    total_classes = len(shift["classes"])
    n_shifted = sum(
        1 for cls, m in shift["classes"].items()
        if any(int(k, 16) != int(v, 16) for k, v in m["ref_to_target"].items())
    )
    n_matched = sum(len(m["ref_to_target"]) for m in shift["classes"].values())
    n_unmatched = sum(len(m["unmatched_ref_slots"]) for m in shift["classes"].values())
    n_target_only = sum(len(m["target_only_slots"]) for m in shift["classes"].values())
    print(f"Classes in shift map:        {total_classes}")
    print(f"  with non-zero shift:       {n_shifted}")
    print(f"  total slot matches:        {n_matched}")
    print(f"  AE-only (unmatched):       {n_unmatched}")
    print(f"  VR-only (target_only):     {n_target_only}")
    print(f"Wrote {OUT_SHIFT}")


# ---------- helpers for on-disk exe lookup ----------
EXPECTED_DISK_LOCATIONS = [
    REPO_DIR / "exes" / "skyrim" / "ae" / "SkyrimSE.exe",
    REPO_DIR / "exes" / "skyrim" / "vr" / "SkyrimVR.exe",
    Path(r"C:/Games/Skyrim Special Edition/SkyrimSE.exe"),
    Path(r"C:/Games/SkyrimVR/SkyrimVR.exe"),
]


def find_on_disk_exe(name):
    """Best-effort: locate the .exe matching this Ghidra program's name."""
    nm = name.lower()
    candidates = list(EXPECTED_DISK_LOCATIONS)
    # Add any *.exe inside REPO_DIR/exes/ whose name matches
    exes_root = REPO_DIR / "exes"
    if exes_root.is_dir():
        for p in exes_root.rglob("*.exe"):
            if "unpacked" in p.name.lower():
                continue
            candidates.append(p)
    # Pick by name match
    for c in candidates:
        if c.is_file() and (c.name.lower() == nm or c.name.lower().startswith(nm.split(".")[0].lower())):
            return c
    return None


if __name__ == "__main__":
    main()
