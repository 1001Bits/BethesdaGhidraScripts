#!/usr/bin/env python3
"""Generic RTTI-driven vtable naming pipeline.

Works on any MSVC x64 PE binary that's already been imported into a
Ghidra project.  Three phases:

  1. RTTI scan: walk the binary's memory blocks for CompleteObjectLocator
     structs (sig==1 + pSelf self-reference), demangle each
     TypeDescriptor, and emit (vtable_va, class_name) pairs for every
     class in the binary.
  2. Slot expansion: walk each vtable's 8-byte function pointer slots
     and emit (target_va, Class::Func<N>) labels.  Termination on zero,
     non-.text pointer, or hitting the next known vtable.
  3. Apply: for each (target_va, name), create a function at that
     address (if Ghidra doesn't already have one) and rename if the
     current name is FUN_*/thunk_*/sub_*.

Usage:
  python run_vtable_pipeline.py <project_dir> <project_name> <program_path>
      [--target-pe <exact-local-pe>] [--target-manifest <identity.json>]
      [--dry-run]

Example:
  python run_vtable_pipeline.py C:/GhidraProjects Combined /Fallout4/Fallout4VR_1_2_72.exe

The scan is binary-derived and requires no CommonLib headers.  Every mutation
is still tied to the loaded Program's exact backing PE identity.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path
from ghidra_project import open_user_project

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = REPO_DIR / "tools" / "ghidra"

DEFAULT_MAX_SLOTS = 65536  # corruption guard; real bound is containing block

_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_<>$~?@-]")


def resolve_backing_manifest(program, backing_manifest=None,
                             target_pe_paths=(), target_manifest_paths=()):
    """Return an exact manifest after attesting the live Ghidra Program.

    Ghidra records the original import path, which is often a short-lived
    Steamless output.  If that path has vanished, an explicitly supplied PE
    or manifest provides the expected SHA/anchors/sections; the Program's
    loader-recorded SHA and live memory must still independently match it.

    When the recorded path still exists it is always included and remains
    authoritative inside :func:`verify_ghidra_program`.  Consequently an
    explicit old target cannot conceal a file that was replaced in place.
    """
    from binary_identity import (PEIdentityError, _program_executable_path,
                                 inspect_pe, read_manifest,
                                 verify_ghidra_program)

    manifests = []
    if backing_manifest is not None:
        manifests.append(backing_manifest)
    for target_path in target_pe_paths or ():
        manifests.append(inspect_pe(str(target_path)))
    for manifest_path in target_manifest_paths or ():
        manifests.append(read_manifest(str(manifest_path)))

    recorded_path = _program_executable_path(program)
    if recorded_path and os.path.isfile(recorded_path):
        manifests.append(inspect_pe(recorded_path))
    elif recorded_path and os.path.lexists(recorded_path):
        # Let the central verifier produce the precise non-regular-file error.
        return verify_ghidra_program(program, manifests)

    if not manifests:
        raise PEIdentityError(
            "backing executable is missing; pass --target-pe or "
            "--target-manifest for the exact imported binary")
    return verify_ghidra_program(program, manifests)


def sanitize_component(part):
    part = part.strip()
    if not part:
        return "_"
    cleaned = _SAFE_COMPONENT_RE.sub("_", part)
    if cleaned and cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned or "_"


def split_namespaced(full):
    return [sanitize_component(p) for p in full.split("::")]


def _manifest_section_for_va(manifest, va, size=1, *, file_backed=True):
    """Return the exact PE section owning a default-space VA span."""
    base = int(manifest["image_base"])
    image_end = base + int(manifest["image_size"])
    if size <= 0 or va < base or va + size > image_end:
        return None
    rva = va - base
    for section in manifest.get("sections", []):
        start = int(section.get("rva", 0))
        span = (int(section.get("raw_size", 0)) if file_backed else
                max(int(section.get("raw_size", 0)),
                    int(section.get("virtual_size", 0))))
        if span > 0 and start <= rva and rva + size <= start + span:
            return section
    return None


def _block_manifest_intersections(start, end, is_default_space, manifest):
    """Clip one inclusive Program block to exact file-backed PE sections."""
    if not is_default_space or end < start:
        return []
    base = int(manifest["image_base"])
    image_end = base + int(manifest["image_size"]) - 1
    result = []
    for section in manifest.get("sections", []):
        raw_size = int(section.get("raw_size", 0))
        if raw_size <= 0:
            continue
        sec_start = base + int(section.get("rva", 0))
        sec_end = min(image_end, sec_start + raw_size - 1)
        clip_start, clip_end = max(start, sec_start), min(end, sec_end)
        if clip_start <= clip_end:
            result.append((clip_start, clip_end, section))
    return result


def _rtti_section_roles(block, pe_section):
    """Return (metadata-readable, COL-scannable) for a clipped PE section.

    CompleteObjectLocators and their pointer cells are scanned only in
    read-only metadata.  Referenced TypeDescriptors normally live in writable
    ``.data`` on MSVC x64, so they must remain available to targeted reads even
    though they are never treated as COL scan candidates.
    """
    metadata_readable = (
        block.isInitialized() and block.isRead() and not block.isExecute() and
        pe_section.get("readable") and not pe_section.get("executable"))
    col_scannable = (
        metadata_readable and not block.isWrite() and
        not pe_section.get("writable"))
    return bool(metadata_readable), bool(col_scannable)


def _bounded_metadata_read_size(sections, rva, requested):
    """Clip a targeted metadata read to its owning file-backed section."""
    if requested <= 0:
        return 0
    for section in sections:
        start = int(section["vaddr"])
        end = start + int(section["vsize"])
        if start <= rva < end:
            return min(int(requested), end - rva)
    return 0


def _validate_rtti_machine(manifest, pointer_size):
    expected = 0x8664 if int(pointer_size) == 8 else 0x014C
    if int(manifest.get("machine", 0)) != expected:
        raise ValueError(
            "RTTI scanner supports only MSVC i386/AMD64 PE images")


def demangle_class(mangled):
    """Minimal MSVC class TypeDescriptor demangler."""
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


# ---------------------------------------------------------------------------
#  Phase 1+2: RTTI scan + vtable slot expansion (operate on Ghidra memory)
# ---------------------------------------------------------------------------

def scan_msvc_rtti(program, backing_manifest=None):
    """Recover MSVC RTTI vtables, COL subobjects, and class hierarchies.

    Reads bytes directly from the Ghidra Program memory; works for any
    MSVC PE binary (x86 or x64) imported into Ghidra.

    Architecture-dependent COL layout (MSVC RTTI):
        x64 (sig==1, 6 DWORDs/24B): off, cd, pTD-RVA, pCHD-RVA, pSelf-RVA
        x86 (sig==0, 5 DWORDs/20B): off, cd, pTD-abs, pCHD-abs (no pSelf)
    Vtable slot pointer is uint64 (x64) or uint32 (x86), stored as
    absolute VA in both cases.
    """
    import jpype
    backing_manifest = resolve_backing_manifest(
        program, backing_manifest=backing_manifest)
    memory = program.getMemory()
    af = program.getAddressFactory()
    ds = af.getDefaultAddressSpace()
    image_base = program.getImageBase().getOffset()
    ptr_size = program.getDefaultPointerSize()  # 4 (x86) or 8 (x64)
    is_x64 = (ptr_size == 8)
    _validate_rtti_machine(backing_manifest, ptr_size)
    col_struct_size = 24 if is_x64 else 20
    expected_sig = 1 if is_x64 else 0
    print(f"  Arch: {'x64' if is_x64 else 'x86'} (ptr_size={ptr_size})")

    # Build a readable metadata list (including writable .data TypeDescriptors)
    # and a narrower set of read-only COL/vtable scan candidates.  Some
    # unpacked binaries split a PE section into multiple Ghidra blocks, so each
    # initialized intersection is handled independently.
    scan_blocks = []
    sects = []
    for block in memory.getBlocks():
        try:
            is_default = bool(
                block.getStart().getAddressSpace().equals(ds))
        except Exception:
            is_default = block.getStart().getAddressSpace() == ds
        intersections = _block_manifest_intersections(
            block.getStart().getOffset(), block.getEnd().getOffset(),
            is_default, backing_manifest)
        for start, end, pe_section in intersections:
            size = end - start + 1
            sect = {
                "name": pe_section.get("name") or block.getName(),
                "vaddr": start - image_base,
                "vsize": size,
                "start_va": start, "end_va": end,
                "start_addr": block.getStart().add(
                    start - block.getStart().getOffset()),
                "block": block, "pe_section": pe_section,
            }
            metadata_readable, col_scannable = _rtti_section_roles(
                block, pe_section)
            if metadata_readable:
                sects.append(sect)
            if col_scannable and size >= col_struct_size:
                scan_blocks.append(sect)
    if not scan_blocks:
        return {'schema': 1, 'pointer_size': ptr_size, 'vtables': {},
                'vtable_records': [], 'complete_object_locators': [], 'classes': {}}

    ByteArray = jpype.JArray(jpype.JByte)
    CHUNK = 64 * 1024
    block_bytes = {}
    for sect in scan_blocks:
        buf_all = bytearray(sect["vsize"])
        n_unread = 0
        for off in range(0, sect["vsize"], CHUNK):
            n = min(CHUNK, sect["vsize"] - off)
            buf = ByteArray(n)
            try:
                memory.getBytes(sect["start_addr"].add(off), buf, 0, n)
                for i in range(n):
                    buf_all[off + i] = buf[i] & 0xff
            except Exception:
                n_unread += n
        if 0 < n_unread < sect["vsize"]:
            print(f"  NOTE: {n_unread:,} bytes of {sect['name']} unreadable; zeros")
        block_bytes[id(sect)] = bytes(buf_all)

    image_rva_max = int(backing_manifest["image_size"])

    def read_any_rva(rva, n):
        for s in scan_blocks:
            if s["vaddr"] <= rva and rva + n <= s["vaddr"] + s["vsize"]:
                local = rva - s["vaddr"]
                buf = block_bytes[id(s)]
                if local + n <= len(buf):
                    return buf[local:local + n]
        # Fallback: ghidra memory for non-cached blocks (e.g., .data sect)
        target_va = image_base + rva
        for s in sects:
            if s["vaddr"] <= rva and rva + n <= s["vaddr"] + s["vsize"]:
                tmp = ByteArray(n)
                try:
                    memory.getBytes(s["start_addr"].add(
                        rva - s["vaddr"]), tmp, 0, n)
                    return bytes((b & 0xff) for b in tmp)
                except Exception:
                    return None
        return None

    # Pass 1: COL discovery.
    #   x64 — sig==1, pSelf self-reference (strong), pTD/pCHD are RVAs.
    #   x86 — sig==0, no pSelf; validate by pTD/pCHD pointing into image
    #         (absolute VAs, converted to RVAs here for uniformity).
    cols = {}
    for sect in scan_blocks:
        bytes_buf = block_bytes[id(sect)]
        sect_rva = sect["vaddr"]
        for p in range(0, len(bytes_buf) - col_struct_size + 1, 4):
            sig = struct.unpack_from("<I", bytes_buf, p)[0]
            if sig != expected_sig:
                continue
            if is_x64:
                off, cd, ptd, pcd, pself = struct.unpack_from(
                    "<IIIII", bytes_buf, p + 4)
                col_rva = sect_rva + p
                if pself != col_rva:
                    continue
                if ptd >= image_rva_max or pcd >= image_rva_max:
                    continue
                cols[col_rva] = {
                    'rva': col_rva, 'type_descriptor_rva': ptd,
                    'class_hierarchy_rva': pcd, 'subobject_offset': off,
                    'constructor_displacement': cd,
                }
            else:
                off, cd, ptd_abs, pcd_abs = struct.unpack_from(
                    "<IIII", bytes_buf, p + 4)
                # x86 stores absolute VAs; convert to RVA.
                if ptd_abs < image_base or pcd_abs < image_base:
                    continue
                ptd = ptd_abs - image_base
                pcd = pcd_abs - image_base
                if ptd >= image_rva_max or pcd >= image_rva_max:
                    continue
                col_rva = sect_rva + p
                cols[col_rva] = {
                    'rva': col_rva, 'type_descriptor_rva': ptd,
                    'class_hierarchy_rva': pcd, 'subobject_offset': off,
                    'constructor_displacement': cd,
                }
    print(f"  Pass1 COL candidates (sig-anchored): {len(cols):,}")

    # Pass 2: demangle TypeDescriptor names (MSVC layout varies — name
    # starts at +0x08 for some builds, +0x10 for others; scan for ".?A").
    name_by_col = {}
    def read_type_name(ptd):
        head_size = _bounded_metadata_read_size(sects, ptd, 0x20)
        if head_size < 0x0b:
            return None
        head = read_any_rva(ptd, head_size)
        if head is None:
            return None
        prefix_pos = None
        for off2 in (0x08, 0x10):
            if head[off2:off2 + 3] == b".?A":
                prefix_pos = off2
                break
        if prefix_pos is None:
            return None
        name_rva = ptd + prefix_pos
        # Template-heavy MSVC TypeDescriptor names regularly exceed 255
        # bytes.  Clip the read to the owning section so valid names near the
        # end of .data are not rejected merely because a fixed-size request
        # would cross the file-backed boundary.
        name_size = _bounded_metadata_read_size(sects, name_rva, 1024)
        if name_size <= 0:
            return None
        name_buf = read_any_rva(name_rva, name_size)
        if name_buf is None:
            return None
        end = name_buf.find(b"\x00")
        if end == -1:
            return None
        mangled = name_buf[:end].decode("latin-1", errors="replace")
        if not mangled.startswith(".?A"):
            return None
        return demangle_class(mangled)

    for col_rva, col in cols.items():
        class_name = read_type_name(col['type_descriptor_rva'])
        if class_name:
            name_by_col[col_rva] = class_name
    print(f"  Pass2 typed COLs (demangled):        {len(name_by_col):,}")

    def rtti_ptr(raw):
        if is_x64:
            return raw
        return (raw - image_base
                if image_base <= raw < image_base + image_rva_max else None)

    # x86 fallback: many older MSVC x86 binaries store COL fields with a
    # non-zero signature or omit it entirely.  Anchor on TypeDescriptor
    # name strings instead, then locate COLs by finding DWORDs that
    # reference each TypeDescriptor and validating the surrounding bytes.
    if not is_x64 and len(name_by_col) < 200:
        added = 0
        # Step A: find every '.?A...' string in scanned blocks.
        td_va_to_name = {}
        for sect in scan_blocks:
            bytes_buf = block_bytes[id(sect)]
            sect_va = sect["start_va"]
            i = 0
            while True:
                i = bytes_buf.find(b".?A", i)
                if i < 0:
                    break
                end = bytes_buf.find(b"\x00", i)
                if end < 0 or end - i > 1024:
                    i += 1
                    continue
                mangled = bytes_buf[i:end].decode("latin-1", errors="replace")
                if not mangled.startswith((".?AV", ".?AU", ".?AW")):
                    i = end + 1
                    continue
                # x86 TD: pVFTable(4) spare(4) name(...) — name at +8.
                td_va = sect_va + i - 8
                if td_va >= image_base:
                    td_va_to_name[td_va] = demangle_class(mangled)
                i = end + 1
        # Step B: scan for DWORDs == td_va, then look back at offsets
        # -12 (5-DWORD COL with sig) and -8 (legacy 4-DWORD COL) for the
        # COL start.  Accept if pCHD points into the image.
        for sect in scan_blocks:
            bytes_buf = block_bytes[id(sect)]
            sect_va = sect["start_va"]
            sect_rva = sect["vaddr"]
            n = len(bytes_buf)
            for p in range(16, n - 4 + 1, 4):
                td_abs = struct.unpack_from("<I", bytes_buf, p)[0]
                if td_abs not in td_va_to_name:
                    continue
                # Try 5-DWORD layout first (offset -12 = COL start).
                for back, has_sig in ((12, True), (8, False)):
                    col_p = p - back
                    if col_p < 0:
                        continue
                    if has_sig:
                        sig_val = struct.unpack_from("<I", bytes_buf, col_p)[0]
                        if sig_val not in (0, 1):
                            continue
                    pcd_off = col_p + (16 if has_sig else 12)
                    if pcd_off + 4 > n:
                        continue
                    pcd_abs = struct.unpack_from("<I", bytes_buf, pcd_off)[0]
                    if pcd_abs < image_base:
                        continue
                    if (pcd_abs - image_base) >= image_rva_max:
                        continue
                    col_rva = sect_rva + col_p
                    if col_rva not in name_by_col:
                        name_by_col[col_rva] = td_va_to_name[td_abs]
                        # Preserve the same coordinate schema as signature-
                        # anchored COLs so hierarchy parsing can consume it.
                        off_pos = col_p + (4 if has_sig else 0)
                        cd_pos = off_pos + 4
                        off_val = struct.unpack_from('<I', bytes_buf, off_pos)[0]
                        cd_val = struct.unpack_from('<I', bytes_buf, cd_pos)[0]
                        cols[col_rva] = {
                            'rva': col_rva,
                            'type_descriptor_rva': td_abs - image_base,
                            'class_hierarchy_rva': pcd_abs - image_base,
                            'subobject_offset': off_val,
                            'constructor_displacement': cd_val,
                        }
                        added += 1
                    break
        print(f"  x86 fallback (TD-anchored) added:    {added:,}")
        print(f"  Total typed COLs after fallback:     {len(name_by_col):,}")

    # x86 lacks x64's pSelf invariant, so a zero/signature-like DWORD plus a
    # TypeDescriptor-looking string is not mutation-grade evidence.  Require
    # the complete CHD -> base array -> BCD graph and require its first base
    # descriptor to refer back to the COL's own TypeDescriptor.
    def valid_x86_hierarchy(col):
        chd = read_any_rva(col.get('class_hierarchy_rva'), 16)
        if not chd or len(chd) != 16:
            return False
        chd_sig, _attrs, base_count, base_array_raw = struct.unpack(
            '<IIII', chd)
        if chd_sig != 0 or base_count == 0 or base_count > 4096:
            return False
        base_array_rva = rtti_ptr(base_array_raw)
        if base_array_rva is None:
            return False
        base_array = read_any_rva(base_array_rva, base_count * 4)
        if not base_array or len(base_array) != base_count * 4:
            return False
        for index in range(base_count):
            bcd_rva = rtti_ptr(struct.unpack_from(
                '<I', base_array, index * 4)[0])
            bcd = read_any_rva(bcd_rva, 24) if bcd_rva is not None else None
            if not bcd or len(bcd) != 24:
                return False
            td_raw, contained, _mdisp, pdisp, _vdisp, _attrs = \
                struct.unpack('<IIiiiI', bcd)
            td_rva = rtti_ptr(td_raw)
            if (td_rva is None or not read_type_name(td_rva) or
                    contained > base_count or pdisp < -1):
                return False
            if index == 0 and td_rva != col.get('type_descriptor_rva'):
                return False
        return True

    if not is_x64:
        rejected = [col_rva for col_rva in name_by_col
                    if not valid_x86_hierarchy(cols[col_rva])]
        for col_rva in rejected:
            name_by_col.pop(col_rva, None)
            cols.pop(col_rva, None)
        if rejected:
            print(f"  x86 COLs rejected by full hierarchy gate: {len(rejected):,}")

    # Pass 3: scan for a slot whose stored pointer == abs VA of a known COL.
    # Vtable layout: [COL-ptr][slot0][slot1]...  COL ptr precedes vtable by
    # one pointer-width slot, in both x86 and x64.
    vtables = {}
    vtable_records = []
    ptr_fmt = "<Q" if is_x64 else "<I"
    for sect in scan_blocks:
        bytes_buf = block_bytes[id(sect)]
        sect_rva = sect["vaddr"]
        for p in range(0, len(bytes_buf) - ptr_size, ptr_size):
            ptr = struct.unpack_from(ptr_fmt, bytes_buf, p)[0]
            if ptr == 0:
                continue
            col_rva = ptr - image_base
            if col_rva not in name_by_col:
                continue
            vt_va = image_base + sect_rva + p + ptr_size
            if vt_va not in vtables:
                vtables[vt_va] = name_by_col[col_rva]
                col = cols.get(col_rva, {})
                vtable_records.append({
                    'vtable_id': '{}@rva_{:X}:subobject_{:X}'.format(
                        name_by_col[col_rva], vt_va - image_base,
                        int(col.get('subobject_offset', 0))),
                    'vtable_va': vt_va,
                    'vtable_rva': vt_va - image_base,
                    'class_name': name_by_col[col_rva],
                    'col_rva': col_rva,
                    'subobject_offset': col.get('subobject_offset', 0),
                    'is_primary': int(col.get('subobject_offset', 0)) == 0,
                    'constructor_displacement': col.get('constructor_displacement', 0),
                })

    # Parse CHD -> base-class array -> BaseClassDescriptor/PMD.  All addresses
    # in x64 RTTI are image-relative; their x86 counterparts are absolute.
    classes = {}
    col_records = []
    for col_rva, class_name in sorted(name_by_col.items()):
        col = cols.get(col_rva)
        if not col:
            continue
        record = dict(col)
        record['class_name'] = class_name
        record['vtable_vas'] = [r['vtable_va'] for r in vtable_records
                                if r['col_rva'] == col_rva]
        col_records.append(record)
        entry = classes.setdefault(class_name, {'bases': [], 'vtables': []})
        entry['vtables'].extend(record['vtable_vas'])
        chd_rva = col.get('class_hierarchy_rva')
        chd = read_any_rva(chd_rva, 16) if chd_rva is not None else None
        if not chd or len(chd) < 16:
            continue
        chd_sig, chd_attrs, base_count, base_array_raw = struct.unpack_from('<IIII', chd, 0)
        base_array_rva = rtti_ptr(base_array_raw)
        if base_count == 0 or base_count > 4096 or base_array_rva is None:
            continue
        base_array = read_any_rva(base_array_rva, base_count * 4)
        if not base_array or len(base_array) < base_count * 4:
            continue
        bases = []
        valid = True
        for idx in range(base_count):
            bcd_raw = struct.unpack_from('<I', base_array, idx * 4)[0]
            bcd_rva = rtti_ptr(bcd_raw)
            if bcd_rva is None:
                valid = False
                break
            bcd = read_any_rva(bcd_rva, 28)
            if not bcd or len(bcd) < 24:
                valid = False
                break
            td_raw, contained, mdisp, pdisp, vdisp, attrs = struct.unpack_from(
                '<IIiiiI', bcd, 0)
            td_rva = rtti_ptr(td_raw)
            base_name = read_type_name(td_rva) if td_rva is not None else None
            if not base_name:
                valid = False
                break
            bases.append({
                'index': idx, 'class_name': base_name,
                'type_descriptor_rva': td_rva,
                'num_contained_bases': contained,
                'member_displacement': mdisp,
                'vbtable_displacement': pdisp,
                'vbase_displacement': vdisp,
                'attributes': attrs,
                'is_virtual': pdisp != -1,
            })
        if valid:
            entry['bases'] = bases
            entry['hierarchy_attributes'] = chd_attrs
            entry['hierarchy_signature'] = chd_sig

    return {
        'schema': 1,
        'pointer_size': ptr_size,
        'image_base': image_base,
        'vtables': vtables,
        'vtable_records': vtable_records,
        'complete_object_locators': col_records,
        'classes': classes,
    }


def scan_rtti_vtables(program):
    """Backward-compatible vtable-only view of :func:`scan_msvc_rtti`."""
    return scan_msvc_rtti(program)['vtables']


def scan_rtti_hierarchy(program):
    """Public hierarchy scanner API for downstream type/inheritance passes."""
    return scan_msvc_rtti(program)


def expand_vtables(program, vtables, backing_manifest=None):
    """For each vtable, walk slots and yield (target_va, Class::Func<N>).

    Termination per vtable:
      * zero pointer
      * pointer outside .text
      * next slot is another known vtable VA
      * DEFAULT_MAX_SLOTS hard cap
    """
    backing_manifest = resolve_backing_manifest(
        program, backing_manifest=backing_manifest)
    memory = program.getMemory()
    af = program.getAddressFactory()
    ds = af.getDefaultAddressSpace()
    ptr_size = program.getDefaultPointerSize()
    ptr_mask = (1 << (ptr_size * 8)) - 1

    def read_ptr(va):
        if ptr_size == 8:
            return memory.getLong(ds.getAddress(va)) & ptr_mask
        return memory.getInt(ds.getAddress(va)) & ptr_mask

    vtable_va_set = set(vtables.keys())
    for vt_va, cls in vtables.items():
        vt_section = _manifest_section_for_va(
            backing_manifest, vt_va, ptr_size, file_backed=True)
        if (vt_section is None or not vt_section.get("readable") or
                vt_section.get("writable") or vt_section.get("executable")):
            continue
        vt_addr = ds.getAddress(vt_va)
        vt_block = memory.getBlock(vt_addr)
        if vt_block is None or not vt_block.isInitialized() or vt_block.isExecute():
            continue
        remaining = vt_block.getEnd().getOffset() - vt_va + 1
        max_slots = min(DEFAULT_MAX_SLOTS, max(0, remaining // ptr_size))
        for slot_idx in range(max_slots):
            slot_va = vt_va + slot_idx * ptr_size
            try:
                ptr_val = read_ptr(slot_va)
            except Exception:
                break
            if ptr_val == 0:
                break
            target_section = _manifest_section_for_va(
                backing_manifest, ptr_val, 1, file_backed=True)
            # Reject unsigned garbage/out-of-image values before converting
            # them to a Java long-backed Address through JPype.
            if target_section is None or not target_section.get("executable"):
                break
            target_block = memory.getBlock(ds.getAddress(ptr_val))
            if (target_block is None or not target_block.isInitialized() or
                    not target_block.isExecute()):
                break
            next_va = vt_va + (slot_idx + 1) * ptr_size
            if slot_idx > 0 and next_va in vtable_va_set:
                yield (ptr_val, f"{cls}::Func{slot_idx}")
                break
            yield (ptr_val, f"{cls}::Func{slot_idx}")


# ---------------------------------------------------------------------------
#  Phase 3: apply names + create functions where needed
# ---------------------------------------------------------------------------

# Ghidra's own placeholders.  We deliberately do NOT match IDA-style
# prefixes (sub_/loc_/Sub_/j_/...) because those may have been intentionally
# applied by a CSV/PDB importer as meaningful names; the only truly safe
# signal is Ghidra's SourceType.DEFAULT bit on the symbol itself.
_GHIDRA_DEFAULT_NAME_RE = re.compile(r"^(?:FUN|thunk_FUN)_[0-9a-fA-F]+$")


def _is_overwritable(func):
    """True iff the function's name is a known Ghidra-default placeholder.

    Conservative on purpose: only renames when we are 100% confident the
    current name carries no meaning.  Symbol source must be DEFAULT
    (Ghidra-generated), AND the name must match a Ghidra placeholder
    regex.  Any IMPORTED / USER_DEFINED / ANALYSIS-source symbol is left
    untouched.
    """
    from ghidra.program.model.symbol import SourceType
    sym = func.getSymbol()
    if sym is None:
        return False
    if sym.getSource() != SourceType.DEFAULT:
        return False
    return bool(_GHIDRA_DEFAULT_NAME_RE.match(func.getName()))


def apply_naming(program, slot_pairs, monitor, dry_run=False,
                 backing_manifest=None):
    """Apply each (target_va, name) to the program; create functions at
    slot-target VAs that don't have one yet.  Returns stats dict.
    """
    from ghidra.program.model.symbol import SourceType
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.app.cmd.disassemble import DisassembleCommand

    backing_manifest = resolve_backing_manifest(
        program, backing_manifest=backing_manifest)
    fm = program.getFunctionManager()
    sym = program.getSymbolTable()
    listing = program.getListing()
    global_ns = program.getGlobalNamespace()
    af = program.getAddressFactory()
    ds = af.getDefaultAddressSpace()
    memory = program.getMemory()

    ns_cache = {}
    def get_or_create_namespace(path_parts):
        if not path_parts:
            return global_ns
        key = "::".join(path_parts)
        if key in ns_cache:
            return ns_cache[key]
        parent = global_ns
        for part in path_parts:
            sub = sym.getNamespace(part, parent)
            if sub is None:
                if not dry_run:
                    sub = sym.createNameSpace(parent, part, SourceType.ANALYSIS)
                else:
                    sub = parent  # dry-run: don't create
            parent = sub
        ns_cache[key] = parent
        return parent

    stats = {"unique_vas": 0, "renamed": 0, "already_named": 0,
             "created": 0, "would_create": 0, "inside_function": 0,
             "create_fail": 0, "outside_text": 0,
             "shared_conflicts": 0, "errors": 0}
    already_named_samples = []  # first ~10 names we skipped
    proposals = defaultdict(set)
    for target_va, name in slot_pairs:
        proposals[target_va].add(name)
    had_parent_transaction = (
        not dry_run and program.getCurrentTransactionInfo() is not None)
    txid = program.startTransaction("RTTI vtable pipeline") if not dry_run else None
    commit = False
    try:
        for target_va, names in sorted(proposals.items()):
            stats["unique_vas"] += 1
            target_section = _manifest_section_for_va(
                backing_manifest, target_va, 1, file_backed=True)
            if target_section is None or not target_section.get("executable"):
                stats["outside_text"] += 1
                continue
            addr = ds.getAddress(target_va)
            block = memory.getBlock(addr)
            if block is None or not block.isInitialized() or not block.isExecute():
                stats["outside_text"] += 1
                continue
            func = fm.getFunctionAt(addr)
            if func is None:
                inside = fm.getFunctionContaining(addr)
                if inside is not None:
                    stats["inside_function"] += 1
                    continue
                if dry_run:
                    stats["would_create"] += 1
                    continue
                if listing.getInstructionAt(addr) is None:
                    if not DisassembleCommand(addr, None, True).applyTo(program, monitor):
                        stats["create_fail"] += 1
                        continue
                if not CreateFunctionCmd(addr).applyTo(program, monitor):
                    stats["create_fail"] += 1
                    continue
                func = fm.getFunctionAt(addr)
                if func is None:
                    stats["create_fail"] += 1
                    continue
                stats["created"] += 1
            if len(names) != 1:
                stats["shared_conflicts"] += 1
                if not dry_run:
                    cu = listing.getCodeUnitAt(addr)
                    if cu:
                        existing = cu.getComment(0) or ''
                        note = 'RTTI shared vfunc claims: ' + ' | '.join(sorted(names))
                        if note not in existing:
                            cu.setComment(0, existing + ('\n' if existing else '') + note)
                continue
            name = next(iter(names))
            if not _is_overwritable(func):
                stats["already_named"] += 1
                if len(already_named_samples) < 10:
                    already_named_samples.append(
                        (f"0x{target_va:x}", func.getName()))
                continue
            parts = split_namespaced(name)
            leaf = parts[-1]
            ns_path = parts[:-1]
            if dry_run:
                stats["renamed"] += 1
                continue
            try:
                target_ns = get_or_create_namespace(ns_path)
                func.setParentNamespace(target_ns)
                func.setName(leaf, SourceType.ANALYSIS)
                stats["renamed"] += 1
            except Exception as e:
                stats["errors"] += 1
                if stats["errors"] < 5:
                    print(f"  err 0x{target_va:x} '{name[:60]}': {e}")
        # Tolerate stray per-name failures (duplicate-name collisions etc.)
        # so one bad name cannot void a long pass, but still roll back when
        # errors are systemic (broken evidence / wrong target).
        error_budget = max(25, stats["unique_vas"] // 100)
        if stats["errors"] > error_budget:
            raise RuntimeError(
                "RTTI apply encountered {} naming error(s) (budget {}); "
                "rolling back the full pass".format(
                    stats["errors"], error_budget))
        commit = True
    finally:
        if txid is not None:
            committed = bool(program.endTransaction(txid, commit))
            if commit and not had_parent_transaction and not committed:
                raise RuntimeError(
                    "RTTI improvement outer transaction did not commit")

    if already_named_samples:
        print("  sample of preserved (already-named) targets:")
        for va, nm in already_named_samples:
            print(f"    {va}  {nm[:80]}")
    return stats


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

def _parse_cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_dir")
    parser.add_argument("project_name")
    parser.add_argument("program_path")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--hierarchy-json")
    parser.add_argument(
        "--target-pe", action="append", default=[], metavar="PATH",
        help="exact local PE candidate; repeat for packed/unpacked candidates")
    parser.add_argument(
        "--target-manifest", action="append", default=[], metavar="PATH",
        help="exact inspect_pe manifest for a no-longer-present import path")
    return parser.parse_args(argv)


def main():
    args = _parse_cli()
    project_dir = args.project_dir
    project_name = args.project_name
    program_path = args.program_path
    dry_run = args.dry_run
    hierarchy_json = args.hierarchy_json

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    print(f"Project:  {project_dir}/{project_name}")
    print(f"Program:  {program_path}")
    print(f"Dry run:  {dry_run}")

    with open_user_project(project_dir, project_name) as project:
        df = project.getProjectData().getFile(program_path)
        if df is None:
            print(f"ERROR: program not found: {program_path}")
            # Not 2: that code is reserved for "the project was locked", which
            # the caller answers by retrying.  A missing program never becomes
            # present on a retry.
            sys.exit(4)
        consumer = java.lang.Object()
        program = df.getDomainObject(consumer, not dry_run, False, monitor)
        try:
            try:
                backing_manifest = resolve_backing_manifest(
                    program,
                    target_pe_paths=args.target_pe,
                    target_manifest_paths=args.target_manifest)
            except (OSError, ValueError) as exc:
                print(f"ERROR: refusing unverifiable RTTI target: {exc}")
                sys.exit(3)
            print(f"\n=== Phase 1+2: RTTI scan ===")
            rtti = scan_msvc_rtti(program, backing_manifest)
            vtables = rtti['vtables']
            n_vt = len(vtables)
            print(f"  Discovered {n_vt:,} vtables via RTTI")
            print(f"  Recovered {len(rtti['classes']):,} class hierarchies and "
                  f"{len(rtti['complete_object_locators']):,} COL subobjects")
            if hierarchy_json:
                out_path = Path(hierarchy_json)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                export = dict(rtti)
                export['target'] = backing_manifest
                temp_path = out_path.with_suffix(out_path.suffix + '.tmp')
                temp_path.write_text(
                    json.dumps(export, indent=2, sort_keys=True) + "\n",
                    encoding='utf-8')
                temp_path.replace(out_path)
                print(f"  Wrote hierarchy evidence: {out_path}")
            if n_vt == 0:
                print("  No vtables found — aborting")
                return

            # Stats before
            fm = program.getFunctionManager()
            n_before_total = fm.getFunctionCount()
            n_before_named = sum(
                1 for f in fm.getFunctions(True)
                if not f.getName().startswith(("FUN_", "thunk_FUN_", "sub_")))

            print(f"\n=== Phase 3: slot expansion + apply ===")
            print(f"  before: {n_before_named:,} / {n_before_total:,} named "
                  f"({100*n_before_named/max(n_before_total,1):.1f}%)")

            stats = apply_naming(
                program, expand_vtables(program, vtables, backing_manifest),
                monitor, dry_run=dry_run,
                backing_manifest=backing_manifest)

            # Save
            if not dry_run:
                print(f"\nSaving program ...")
                program.save("RTTI vtable pipeline", monitor)

            # Stats after
            n_after_total = fm.getFunctionCount()
            n_after_named = sum(
                1 for f in fm.getFunctions(True)
                if not f.getName().startswith(("FUN_", "thunk_FUN_", "sub_")))

            print(f"\n=== Summary ===")
            print(f"  vtables discovered:    {n_vt:,}")
            print(f"  unique target VAs:     {stats['unique_vas']:,}")
            if dry_run:
                print(f"  functions would create:{stats['would_create']:>7,}")
                print(f"  functions would rename:{stats['renamed']:>7,}")
            else:
                print(f"  functions created:     {stats['created']:,}")
                print(f"  functions renamed:     {stats['renamed']:,}")
            print(f"  already named:         {stats['already_named']:,}")
            print(f"  shared conflicts:      {stats['shared_conflicts']:,}")
            print(f"  inside existing funcs: {stats['inside_function']:,}")
            print(f"  create fail:           {stats['create_fail']:,}")
            print(f"  outside .text:         {stats['outside_text']:,}")
            print(f"  errors:                {stats['errors']:,}")
            print()
            print(f"  named before:  {n_before_named:>7,} / {n_before_total:>7,} "
                  f"({100*n_before_named/max(n_before_total,1):.1f}%)")
            print(f"  named after:   {n_after_named:>7,} / {n_after_total:>7,} "
                  f"({100*n_after_named/max(n_after_total,1):.1f}%)")
            print(f"  delta:         {n_after_named - n_before_named:+,} named, "
                  f"{n_after_total - n_before_total:+,} total funcs")
            if dry_run:
                print("  dry run:       no program changes were made")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
