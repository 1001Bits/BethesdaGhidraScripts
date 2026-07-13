"""Extract trustworthy x64 function boundaries and unwind metadata from PE.

Unlike byte-signature/prologue discovery, ``.pdata`` entries are linker-owned
runtime-function records.  They are therefore useful as a high-confidence
function-entry index and as additional evidence for cross-version matching.
The module is stdlib-only and binds every output to an exact PE manifest.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from binary_identity import PEIdentityError, inspect_pe


UNW_FLAG_EHANDLER = 0x1
UNW_FLAG_UHANDLER = 0x2
UNW_FLAG_CHAININFO = 0x4

_OP_NAMES = {
    0: "PUSH_NONVOL",
    1: "ALLOC_LARGE",
    2: "ALLOC_SMALL",
    3: "SET_FPREG",
    4: "SAVE_NONVOL",
    5: "SAVE_NONVOL_FAR",
    6: "EPILOG",
    7: "SPARE",
    8: "SAVE_XMM128",
    9: "SAVE_XMM128_FAR",
    10: "PUSH_MACHFRAME",
}


def section_for_rva(manifest: Dict[str, Any], rva: int) -> Optional[Dict[str, Any]]:
    for section in manifest.get("sections", []):
        start = int(section["rva"])
        span = max(int(section["virtual_size"]), int(section["raw_size"]))
        if start <= rva < start + span:
            return section
    return None


def rva_to_offset(manifest: Dict[str, Any], rva: int, size: int = 1) -> int:
    section = section_for_rva(manifest, rva)
    if section is None:
        raise ValueError("RVA 0x{:X} is outside mapped sections".format(rva))
    delta = rva - int(section["rva"])
    if delta < 0 or delta + size > int(section["raw_size"]):
        raise ValueError("RVA 0x{:X} is not physically backed".format(rva))
    return int(section["raw_offset"]) + delta


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def parse_unwind_info(data: bytes, offset: int = 0) -> Dict[str, Any]:
    """Parse one AMD64 ``UNWIND_INFO`` from *data* at *offset*.

    Malformed/truncated records raise ``ValueError``; callers should quarantine
    that runtime-function entry rather than accepting partial metadata.
    """
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("truncated UNWIND_INFO header")
    vf, prolog_size, code_count, frame = struct.unpack_from("<BBBB", data, offset)
    version = vf & 0x7
    flags = vf >> 3
    if version not in (1, 2):
        raise ValueError("unsupported UNWIND_INFO version {}".format(version))
    if flags & ~(UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER |
                 UNW_FLAG_CHAININFO):
        raise ValueError("unsupported UNWIND_INFO flags 0x{:X}".format(flags))
    if (frame & 0x0F) == 0 and (frame >> 4):
        raise ValueError("frame offset is set without a frame register")
    codes_start = offset + 4
    codes_end = codes_start + code_count * 2
    if codes_end > len(data):
        raise ValueError("truncated unwind-code array")

    codes: List[Dict[str, Any]] = []
    slot = 0
    while slot < code_count:
        pos = codes_start + slot * 2
        code_offset = data[pos]
        packed = data[pos + 1]
        op = packed & 0x0F
        op_info = packed >> 4
        if op > 10:
            raise ValueError("unsupported unwind opcode {}".format(op))
        if op == 1 and op_info not in (0, 1):
            raise ValueError("invalid ALLOC_LARGE op-info {}".format(op_info))
        if op == 3 and op_info != 0:
            raise ValueError("SET_FPREG has nonzero op-info")
        if op in (6, 7) and version != 2:
            raise ValueError("version 1 cannot contain opcode {}".format(op))
        if op == 10 and op_info not in (0, 1):
            raise ValueError("invalid PUSH_MACHFRAME op-info {}".format(op_info))
        extra_slots = 0
        value = None
        if op == 1:  # ALLOC_LARGE
            extra_slots = 1 if op_info == 0 else 2 if op_info == 1 else 0
        elif op in (4, 8):
            extra_slots = 1
        elif op in (5, 9):
            extra_slots = 2
        if slot + extra_slots >= code_count:
            raise ValueError("truncated operands for unwind opcode {}".format(op))
        if extra_slots == 1:
            raw = _u16(data, pos + 2)
            if op == 1:
                value = raw * 8
            elif op == 4:
                value = raw * 8
            elif op == 8:
                value = raw * 16
        elif extra_slots == 2:
            raw = _u32(data, pos + 2)
            value = raw if op in (1, 5) else raw * 16
        elif op == 2:
            value = op_info * 8 + 8
        codes.append({
            "code_offset": code_offset,
            "op": op,
            "op_name": _OP_NAMES.get(op, "UNKNOWN_{}".format(op)),
            "op_info": op_info,
            "value": value,
        })
        slot += 1 + extra_slots

    tail = codes_start + ((code_count + 1) & ~1) * 2
    if tail > len(data):
        raise ValueError("truncated aligned unwind record")
    result: Dict[str, Any] = {
        "version": version,
        "flags": flags,
        "prolog_size": prolog_size,
        "frame_register": frame & 0x0F,
        "frame_offset": (frame >> 4) * 16,
        "codes": codes,
    }
    if flags & UNW_FLAG_CHAININFO:
        if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
            raise ValueError("CHAININFO cannot be combined with handler flags")
        if tail + 12 > len(data):
            raise ValueError("truncated chained runtime-function record")
        result["chained"] = {
            "begin_rva": _u32(data, tail),
            "end_rva": _u32(data, tail + 4),
            "unwind_rva": _u32(data, tail + 8),
        }
    elif flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
        if tail + 4 > len(data):
            raise ValueError("truncated exception-handler RVA")
        result["handler_rva"] = _u32(data, tail)
    return result


def validated_runtime_function_starts(path: str) -> set[int]:
    """Return structurally valid AMD64 ``.pdata`` begin RVAs quickly.

    This boundary-only path deliberately avoids decoding ~200k unwind programs
    when a caller only needs linker-attested starts.  It still binds the exact
    PE, requires an entirely file-backed exception directory, validates sorted
    non-overlapping executable ranges, and checks that each unwind RVA points
    into physically backed non-executable data.
    """
    manifest = inspect_pe(path)
    if int(manifest["machine"]) != 0x8664:
        return set()
    exception = next((entry for entry in manifest.get("data_directories", [])
                      if entry.get("name") == "exception"), None)
    if not exception or not int(exception.get("rva", 0)):
        return set()
    directory_rva = int(exception["rva"])
    size = int(exception["size"])
    if size < 12 or size % 12:
        raise ValueError("malformed AMD64 exception-directory size")
    blob = Path(path).read_bytes()
    start = rva_to_offset(manifest, directory_rva, size)
    starts = set()
    last_begin = -1
    last_end = -1
    for begin, end, unwind_rva in struct.iter_unpack(
            "<III", blob[start:start + size]):
        if begin == end == unwind_rva == 0:
            continue
        code_section = section_for_rva(manifest, begin)
        end_section = section_for_rva(manifest, max(begin, end - 1))
        unwind_section = section_for_rva(manifest, unwind_rva)
        valid = (0 < begin < end <= int(manifest["image_size"]) and
                 code_section is not None and code_section["executable"] and
                 end_section is code_section and begin > last_begin and
                 begin >= last_end and unwind_section is not None and
                 not unwind_section["executable"])
        if not valid:
            raise ValueError("malformed AMD64 runtime-function table")
        rva_to_offset(manifest, unwind_rva, 4)
        starts.add(begin)
        last_begin, last_end = begin, end
    return starts


def extract_runtime_functions(path: str) -> Dict[str, Any]:
    manifest = inspect_pe(path)
    if int(manifest["machine"]) != 0x8664:
        return {"schema": 1, "target": manifest, "runtime_functions": [],
                "rejected": [], "note": "AMD64 .pdata format not applicable"}
    exception = next((entry for entry in manifest.get("data_directories", [])
                      if entry.get("name") == "exception"), None)
    if not exception or not int(exception.get("rva", 0)) \
            or int(exception.get("size", 0)) < 12:
        return {"schema": 1, "target": manifest, "runtime_functions": [],
                "rejected": [], "note": "no PE exception directory"}
    blob = Path(path).read_bytes()
    directory_rva = int(exception["rva"])
    size = int(exception["size"])
    try:
        start = rva_to_offset(manifest, directory_rva, size)
    except ValueError as exc:
        return {"schema": 1, "target": manifest, "runtime_functions": [],
                "rejected": [{"entry_rva": directory_rva,
                              "begin_rva": 0, "reason": str(exc)}]}
    rows = []
    rejected = []
    last_begin = -1
    last_end = -1
    for rel in range(0, size - 11, 12):
        begin, end, unwind_rva = struct.unpack_from("<III", blob, start + rel)
        if begin == end == unwind_rva == 0:
            continue
        reason = None
        code_section = section_for_rva(manifest, begin)
        end_section = section_for_rva(manifest, max(begin, end - 1))
        if not (0 < begin < end <= int(manifest["image_size"])):
            reason = "invalid range"
        elif code_section is None or not code_section["executable"]:
            reason = "begin is not executable"
        elif end_section is None or not end_section["executable"]:
            reason = "end is not executable"
        elif code_section is not end_section:
            reason = "range crosses executable sections"
        elif begin <= last_begin or begin < last_end:
            reason = "runtime-function table is unsorted or overlapping"
        else:
            try:
                uoff = rva_to_offset(manifest, unwind_rva, 4)
                unwind_section = section_for_rva(manifest, unwind_rva)
                if unwind_section is None or unwind_section["executable"]:
                    raise ValueError("unwind info is not in non-executable data")
                section_end = (int(unwind_section["raw_offset"]) +
                               int(unwind_section["raw_size"]))
                unwind = parse_unwind_info(blob[uoff:section_end])
                if "handler_rva" in unwind:
                    handler = section_for_rva(manifest, unwind["handler_rva"])
                    if handler is None or not handler["executable"]:
                        raise ValueError("exception handler is not executable")
                if "chained" in unwind:
                    chained = unwind["chained"]
                    chained_code = section_for_rva(manifest,
                                                   chained["begin_rva"])
                    chained_end = section_for_rva(
                        manifest, max(chained["begin_rva"],
                                      chained["end_rva"] - 1))
                    chained_unwind = section_for_rva(
                        manifest, chained["unwind_rva"])
                    if not (0 < chained["begin_rva"] < chained["end_rva"]
                            <= int(manifest["image_size"])):
                        raise ValueError("invalid chained runtime-function range")
                    if (chained_code is None or chained_end is not chained_code
                            or not chained_code["executable"]):
                        raise ValueError("chained range is not executable")
                    if (chained_unwind is None or chained_unwind["executable"]
                            or rva_to_offset(manifest,
                                             chained["unwind_rva"], 4) < 0):
                        raise ValueError("chained unwind info is invalid")
            except (ValueError, struct.error) as exc:
                reason = str(exc)
        if reason:
            rejected.append({"entry_rva": directory_rva + rel,
                             "begin_rva": begin, "reason": reason})
            continue
        rows.append({"begin_rva": begin, "end_rva": end,
                     "size": end - begin, "unwind_rva": unwind_rva,
                     "unwind": unwind})
        last_begin, last_end = begin, end
    rows.sort(key=lambda row: row["begin_rva"])
    return {"schema": 1, "target": manifest,
            "exception_directory": {"rva": directory_rva, "size": size},
            "runtime_functions": rows, "rejected": rejected}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pe")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    try:
        result = extract_runtime_functions(args.pe)
    except (OSError, PEIdentityError, ValueError) as exc:
        print("ERROR: {}".format(exc))
        return 1
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    temp = out.with_suffix(out.suffix + ".tmp")
    temp.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    temp.replace(out)
    print("{} runtime functions; {} rejected -> {}".format(
        len(result["runtime_functions"]), len(result["rejected"]), out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
