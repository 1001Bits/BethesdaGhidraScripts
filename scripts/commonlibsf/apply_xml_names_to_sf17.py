#!/usr/bin/env python3
"""Apply names from `starfield_with_fallout_matched_functions.xml` to the
Starfield 1.7-ish binary currently loaded in Ghidra via MCP.

The XML is a Ghidra Program export from Sep 2023 (Starfield ~1.7.x).
We don't have its companion `.bytes` file so byte-signature porting
isn't possible from the XML alone -- but the image base + section
layout of the user's loaded `Starfield.exe` matches closely enough
that direct address-based rename works for most names that haven't
drifted between the two builds.

Strategy:
  1. Stream FUNCTION entries from the XML.
  2. Filter out auto-named noise (FUN_, thunk_, _dynamic_initializer_,
     _anonymous_namespace_::_dynamic_initializer, _lambda_, sub_, API-MS-).
  3. Batch-rename via `batch_rename` MCP tool, target_type="function",
     identifier="FUN_<rva>" so we hit the auto-generated function name
     at the address.  Fall back to target_type="data" for entries that
     don't resolve as functions (label-only rename).

Output:
  - Audit CSV at refs/sf17_xml_rename_audit.csv with (rva, name, status).
  - Final stats printed to stdout (renamed / labeled / no_function / errors).
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import time
import urllib.request
import zipfile
from html import unescape
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
XML_ZIP   = os.environ.get("BGS_SF17_XML_ZIP", "")
XML_NAME  = "starfield_with_fallout_matched_functions.xml"
MCP_URL   = os.environ.get("BGS_MCP_URL", "http://localhost:8080/mcp")
PROGRAM   = os.environ.get("BGS_MCP_PROGRAM", "Starfield.exe")
OUT_CSV   = os.environ.get(
    "BGS_SF17_XML_AUDIT", str(SCRIPT_DIR / "refs" / "sf17_xml_rename_audit.csv"))
BATCH     = 200  # renames per MCP call

FUNCTION_RE = re.compile(
    r'<FUNCTION\s+ENTRY_POINT="([0-9a-fA-F]+)"\s+NAME="([^"]+)"',
)

# Substring-based -- catches Scaleform::Alg::_dynamic_initializer_for__... too.
NOISE_SUBSTRINGS = (
    "_dynamic_initializer_for_",
    "_lambda_",
    "API-MS-",
)
NOISE_PREFIXES = (
    "FUN_",
    "thunk_FUN_",
    "sub_",
)


def is_noise(name: str) -> bool:
    if any(name.startswith(p) for p in NOISE_PREFIXES):
        return True
    if any(s in name for s in NOISE_SUBSTRINGS):
        return True
    return False


# ---------------------------------------------------------------------
#  MCP plumbing
# ---------------------------------------------------------------------

def _http_post(url: str, body: dict, headers: dict, timeout: int = 20) -> str:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers=headers,
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", errors="replace")
        return text, dict(resp.headers)


def _parse_sse_or_json(text: str) -> dict:
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:].strip())
    return json.loads(text)


def init_session() -> str:
    body = {
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "applier", "version": "1"},
        },
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    text, hdrs = _http_post(MCP_URL, body, headers, timeout=15)
    sid = hdrs.get("Mcp-Session-Id") or hdrs.get("mcp-session-id")
    if not sid:
        for k, v in hdrs.items():
            if k.lower() == "mcp-session-id":
                sid = v; break
    if not sid:
        raise RuntimeError("MCP init: no Mcp-Session-Id header in response")
    # notify initialized
    _http_post(
        MCP_URL,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {**headers, "Mcp-Session-Id": sid},
        timeout=10,
    )
    return sid


def mcp_call(sid: str, tool: str, args: dict, timeout: int = 60) -> dict:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Mcp-Session-Id": sid,
    }
    body = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }
    text, _ = _http_post(MCP_URL, body, headers, timeout=timeout)
    return _parse_sse_or_json(text)


def extract_text(resp: dict) -> str:
    try:
        return resp["result"]["content"][0]["text"]
    except Exception:
        return ""


# ---------------------------------------------------------------------
#  XML streaming
# ---------------------------------------------------------------------

def stream_xml_entries():
    with zipfile.ZipFile(XML_ZIP) as zf, zf.open(XML_NAME) as f:
        for line in io.TextIOWrapper(f, encoding="utf-8", errors="replace"):
            m = FUNCTION_RE.search(line)
            if m:
                rva = int(m.group(1), 16)
                name = unescape(m.group(2))
                if is_noise(name):
                    continue
                yield rva, name


# ---------------------------------------------------------------------
#  Batch rename
# ---------------------------------------------------------------------

def submit_batch(sid: str, entries: list[tuple[int, str]],
                 target_type: str) -> dict:
    """Return summary of one batch_rename call."""
    renames = []
    for rva, name in entries:
        if target_type == "function":
            identifier = f"FUN_{rva:09x}"
        elif target_type == "data":
            identifier = "0x{:x}".format(rva)
        else:
            raise ValueError(target_type)
        renames.append({
            "target_type": target_type,
            "identifier":  identifier,
            "new_name":    name,
        })
    return mcp_call(sid, "batch_rename", {
        "program_name": PROGRAM,
        "renames": renames,
    }, timeout=120)


def parse_batch_text(text: str) -> dict[str, int]:
    """Heuristic parse of the batch_rename response text.

    Response example (free-form text):
       'Batch rename: 78 succeeded, 22 failed
        Failures:
          - FUN_140001234: not found
          ...'
    """
    succ = 0
    fail = 0
    failures = []
    m = re.search(r'(\d+)\s+succe', text)
    if m: succ = int(m.group(1))
    m = re.search(r'(\d+)\s+fail', text)
    if m: fail = int(m.group(1))
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("-") or line.startswith("*"):
            failures.append(line.lstrip("-* ").strip())
    return {"ok": succ, "fail": fail, "failures": failures}


def main():
    raise SystemExit(
        "DISABLED: direct XML-address mutation across an approximate "
        "'1.7-ish' target is not identity-safe and MCP cannot provide "
        "atomic rollback. Export against the exact source PE and use the "
        "SHA-bound port_sf17_to_sf116.py pipeline instead.")
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    print(f"MCP {MCP_URL}; target program: {PROGRAM}")
    print(f"XML: {XML_ZIP}")
    print(f"BATCH size: {BATCH}\n")

    sid = init_session()
    print(f"MCP session: {sid}\n")

    # Sanity check program is loaded
    r = mcp_call(sid, "get_binary_info", {"program_name": PROGRAM}, timeout=10)
    t = extract_text(r)
    if "not found" in t.lower() or not t:
        print(f"ERROR: program '{PROGRAM}' not loaded.  Response: {t[:200]}")
        sys.exit(2)
    print(f"Program OK: {t.splitlines()[0][:120]}\n")

    rows: list[tuple[str, str, str]] = []
    n_total = 0
    n_func_ok = 0
    n_func_fail = 0
    n_data_ok = 0
    n_data_fail = 0

    buf: list[tuple[int, str]] = []
    func_fail_buf: list[tuple[int, str]] = []
    t0 = time.time()

    def flush_function_batch():
        nonlocal n_func_ok, n_func_fail
        if not buf:
            return
        r = submit_batch(sid, buf, "function")
        text = extract_text(r)
        parsed = parse_batch_text(text)
        n_func_ok += parsed["ok"]
        n_func_fail += parsed["fail"]
        # Identify which entries failed -> retry as data labels.
        failed_ids = set()
        for ln in parsed["failures"]:
            m = re.search(r'FUN_([0-9a-fA-F]+)', ln)
            if m:
                failed_ids.add(int(m.group(1), 16))
        for rva, name in buf:
            if rva in failed_ids:
                func_fail_buf.append((rva, name))
                rows.append(("0x{:x}".format(rva), name, "func_miss_retry_as_data"))
            else:
                rows.append(("0x{:x}".format(rva), name, "renamed_function"))
        buf.clear()

    def flush_data_batch():
        nonlocal n_data_ok, n_data_fail
        if not func_fail_buf:
            return
        r = submit_batch(sid, func_fail_buf, "data")
        text = extract_text(r)
        parsed = parse_batch_text(text)
        n_data_ok += parsed["ok"]
        n_data_fail += parsed["fail"]
        for rva, name in func_fail_buf:
            rows.append(("0x{:x}".format(rva), name, "labeled_as_data"))
        func_fail_buf.clear()

    print("Streaming XML and submitting batches...")
    for rva, name in stream_xml_entries():
        buf.append((rva, name))
        n_total += 1
        if len(buf) >= BATCH:
            flush_function_batch()
        if n_total % (BATCH * 5) == 0:
            elapsed = time.time() - t0
            rate = n_total / max(elapsed, 0.001)
            print(f"  {n_total:6d} processed  func_ok={n_func_ok}  func_fail={n_func_fail}  rate={rate:.1f}/s  elapsed={elapsed:.0f}s")

    flush_function_batch()
    # Now retry all function misses as data labels
    if func_fail_buf:
        print(f"\nRetrying {len(func_fail_buf)} function-misses as data labels...")
        # Process in BATCH-size chunks
        i = 0
        while i < len(func_fail_buf):
            chunk = func_fail_buf[i:i+BATCH]
            saved = func_fail_buf[:]
            func_fail_buf[:] = chunk
            flush_data_batch()
            func_fail_buf[:] = saved[i+BATCH:]
            i += BATCH

    print(f"\nDone in {time.time() - t0:.0f}s")
    print(f"  total names tried:      {n_total}")
    print(f"  function renames OK:    {n_func_ok}")
    print(f"  function renames fail:  {n_func_fail}")
    print(f"  data labels OK:         {n_data_ok}")
    print(f"  data labels fail:       {n_data_fail}")
    if n_total:
        print(f"  effective hit rate:     {100.0 * (n_func_ok + n_data_ok) / n_total:.1f}%")

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rva", "name", "status"])
        w.writerows(rows)
    print(f"  audit CSV:              {OUT_CSV}")


if __name__ == "__main__":
    main()
