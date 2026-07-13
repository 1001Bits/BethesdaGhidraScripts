#!/usr/bin/env python3
"""Phase 1 of the SF 1.7 -> SF 1.16.236 byte-sig naming port.

Streams the user's loaded Starfield 1.7 Ghidra database via MCP to
build a corpus of (name, rva, prologue_bytes) for every non-noise named
function.

Output: ``scripts/commonlibsf/refs/sf17_named_corpus.csv`` with columns
``rva,name,prologue_hex``.  This is the source side of the cross-
version byte-signature port; Phase 2 runs the matcher locally against
the 1.16.236 PE file.

Tunables at the top.  Default settings are conservative serial calls
because Ghidra's MCP server is single-threaded for many ops.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MCP_URL    = os.environ.get("BGS_MCP_URL", "http://localhost:8080/mcp")
PROGRAM    = os.environ.get("BGS_MCP_PROGRAM", "Starfield.exe")
OUT_CSV    = os.environ.get(
    "BGS_SF17_CORPUS", str(SCRIPT_DIR / "refs" / "sf17_named_corpus.csv"))
PAGE_SIZE  = 200       # functions per get_functions call
PROLOGUE_N = 48        # bytes per function to capture
PROGRESS_EVERY = 250   # log every N captured rows
MAX_FUNCS  = None      # set to int to cap (e.g. 100 for smoke test)

# Noise filters identical to apply_xml_names_to_sf17.py
NOISE_PREFIXES = ("FUN_", "thunk_FUN_", "sub_")
NOISE_SUBSTRINGS = (
    "_dynamic_initializer_for_",
    "_lambda_",
    "API-MS-",
)

FUNC_LINE_RE = re.compile(
    r'^- (?P<name>[^@]+?)\s+@\s+(?P<addr>[0-9a-fA-F]+)\s+\((?P<params>\d+)\s+params\)'
)


def is_noise(name: str) -> bool:
    if any(name.startswith(p) for p in NOISE_PREFIXES):
        return True
    return any(s in name for s in NOISE_SUBSTRINGS)


# ---------------------------------------------------------------------
#  MCP plumbing
# ---------------------------------------------------------------------

def _http_post(body: dict, headers: dict, timeout: int = 30):
    req = urllib.request.Request(
        MCP_URL, data=json.dumps(body).encode(),
        method="POST", headers=headers,
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", errors="replace")
        return text, dict(resp.headers)


def _parse_response(text: str) -> dict:
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:].strip())
    return json.loads(text)


def init_session() -> str:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    body = {
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "extract_sf17", "version": "1"},
        },
    }
    _, hdrs = _http_post(body, headers, timeout=15)
    sid = None
    for k, v in hdrs.items():
        if k.lower() == "mcp-session-id":
            sid = v; break
    if not sid:
        raise RuntimeError("MCP init: no Mcp-Session-Id in response headers")
    _http_post(
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {**headers, "Mcp-Session-Id": sid},
        timeout=10,
    )
    return sid


def call(sid: str, tool: str, args: dict, timeout: int = 30) -> dict:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Mcp-Session-Id": sid,
    }
    body = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }
    text, _ = _http_post(body, headers, timeout=timeout)
    return _parse_response(text)


def text_of(resp: dict) -> str:
    try:
        return resp["result"]["content"][0]["text"]
    except Exception:
        return ""


# ---------------------------------------------------------------------
#  Function listing + byte fetch
# ---------------------------------------------------------------------

def list_functions_page(sid: str, offset: int, limit: int, pattern: str = "::") -> list[tuple[str, int]]:
    """Page through named functions.  Default pattern '::' filters to C++
    namespaced names server-side -- skips ~150k FUN_* entries that come
    first in the function listing.  Non-namespaced RE names (eg singleton
    'Main', 'BGSDefaultObjectManager') are picked up by a second pass.
    """
    args = {
        "program_name": PROGRAM,
        "limit": limit,
        "offset": offset,
    }
    if pattern:
        args["pattern"] = pattern
    r = call(sid, "get_functions", args, timeout=60)
    text = text_of(r)
    if not text or "error" in text.lower()[:80]:
        return []
    out = []
    for line in text.splitlines():
        m = FUNC_LINE_RE.match(line.strip())
        if m:
            out.append((m.group("name").strip(), int(m.group("addr"), 16)))
    return out


HEX_RE = re.compile(r'^[0-9a-f]{8}\s+((?:[0-9a-f]{2}\s){1,16})\s*\|')


def fetch_bytes(sid: str, rva: int, n: int) -> bytes | None:
    """Return up to ``n`` bytes at address ``rva`` from MCP get_data_at."""
    addr_hex = "0x{:x}".format(rva)
    r = call(sid, "get_data_at", {
        "program_name": PROGRAM,
        "address": addr_hex,
        "len": n,
    }, timeout=30)
    text = text_of(r)
    if not text:
        return None
    out = bytearray()
    # Hexdump format example:
    #   140001000  48 89 5c 24 08 48 89 6c 24 10  ...   |H.\$.H.l$.....|
    for line in text.splitlines():
        m = HEX_RE.match(line.strip().lower())
        if m:
            for b in m.group(1).split():
                out.append(int(b, 16))
                if len(out) >= n:
                    return bytes(out[:n])
    return bytes(out) if out else None


# ---------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------

def main():
    raise SystemExit(
        "DISABLED: this disconnected MCP extractor cannot attest the active "
        "Program SHA-256 and may publish partial evidence. Use an exact "
        "Ghidra XML/.bytes export with port_sf17_to_sf116.py instead.")
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    print(f"MCP {MCP_URL}; program: {PROGRAM}")
    print(f"PAGE_SIZE={PAGE_SIZE}  PROLOGUE_N={PROLOGUE_N}  MAX={MAX_FUNCS}\n")

    sid = init_session()
    print(f"Session: {sid}")

    # Sanity check
    r = call(sid, "get_function_statistics", {"program_name": PROGRAM}, timeout=15)
    print("Stats:", text_of(r).splitlines()[2:7])

    n_pages = 0
    n_seen = 0
    n_noise = 0
    n_kept = 0
    n_byte_fail = 0
    rows: list[tuple[str, str, str]] = []
    t0 = time.time()
    offset = 0
    last_progress_t = t0

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["rva", "name", "prologue_hex"])

        while True:
            page = list_functions_page(sid, offset, PAGE_SIZE)
            if not page:
                break
            n_pages += 1
            for name, rva in page:
                n_seen += 1
                if is_noise(name):
                    n_noise += 1
                    continue
                bs = fetch_bytes(sid, rva, PROLOGUE_N)
                if not bs or len(bs) < 8:
                    n_byte_fail += 1
                    continue
                hex_str = bs.hex()
                w.writerow(["0x{:x}".format(rva), name, hex_str])
                n_kept += 1

                if n_kept % PROGRESS_EVERY == 0:
                    now = time.time()
                    rate = n_kept / max(now - t0, 0.001)
                    eta_s = (45000 - n_kept) / max(rate, 0.001)
                    print(f"  kept={n_kept:6d}  seen={n_seen:6d}  noise={n_noise:6d}  byte_fail={n_byte_fail}  rate={rate:.1f}/s  eta={eta_s/60:.0f}m")
                    last_progress_t = now

                if MAX_FUNCS and n_kept >= MAX_FUNCS:
                    break
            if MAX_FUNCS and n_kept >= MAX_FUNCS:
                break
            offset += PAGE_SIZE
            fh.flush()

    print(f"\nDone in {(time.time() - t0):.0f}s")
    print(f"  pages walked:     {n_pages}")
    print(f"  functions seen:   {n_seen}")
    print(f"  noise filtered:   {n_noise}")
    print(f"  byte fetch fail:  {n_byte_fail}")
    print(f"  rows written:     {n_kept}")
    print(f"  output:           {OUT_CSV}")


if __name__ == "__main__":
    main()
