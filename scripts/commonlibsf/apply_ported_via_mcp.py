#!/usr/bin/env python3
"""Apply ``refs/sf116_ported_names.csv`` to the currently active SF binary
in user's main Ghidra via MCP batch_rename.

Use this instead of ``apply_ported_to_sf116.py`` (pyghidra against the
BethesdaGhidraScripts headless project) when you want the names in the
live Ghidra GUI session at MCP host:8080.

Assumes ``program_name="Starfield.exe"`` resolves to the right binary
(check via list_binaries first if multiple are loaded).
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
from html import unescape
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MCP_URL  = os.environ.get("BGS_MCP_URL", "http://localhost:8080/mcp")
PROGRAM  = os.environ.get("BGS_MCP_PROGRAM", "Starfield.exe")
CSV_PATH = os.environ.get(
    "BGS_SF_PORTED_CSV", str(SCRIPT_DIR / "refs" / "sf116_ported_names.csv"))
BATCH    = 80

# Same sanitiser as the pyghidra path: Ghidra rejects names with spaces,
# backticks, commas, parens, single quotes.  Replace with '_'.
_SAFE_RE = re.compile(r"[^A-Za-z0-9_<>$~?@:.-]")


def sanitize_full_name(name: str) -> str:
    """Sanitize a fully-qualified name; keep '::' separators intact."""
    parts = name.split("::")
    cleaned = []
    for p in parts:
        p = p.strip()
        p = _SAFE_RE.sub("_", p)
        if p and p[0].isdigit():
            p = "_" + p
        cleaned.append(p or "_")
    return "::".join(cleaned)


# ---------------------------------------------------------------------
#  MCP plumbing
# ---------------------------------------------------------------------

def _http_post(body, headers, timeout=60):
    req = urllib.request.Request(
        MCP_URL, data=json.dumps(body).encode(),
        method="POST", headers=headers,
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", errors="replace")
        return text, dict(resp.headers)


def _parse(text):
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:].strip())
    return json.loads(text)


def init_session():
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    _, hdrs = _http_post({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp_apply", "version": "1"},
        },
    }, headers, timeout=15)
    sid = next((v for k, v in hdrs.items() if k.lower() == "mcp-session-id"), None)
    if not sid:
        raise RuntimeError("no Mcp-Session-Id in init response")
    _http_post({"jsonrpc": "2.0", "method": "notifications/initialized"},
               {**headers, "Mcp-Session-Id": sid}, timeout=10)
    return sid


def call(sid, tool, args, timeout=120):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Mcp-Session-Id": sid,
    }
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": args}}
    text, _ = _http_post(body, headers, timeout=timeout)
    return _parse(text)


def text_of(r):
    try:
        return r["result"]["content"][0]["text"]
    except Exception:
        return ""


# ---------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------

def main():
    raise SystemExit(
        "DISABLED: the MCP bridge does not expose an executable SHA-256 "
        "attestation or atomic rollback for batch_rename. Use "
        "apply_ported_to_sf116.py, which validates the content-hashed "
        "evidence sidecar and exact Ghidra Program identity.")
    if not os.path.isfile(CSV_PATH):
        print(f"ERROR: CSV missing: {CSV_PATH}"); sys.exit(2)
    print(f"MCP {MCP_URL}; program: {PROGRAM}")
    print(f"CSV: {CSV_PATH}; batch size: {BATCH}\n")

    sid = init_session()
    print(f"Session: {sid}")

    # Read CSV
    rows = []
    with open(CSV_PATH, encoding="utf-8") as fh:
        r = csv.DictReader(fh)
        for row in r:
            try:
                va = int(row["target_va"], 16)
            except (KeyError, ValueError):
                continue
            name = sanitize_full_name(row["name"])
            rows.append((va, name))
    print(f"Loaded {len(rows)} ported entries")

    n_total = 0
    n_ok = 0
    n_fail = 0
    sample_fails = []
    t0 = time.time()

    for i in range(0, len(rows), BATCH):
        chunk = rows[i:i + BATCH]
        renames = [{
            "target_type": "function",
            "identifier": f"FUN_{va:09x}",
            "new_name":   name,
        } for va, name in chunk]
        # Per-batch retry: large batches can blow Ghidra's response budget;
        # retry once with a fresh session on timeout.
        attempt = 0
        while True:
            attempt += 1
            try:
                r = call(sid, "batch_rename", {
                    "program_name": PROGRAM,
                    "renames": renames,
                }, timeout=300)
                break
            except (TimeoutError, OSError) as exc:
                if attempt >= 3:
                    print(f"  giving up after {attempt} timeouts on batch {i//BATCH + 1}: {exc}")
                    r = {"result": {"content": [{"text": "{\"succeeded\":0,\"failed\":" + str(len(chunk)) + "}"}]}}
                    break
                print(f"  retry {attempt} after {type(exc).__name__} on batch {i//BATCH + 1}")
                time.sleep(2)
                sid = init_session()
        text = text_of(r)
        # Strip leading "[Context] ..." preamble before JSON body
        idx = text.find("{")
        try:
            payload = json.loads(text[idx:]) if idx >= 0 else {}
        except Exception:
            payload = {}
        succ = int(payload.get("succeeded", 0))
        fail = int(payload.get("failed", 0))
        n_ok += succ
        n_fail += fail
        n_total += len(chunk)
        # Capture a handful of failure reasons for diagnosis
        for res in payload.get("results", [])[:5]:
            if not res.get("success") and len(sample_fails) < 8:
                sample_fails.append((res.get("identifier", "?"), res.get("new_name", "?")[:60],
                                      res.get("message", "")[:120]))
        elapsed = time.time() - t0
        rate = n_total / max(elapsed, 0.001)
        eta = (len(rows) - n_total) / max(rate, 0.001)
        print(f"  batch {i//BATCH + 1}/{(len(rows) + BATCH - 1)//BATCH}: "
              f"+{succ} ok / +{fail} fail   total: {n_total}/{len(rows)}  "
              f"ok={n_ok}  fail={n_fail}  rate={rate:.1f}/s  eta={eta:.0f}s", flush=True)

    print(f"\nDone in {time.time() - t0:.0f}s")
    print(f"  total processed:  {n_total}")
    print(f"  ok / renamed:     {n_ok}")
    print(f"  failed:           {n_fail}")
    if sample_fails:
        print("\nSample failures (first 8):")
        for ident, name, msg in sample_fails:
            print(f"  {ident}  -> {name}  : {msg}")


if __name__ == "__main__":
    main()
