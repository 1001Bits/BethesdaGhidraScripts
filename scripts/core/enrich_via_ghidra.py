"""Improve a per-binary vtable layout CSV with names + fingerprints from Ghidra.

For every slot in the input CSV that doesn't already have a fingerprint,
calls ``get_function_signature`` against the running GhidrAssistMCP server
to fetch the function's name + masked byte signature.  Writes back to the
CSV incrementally (every N successful fetches), so a crash or
interruption never loses more than that batch.

Designed to run as an overnight job via Monitor: emits one progress
event per ``--checkpoint-every`` slots, and a final summary line on
exit.  Re-running the same command resumes where it left off because
slots that already have a non-empty fingerprint are skipped.

Usage::

    python enrich_via_ghidra.py \
        --in scripts/commonlibf4/refs/f4_vr_vtables.csv \
        --program Fallout4VR.exe \
        --out scripts/commonlibf4/refs/f4_vr_vtables.csv \
        --checkpoint-every 100

For sub-class scoping::

    python enrich_via_ghidra.py ... --classes Actor,PlayerCharacter,TESObjectREFR
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from typing import Optional, Set
from urllib import request, error

# Allow running from any cwd as long as scripts/core is on sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from vtable_layout import load_csv, save_csv, BinaryLayout

DEFAULT_MCP_URL = 'http://localhost:8080/mcp'


class MCPClient:
    """Tiny streamable-HTTP MCP client (stdlib only, no deps)."""
    def __init__(self, url: str = DEFAULT_MCP_URL):
        self.url = url
        self.session_id: Optional[str] = None
        self._id = 0
        self._failures_in_a_row = 0

    def _post(self, body: dict, timeout: float = 30.0) -> dict:
        data = json.dumps(body).encode('utf-8')
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
        }
        if self.session_id:
            headers['Mcp-Session-Id'] = self.session_id
        req = request.Request(self.url, data=data, headers=headers, method='POST')
        with request.urlopen(req, timeout=timeout) as resp:
            sid = resp.headers.get('Mcp-Session-Id')
            if sid and not self.session_id:
                self.session_id = sid
            raw = resp.read().decode('utf-8', errors='replace')
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith('data: '):
                line = line[len('data: '):]
            if line.startswith('{'):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return {}

    def initialize(self) -> None:
        self._id += 1
        self._post({
            'jsonrpc': '2.0', 'id': self._id, 'method': 'initialize',
            'params': {
                'protocolVersion': '2024-11-05', 'capabilities': {},
                'clientInfo': {'name': 'enrich_via_ghidra', 'version': '1'},
            },
        })
        self._post({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def reconnect(self) -> None:
        """Force a new session (used after a server restart or transport error)."""
        self.session_id = None
        self.initialize()

    def get_function_signature(self, addr: int, program_name: str,
                                  timeout: float = 15.0) -> tuple:
        """Returns (name, fingerprint).  Both '' on miss."""
        self._id += 1
        try:
            resp = self._post({
                'jsonrpc': '2.0', 'id': self._id, 'method': 'tools/call',
                'params': {
                    'name': 'get_function_signature',
                    'arguments': {
                        'function_name_or_address': '0x{:X}'.format(addr),
                        'program_name': program_name,
                    },
                },
            }, timeout=timeout)
        except (error.URLError, error.HTTPError, ConnectionError, OSError) as e:
            self._failures_in_a_row += 1
            if self._failures_in_a_row > 5:
                # Stale session; try once to reconnect
                try:
                    self.reconnect()
                    self._failures_in_a_row = 0
                except Exception:
                    pass
            return '', ''
        self._failures_in_a_row = 0
        result = resp.get('result', {})
        content = result.get('content', [])
        if not content:
            return '', ''
        text = content[0].get('text', '') or ''
        # Strip the "[Context] Operating on: ..." prefix Ghidra prepends
        text = re.sub(r'\[Context\][^\n]*\n+', '', text)
        # Body is JSON like {"name":"X","address":"Y","signature":"48 8B..."}
        # but may also be a plain error string like "Function not found".
        try:
            obj = json.loads(text.strip())
            return obj.get('name', '') or '', obj.get('signature', '') or ''
        except json.JSONDecodeError:
            return '', ''


def _checkpoint(layout: BinaryLayout, out_path: str) -> int:
    n = save_csv(layout, out_path)
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--in', dest='inp', required=True, help='input vtable layout CSV')
    ap.add_argument('--out', required=True, help='output CSV (safe to match --in)')
    ap.add_argument('--program', required=True, help='Ghidra program filename (Fallout4VR.exe, etc.)')
    ap.add_argument('--classes', help='comma-separated class names to limit scope; default = all')
    ap.add_argument('--checkpoint-every', type=int, default=200,
                    help='write to disk + emit progress line every N successful fetches')
    ap.add_argument('--mcp-url', default=DEFAULT_MCP_URL)
    ap.add_argument('--label', default='enriched', help='binary label for the loaded layout')
    ap.add_argument('--skip-named', action='store_true',
                    help='also skip slots that already have a func_name even without fingerprint')
    args = ap.parse_args()

    layout = load_csv(args.inp, args.label)
    if not layout.classes:
        print(f'ERROR: no classes in {args.inp}', file=sys.stderr)
        return 2

    scope: Optional[Set[str]] = None
    if args.classes:
        scope = {c.strip() for c in args.classes.split(',') if c.strip()}

    # Build worklist
    worklist = []
    for cls_name in sorted(layout.classes):
        if scope and cls_name not in scope:
            continue
        cv = layout.classes[cls_name]
        for slot, e in cv.slots.items():
            if e.fingerprint:
                continue  # already improved -- resume
            if args.skip_named and e.func_name and not e.func_name.startswith('FUN_'):
                continue
            worklist.append((cls_name, slot, e))
    total = len(worklist)
    if total == 0:
        print(f'Nothing to do: every slot already has a fingerprint in {args.inp}')
        return 0
    print(f'Worklist: {total:,} slots to fetch '
          f'(across {len(scope) if scope else len(layout.classes)} class(es))',
          flush=True)

    client = MCPClient(args.mcp_url)
    try:
        client.initialize()
    except (error.URLError, OSError) as e:
        print(f'ERROR: cannot reach Ghidra MCP at {args.mcp_url}: {e}', file=sys.stderr)
        return 3

    done = 0
    enriched_names = 0
    enriched_fps = 0
    misses = 0
    started = time.time()
    last_chk = started

    try:
        for cls_name, slot, e in worklist:
            name, fp = client.get_function_signature(e.func_addr, args.program)
            if fp:
                e.fingerprint = fp
                enriched_fps += 1
            if name and (not e.func_name or e.func_name.startswith('FUN_')):
                e.func_name = name
                enriched_names += 1
            if not name and not fp:
                misses += 1
            done += 1

            if done % args.checkpoint_every == 0:
                _checkpoint(layout, args.out)
                now = time.time()
                rate = args.checkpoint_every / max(now - last_chk, 0.001)
                eta_s = (total - done) / max(rate, 0.001)
                last_chk = now
                print(f'  [{done:,}/{total:,}] +{enriched_fps:,} fps  '
                      f'+{enriched_names:,} names  miss={misses:,}  '
                      f'rate={rate:.1f}/s  eta={eta_s/60:.1f}m',
                      flush=True)
    except KeyboardInterrupt:
        print('\nInterrupted -- checkpointing partial progress...', flush=True)
    finally:
        _checkpoint(layout, args.out)
        elapsed = time.time() - started
        print(f'\nDONE in {elapsed/60:.1f}m: '
              f'{done}/{total} processed; +{enriched_fps:,} fingerprints, '
              f'+{enriched_names:,} new names, {misses:,} misses',
              flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
