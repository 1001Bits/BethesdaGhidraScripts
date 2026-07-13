"""Dump per-binary vtable layouts via the GhidrAssistMCP HTTP API.

Run once per binary version when a new patch ships.  Output is a CSV file
(``vtable_layout`` format) checked into the repo under
``<commonlib>/refs/<version>_vtables.csv``; the build pipeline reads
those CSVs and never talks to Ghidra at build time.

Usage (CLI)::

    python -m vtable_dumper \
        --program SkyrimSE.exe \
        --label se \
        --out scripts/commonlibsse/refs/se_vtables.csv

Or programmatically::

    from vtable_dumper import dump_binary
    layout = dump_binary('Fallout4VR.exe', 'f4_vr',
                         class_list=['Actor', 'PlayerCharacter', ...],
                         mcp_url='http://localhost:8080/mcp')
    from vtable_layout import save_csv
    save_csv(layout, 'scripts/commonlibf4/refs/f4_vr_vtables.csv')

This module talks to the MCP server using stdlib only (urllib + json) so
the dumper can run in any Python 3 environment.  Long-running ``classes``
calls use the server's async task queue with polling.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from typing import Dict, Iterable, List, Optional, Tuple
from urllib import request, error

from vtable_layout import BinaryLayout, ClassVtable, SlotEntry, save_csv

DEFAULT_MCP_URL = 'http://localhost:8080/mcp'


# ---------------------------------------------------------------------------
# Minimal MCP streamable-HTTP client
# ---------------------------------------------------------------------------

class _MCPClient:
    def __init__(self, url: str = DEFAULT_MCP_URL):
        self.url = url
        self.session_id: Optional[str] = None
        self._id = 0

    def _post(self, body: dict, expect_text: bool = True, timeout: float = 30.0) -> dict:
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
        # The server emits SSE-style "data: {...}" lines on tools/call.
        # Strip prefixes if present.
        chunks = []
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith('data: '):
                chunks.append(line[len('data: '):])
            elif line.startswith('{'):
                chunks.append(line)
        if not chunks:
            return {}
        # Parse the last well-formed JSON chunk (final result for the id)
        for chunk in reversed(chunks):
            try:
                return json.loads(chunk)
            except json.JSONDecodeError:
                continue
        return {}

    def initialize(self) -> None:
        self._id += 1
        self._post({
            'jsonrpc': '2.0', 'id': self._id, 'method': 'initialize',
            'params': {
                'protocolVersion': '2024-11-05', 'capabilities': {},
                'clientInfo': {'name': 'vtable_dumper', 'version': '1'},
            },
        })
        # Notify initialized
        self._post({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def call_tool(self, name: str, arguments: dict, timeout: float = 30.0) -> str:
        """Call a Ghidra MCP tool, returning its text content (or '')."""
        self._id += 1
        resp = self._post({
            'jsonrpc': '2.0', 'id': self._id, 'method': 'tools/call',
            'params': {'name': name, 'arguments': arguments},
        }, timeout=timeout)
        result = resp.get('result', {})
        content = result.get('content', [])
        if content and isinstance(content, list):
            return content[0].get('text', '') or ''
        return ''

    def call_async(self, name: str, arguments: dict, poll_interval: float = 4.0,
                    max_wait: float = 600.0) -> str:
        """Call a tool that returns a task_id and poll until COMPLETED."""
        text = self.call_tool(name, arguments)
        m = re.search(r'Task ID: ([0-9a-f-]+)', text)
        if not m:
            return text  # synchronous result
        task_id = m.group(1)
        deadline = time.time() + max_wait
        while time.time() < deadline:
            time.sleep(poll_interval)
            status_text = self.call_tool('get_task_status', {'task_id': task_id})
            if 'Status: COMPLETED' in status_text or 'COMPLETED' in status_text and 'Task' in status_text:
                return status_text
            if 'Status: FAILED' in status_text or 'Status: CANCELLED' in status_text:
                raise RuntimeError('Ghidra task {} failed: {}'.format(task_id, status_text[:500]))
        raise TimeoutError('Ghidra task {} did not complete in {}s'.format(task_id, max_wait))


# ---------------------------------------------------------------------------
# Vtable extraction from Ghidra responses
# ---------------------------------------------------------------------------

# Match Ghidra's class get_info output:
# "private static vtable vtable VTABLE_<Class> @ <addr> -> vtable[N]->FuncName, vtable[N]->..."
_VTABLE_HEADER_RE = re.compile(
    r'VTABLE_(.+?) @ (?:0x)?([0-9a-fA-F]+) -> '
)
_SLOT_ENTRY_RE = re.compile(
    r'vtable\[(\d+)\]->(.+?)(?=,\s*vtable\[|\r?\n|$)')


def _parse_vtable_response(text: str, class_filter: Optional[str] = None
                            ) -> List[Tuple[str, int, List[Tuple[int, str]]]]:
    """Yield (vtable_name, vtable_addr, [(slot, func_name), ...]) groups."""
    out = []
    for hdr in _VTABLE_HEADER_RE.finditer(text):
        vname = 'VTABLE_' + hdr.group(1)
        vaddr = int(hdr.group(2), 16)
        # Body: from end-of-header until next 'private static' or EOF
        start = hdr.end()
        end_m = text.find('private static', start)
        body = text[start:end_m if end_m >= 0 else len(text)]
        slots = [(int(m.group(1)), m.group(2).strip())
                 for m in _SLOT_ENTRY_RE.finditer(body)]
        if class_filter and class_filter not in vname:
            continue
        out.append((vname, vaddr, slots))
    return out


def _strip_context(text: str) -> str:
    """Remove '[Context] Operating on: ...' prefix Ghidra prepends to every response."""
    return re.sub(r'\[Context\][^\n]*\n+', '', text)


def _get_function_signature(client: _MCPClient, addr_or_name: str,
                              program_name: str) -> Tuple[str, int, str]:
    """Return (func_name, address, fingerprint), or empty values on miss."""
    text = client.call_tool('get_function_signature', {
        'function_name_or_address': addr_or_name,
        'program_name': program_name,
    })
    text = _strip_context(text)
    # Body is JSON like {"name":"X","address":"Y","signature":"48 8B..."}
    try:
        obj = json.loads(text.strip())
        raw_addr = str(obj.get('address', '') or '')
        match = re.search(r'(?:0x)?([0-9a-fA-F]+)$', raw_addr)
        func_addr = int(match.group(1), 16) if match else 0
        return (obj.get('name', '') or '', func_addr,
                obj.get('signature', '') or '')
    except json.JSONDecodeError:
        return '', 0, ''


def dump_binary(program_name: str, label: str,
                 class_list: Optional[Iterable[str]] = None,
                 mcp_url: str = DEFAULT_MCP_URL,
                 only_primary_vtable: bool = True,
                 fetch_fingerprints: bool = True,
                 verbose: bool = True) -> BinaryLayout:
    """Dump every class's primary vtable from one binary.

    Args:
      program_name: Ghidra program filename ('SkyrimSE.exe', 'Fallout4VR.exe', ...)
      label: short tag used in the output ('se', 'svr', 'f4_ng', ...)
      class_list: explicit list of class names to dump.  If None, dumps every
                  class known to Ghidra's RTTI (slow -- thousands of classes).
      only_primary_vtable: skip non-primary inheritance vtables (those with
                            _<N> suffix like VTABLE_PlayerCharacter_3).
      fetch_fingerprints: query each slot's function for its byte signature
                           (the cross-version matcher's strongest signal).
                           Doubles dump time but makes shift maps far more
                           reliable.
    """
    client = _MCPClient(mcp_url)
    client.initialize()

    layout = BinaryLayout(binary_label=label, binary_path=program_name)

    if class_list is None:
        # Fetch the full class list once
        text = _strip_context(client.call_async('classes', {
            'action': 'list', 'program_name': program_name,
        }))
        # Format: "ClassName" lines, optionally prefixed
        class_list = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('---') or line.startswith('Total'):
                continue
            # crude filter: drop obvious non-class lines
            m = re.match(r'(?:[\s\-\*]+)?([A-Za-z_][A-Za-z_0-9:<>]+)', line)
            if m:
                class_list.append(m.group(1))

    seen = set()
    for cls in class_list:
        if cls in seen:
            continue
        seen.add(cls)
        if verbose:
            print('  dump {} / {}'.format(label, cls))
        try:
            text = _strip_context(client.call_async('classes', {
                'action': 'get_info', 'class_name': cls,
                'program_name': program_name,
            }))
        except Exception as e:
            if verbose:
                print('    skip ({}): {}'.format(cls, e))
            continue

        groups = _parse_vtable_response(text, class_filter=cls)
        if not groups:
            continue

        primary_name = 'VTABLE_' + cls
        selected = ([group for group in groups if group[0] == primary_name]
                    if only_primary_vtable else groups)
        for vname, vaddr, slot_entries in selected:
            is_primary = vname == primary_name
            cv = layout.upsert(
                cls, vaddr, vtable_id=vname,
                subobject_offset=0, is_primary=is_primary)
            for slot, func_name in slot_entries:
                fp = ''
                func_addr = 0
                if func_name:
                    fn_name, func_addr, fetched_fp = _get_function_signature(
                        client, func_name, program_name)
                    if fetch_fingerprints:
                        fp = fetched_fp
                    if fn_name:
                        func_name = fn_name
                cv.add(SlotEntry(slot=slot, func_addr=func_addr,
                                 func_name=func_name, fingerprint=fp))

    return layout


def _cli() -> int:
    p = argparse.ArgumentParser(description='Dump per-binary vtable layout via Ghidra MCP')
    p.add_argument('--program', required=True, help='Ghidra program filename')
    p.add_argument('--label', required=True, help='short label (se, svr, f4_ng, ...)')
    p.add_argument('--out', required=True, help='output CSV path')
    p.add_argument('--mcp-url', default=DEFAULT_MCP_URL)
    p.add_argument('--classes', help='comma-separated class list; default = all')
    p.add_argument('--no-fingerprints', action='store_true',
                   help="skip per-slot function signature fetch (faster, less accurate matching)")
    args = p.parse_args()

    class_list = None
    if args.classes:
        class_list = [c.strip() for c in args.classes.split(',') if c.strip()]
    try:
        layout = dump_binary(
            program_name=args.program, label=args.label,
            class_list=class_list, mcp_url=args.mcp_url,
            fetch_fingerprints=not args.no_fingerprints,
        )
    except (error.URLError, ConnectionError) as e:
        print('ERROR: cannot reach Ghidra MCP at {}: {}'.format(args.mcp_url, e), file=sys.stderr)
        return 2

    rows = save_csv(layout, args.out)
    print('Wrote {} rows for {} class(es) to {}'.format(
        rows, len(layout.classes), args.out))
    return 0


if __name__ == '__main__':
    sys.exit(_cli())
