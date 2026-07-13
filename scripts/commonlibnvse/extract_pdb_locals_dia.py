#!/usr/bin/env python3
"""Extract per-function parameters + local variables from Xbox PDB
via Microsoft's DIA SDK (msdia140.dll), no registration required.

DIA exposes structured ``IDiaSymbol`` records that llvm-pdbutil doesn't:

  - dataKind: Local / Param / ObjectPtr / Global / Member
  - locationType: Static / TLS / RegRel / ThisRel / Enregistered / BitField
  - offset: stack frame offset (Xbox PPC)
  - type: IDiaSymbol for the variable's type

We harvest parameters + locals for every function in the global scope
and write a JSON file:

    {
      "Class::method": {
        "rva": 0x12345,
        "len": 640,
        "params": [{"name": "apMob", "type": "MobileObject *",
                    "kind": "Param", "offset": 220}, ...],
        "locals": [{"name": "pobj", "type": "int",
                    "kind": "Local", "offset": 80}, ...]
      }, ...
    }

Run:
    python extract_pdb_locals_dia.py <pdb> <out.json>
"""
from __future__ import annotations

import json
import os
import sys
import ctypes
from pathlib import Path

import comtypes
import comtypes.client


DIA_DLL = os.environ.get('BGS_DIA_DLL', '')


# ---------------------------------------------------------------------------
# COM setup (msdia140 isn't registered; use DllGetClassObject directly)
# ---------------------------------------------------------------------------

def _make_dia_source():
    if not DIA_DLL or not Path(DIA_DLL).is_file():
        raise FileNotFoundError('set BGS_DIA_DLL to msdia140.dll')
    tlb = comtypes.client.GetModule(DIA_DLL)
    DiaSource_CLSID = comtypes.GUID("{E6756135-1E65-4D17-8576-610761398C3C}")
    IClassFactory_IID = comtypes.GUID("{00000001-0000-0000-C000-000000000046}")
    dll = ctypes.OleDLL(DIA_DLL)
    dll.DllGetClassObject.argtypes = [
        ctypes.POINTER(comtypes.GUID),
        ctypes.POINTER(comtypes.GUID),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    dll.DllGetClassObject.restype = ctypes.c_long
    pcf = ctypes.c_void_p()
    dll.DllGetClassObject(ctypes.byref(DiaSource_CLSID),
                          ctypes.byref(IClassFactory_IID),
                          ctypes.byref(pcf))
    vtbl_ptr = ctypes.cast(pcf, ctypes.POINTER(ctypes.c_void_p))[0]
    vtbl = ctypes.cast(vtbl_ptr, ctypes.POINTER(ctypes.c_void_p))
    CF = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p,
                           ctypes.POINTER(comtypes.GUID),
                           ctypes.POINTER(ctypes.c_void_p))(vtbl[3])
    psrc = ctypes.c_void_p()
    iid = tlb.IDiaDataSource._iid_
    CF(pcf, None, ctypes.byref(iid), ctypes.byref(psrc))
    return ctypes.cast(psrc, ctypes.POINTER(tlb.IDiaDataSource)), tlb


# ---------------------------------------------------------------------------
# IDiaSymbol type name extraction (recursive: handles pointers, arrays,
# references, base types)
# ---------------------------------------------------------------------------

# SymTag values
_SymTag_Function   = 5
_SymTag_Data       = 7
_SymTag_UDT        = 11
_SymTag_Enum       = 12
_SymTag_PointerType = 14
_SymTag_ArrayType  = 15
_SymTag_BaseType   = 16
_SymTag_Typedef    = 17

# BaseType enum (DIA's btCondensed namespace)
_BASE_TYPE_NAMES = {
    0: 'none', 1: 'void', 2: 'char', 3: 'wchar_t', 6: 'int', 7: 'unsigned',
    8: 'float', 9: 'BCD', 10: 'bool', 13: 'long', 14: 'unsigned long',
    25: 'currency', 26: 'date', 27: 'variant', 28: 'complex', 29: 'bit',
    30: 'BSTR', 31: 'HRESULT', 32: 'char16_t', 33: 'char32_t', 34: 'char8_t',
}


def _type_name(sym) -> str:
    """Recursively reconstruct a type name from an IDiaSymbol."""
    if sym is None:
        return '?'
    try:
        tag = sym.symTag
    except Exception:
        return '?'
    if tag == _SymTag_BaseType:
        try:
            bt = sym.baseType
            length = sym.length
        except Exception:
            return '?'
        # Pick the closest C name based on baseType + length
        if bt == 6:  # int
            return {1: 'int8_t', 2: 'short', 4: 'int', 8: '__int64'}.get(length, 'int')
        if bt == 7:  # unsigned
            return {1: 'unsigned char', 2: 'unsigned short',
                    4: 'unsigned int', 8: 'unsigned __int64'}.get(length, 'unsigned')
        if bt == 8:  # float
            return {4: 'float', 8: 'double'}.get(length, 'float')
        if bt == 2:
            return 'char'
        if bt == 10:
            return 'bool'
        return _BASE_TYPE_NAMES.get(bt, '?')
    if tag == _SymTag_PointerType:
        try:
            inner = sym.type
            inner_name = _type_name(inner)
        except Exception:
            inner_name = '?'
        try:
            if sym.reference:
                return f'{inner_name}&'
        except Exception:
            pass
        return f'{inner_name}*'
    if tag == _SymTag_ArrayType:
        try:
            inner = sym.type
            count = sym.count
        except Exception:
            return '?'
        return f'{_type_name(inner)}[{count}]'
    if tag in (_SymTag_UDT, _SymTag_Enum, _SymTag_Typedef):
        try:
            return sym.name or '?'
        except Exception:
            return '?'
    # Other tags: best effort
    try:
        return sym.name or '?'
    except Exception:
        return '?'


# Map DIA dataKind values to readable strings
_DATAKIND_NAMES = {
    1: 'Local', 2: 'StaticLocal', 3: 'Param', 4: 'ObjectPtr',
    5: 'FileStatic', 6: 'Global', 7: 'Member',
    8: 'StaticMember', 9: 'Constant',
}


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    pdb_path = sys.argv[1]
    out_path = Path(sys.argv[2])

    print(f'Loading PDB via DIA SDK: {pdb_path}')
    src, tlb = _make_dia_source()
    src.loadDataFromPdb(pdb_path)
    session = src.openSession()
    gs = session.globalScope

    print('Enumerating functions...')
    enum_fn = gs.findChildren(_SymTag_Function, None, 0)
    n_total = enum_fn.Count
    print(f'  function symbols: {n_total:,}')

    entries = []
    n_with_locals = 0
    n_locals_total = 0
    n_params_total = 0
    for i in range(n_total):
        if i and i % 5000 == 0:
            print(f'  {i:,}/{n_total:,}...')
        f = enum_fn.Item(i)
        try:
            name = f.name
            rva  = f.relativeVirtualAddress
            fn_len = f.length
        except Exception:
            continue
        if not name:
            continue

        ch_enum = f.findChildren(_SymTag_Data, None, 0)
        params, locals_ = [], []
        for j in range(ch_enum.Count):
            c = ch_enum.Item(j)
            try:
                dk = c.dataKind
                lt = c.locationType
                cname = c.name or ''
                ctype = _type_name(c.type) if c.type else '?'
                coff  = c.offset
            except Exception:
                continue
            entry = {
                'name':   cname,
                'type':   ctype,
                'kind':   _DATAKIND_NAMES.get(dk, str(dk)),
                'offset': coff,
            }
            if dk in (3, 4):  # Param / ObjectPtr (this)
                params.append(entry)
            elif dk == 1:     # Local
                locals_.append(entry)
        if params or locals_:
            # Preserve every overload/local scope.  ``name`` alone is not a
            # function identity; the PDB RVA and DIA symbol id are stable
            # disambiguators within this PDB.
            try:
                sym_id = int(f.symIndexId)
            except Exception:
                sym_id = 0
            try:
                decorated = f.undecoratedName or ''
            except Exception:
                decorated = ''
            entries.append({
                'name': name,
                'rva': rva,
                'len': fn_len,
                'sym_id': sym_id,
                'identity': decorated,
                'params': params,
                'locals': locals_,
            })
            n_with_locals += 1
            n_params_total += len(params)
            n_locals_total += len(locals_)

    print(f'  functions with params/locals: {n_with_locals:,}')
    print(f'  total params:                 {n_params_total:,}')
    print(f'  total locals:                 {n_locals_total:,}')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out = {'schema': 'fnv-dia-locals-v2', 'entries': entries}
    out_path.write_text(json.dumps(out), encoding='utf-8')
    print(f'Wrote {out_path}: {out_path.stat().st_size:,} bytes')


if __name__ == '__main__':
    main()
