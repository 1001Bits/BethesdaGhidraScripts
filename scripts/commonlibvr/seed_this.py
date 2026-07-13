"""Make class-namespace functions proper `__thiscall` members (safe replacement
for the naive PopulateParameters; the correct mechanism vs. hand-typing param-0).

For each function whose parent is a GhidraClass with a `/types.h` struct, and only
when the method is not static/operator and the signature is not IMPORTED/
USER_DEFINED, set the calling convention to `__thiscall`. Ghidra then auto-inserts
a `this` param and -- because our GhidraClass namespaces are associated with their
structs -- auto-TYPES it to `Class*`. If that association does not yield a type
(`this` stays untyped), FALL BACK to setting param-0 explicitly to `Class*`
(SourceType.ANALYSIS). This extends typed-`this` coverage beyond CommonLib's
id-bound signatures (vtable-walk-named / reparented functions) so a downstream
call-graph type-propagation fixpoint has more anchors to radiate from.

It also CONVERTS members that already have an explicit `this` under the wrong
convention (__fastcall): it removes the explicit `this` and sets __thiscall so the
auto-this is the only one (no double / storage shift), since __thiscall is the
correct convention for a member. IMPORTED (PDB) functions are left alone (their
convention may be deliberate / they may be non-members).

TRANSACTION MODEL (important): the Ghidra MCP wraps each eval in its OWN outer
transaction, so any transaction this script opens is NESTED inside it. Ghidra rolls
back the ENTIRE transaction group if any nested transaction is ended with
commit=False -- so a single rolled-back function would silently discard the whole
run. Therefore this script NEVER ends a transaction with commit=False:
  * dry-run mutates NOTHING (it only classifies and counts), so there is nothing to
    roll back;
  * apply opens ONE transaction, mutates, and on the rare post-mutation verify
    failure RESTORES that function's original signature via the API (not a
    rollback), then always commits the group.
Seeds use SourceType.ANALYSIS so a human edit / CommonLib re-import outranks them.
Dry-run by default; CLVR_SEED=go to apply. Decision logic is in seed_plan.py
(unit-tested).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402

APPLY = os.environ.get('CLVR_SEED', 'dry').lower() == 'go'

import importlib.util as _ilu  # noqa: E402
_spec = _ilu.spec_from_file_location('clvr_seed_plan', os.path.join(SCRIPT_DIR, 'seed_plan.py'))
sp = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(sp)

import re as _re  # noqa: E402
_DUP = _re.compile(r'(?:_[0-9A-Fa-f]{6,})+$')


def _static_map():
    """{ 'Class::Method': is_static } from CommonLib SYMBOLS (sd[2])."""
    out = {}
    try:
        with open(IMPORT_PATH) as f:
            for line in f:
                if line.startswith('SYMBOLS = '):
                    for s in json.loads(line[len('SYMBOLS = '):]):
                        if s.get('t') == 'func' and s.get('sd'):
                            out[s['n']] = bool(s['sd'][2])
                    break
    except Exception:
        pass
    return out


def run():
    from ghidra.program.model.symbol import SymbolType, SourceType
    from ghidra.program.model.data import CategoryPath, Pointer, FunctionDefinitionDataType
    from ghidra.program.model.listing import ParameterImpl
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    fm = cp.getFunctionManager()
    gns = cp.getGlobalNamespace()
    static_of = _static_map()

    via_thiscall = via_fallback = converted = anomalies = skipped = errors = 0
    dry_set = dry_convert = 0
    reasons = {}
    sample = []

    def _base(tn):
        return (tn or '').replace(' ', '').rstrip('*').rstrip('64').rstrip('*')

    # Apply runs inside ONE transaction that ALWAYS commits (a nested commit=False
    # would poison the MCP's outer transaction and discard everything). Dry-run
    # opens no transaction and mutates nothing.
    tx = cp.startTransaction('thiscall-seed') if APPLY else None
    try:
        for f in fm.getFunctions(True):
            parent = f.getParentNamespace()
            if parent is gns or parent.getSymbol() is None:
                continue
            if parent.getSymbol().getSymbolType() != SymbolType.CLASS:
                continue
            cls = parent.getName()
            leaf = _DUP.sub('', f.getName())
            struct = dtm.getDataType(CategoryPath('/types.h'), cls)
            conv = f.getCallingConventionName()
            src = f.getSignatureSource()
            srcname = src.name() if hasattr(src, 'name') else str(src)
            is_static = static_of.get(cls + '::' + leaf, False)
            ps0 = f.getParameters()
            # A struct-RETURNING member has a hidden __return_storage_ptr__ in RCX
            # and its real `this` is param-1, not param-0. Removing param-0 here
            # would drop the return pointer, so skip -- needs return-type RE first.
            if ps0 and (ps0[0].getName() == '__return_storage_ptr__'
                        or (ps0[0].isAutoParameter()
                            and 'RETURN' in str(ps0[0].getAutoParameterType()))):
                skipped += 1
                reasons['struct-return-ptr'] = reasons.get('struct-return-ptr', 0) + 1
                continue
            dt0 = ps0[0].getDataType() if ps0 else None
            has_this = dt0 is not None and isinstance(dt0, Pointer) and not sp.is_untyped(dt0.getName())

            action, reason = sp.should_set_thiscall(
                struct is not None, leaf, conv, srcname, is_static, has_this)

            # A 'convert' whose explicit param-0 is typed to a DIFFERENT class is
            # almost certainly a real first argument, not a misconventioned `this`
            # (e.g. TESImageSpace::SetBaseData(BaseData*)). Removing it would
            # corrupt the signature, so skip rather than convert. param-0 typed to
            # the owning class (or untyped) is a genuine `this`.
            if action == 'convert' and _base(dt0.getName()) != cls:
                skipped += 1
                reasons['this-type-mismatch'] = reasons.get('this-type-mismatch', 0) + 1
                continue

            if action == 'skip':
                skipped += 1
                reasons[reason] = reasons.get(reason, 0) + 1
                continue

            if not APPLY:
                # Dry-run: classify only, never mutate (nothing to roll back).
                if action == 'convert':
                    dry_convert += 1
                else:
                    dry_set += 1
                if len(sample) < 15:
                    sample.append('%s::%s  [DRY %s]' % (cls, leaf, action))
                continue

            kind = None
            tag = ''
            try:
                if action == 'convert':
                    before_n = len(ps0)
                    orig_sig = FunctionDefinitionDataType(f, False)  # snapshot to restore
                    f.removeParameter(0)                  # drop explicit this...
                    f.setCallingConvention('__thiscall')  # ...auto-this replaces it
                    ps = f.getParameters()
                    d0 = ps[0].getDataType() if ps else None
                    if (len(ps) == before_n and d0 is not None
                            and isinstance(d0, Pointer) and not sp.is_untyped(d0.getName())):
                        kind, tag = 'convert', 'convert->%s' % d0.getName()
                    else:
                        # Restore in-API (NOT a transaction rollback, which would
                        # poison the whole group) and count as an anomaly.
                        ApplyFunctionSignatureCmd(
                            f.getEntryPoint(), orig_sig, SourceType.USER_DEFINED).applyTo(cp, monitor)  # noqa: F821
                        kind, tag = 'anomaly', 'convert-ANOMALY(%d->%d)' % (before_n, len(ps))
                else:
                    f.setCallingConvention('__thiscall')
                    ps = f.getParameters()
                    d0 = ps[0].getDataType() if ps else None
                    if d0 is not None and isinstance(d0, Pointer) and not sp.is_untyped(d0.getName()):
                        kind, tag = 'thiscall', 'thiscall->%s' % d0.getName()
                    else:
                        ptr = dtm.getPointer(struct, 8)
                        if ps:
                            ps[0].setDataType(ptr, SourceType.ANALYSIS)
                            ps[0].setName('this', SourceType.ANALYSIS)
                        else:
                            f.insertParameter(0, ParameterImpl('this', ptr, cp), SourceType.ANALYSIS)
                        kind, tag = 'fallback', 'fallback->%s*' % cls
            except Exception as e:
                kind, tag = 'error', str(e)[:60]

            if kind == 'convert':
                converted += 1
            elif kind == 'thiscall':
                via_thiscall += 1
            elif kind == 'fallback':
                via_fallback += 1
            elif kind == 'anomaly':
                anomalies += 1
            else:
                errors += 1
            if len(sample) < 15 and kind in ('convert', 'thiscall', 'fallback'):
                sample.append('%s::%s  [%s]' % (cls, leaf, tag))
    finally:
        if tx is not None:
            cp.endTransaction(tx, True)   # always commit the group; never poison it

    print('thiscall-set (%s): %s' % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN (no changes made)'))
    if APPLY:
        print('  gap-fill: auto-this=%d, explicit-fallback=%d' % (via_thiscall, via_fallback))
        print('  convert (remove this + __thiscall): %d   ANOMALIES(restored)=%d' % (converted, anomalies))
        print('  errors=%d' % errors)
    else:
        print('  would set __thiscall (gap-fill): %d' % dry_set)
        print('  would convert (remove this + __thiscall): %d' % dry_convert)
    print('  skipped=%d' % skipped)
    print('  skip reasons: %s' % reasons)
    for s in sample:
        print('   ' + s)


run()
