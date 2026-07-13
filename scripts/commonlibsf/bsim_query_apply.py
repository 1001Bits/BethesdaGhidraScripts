# @category BSim
# @runtime PyGhidra
"""Headless BSim cross-program name port.

For the currentProgram, generates BSim signatures, queries an H2 file
database, and for each function takes the highest-similarity match
from the corpus and renames the local function (if the match's source
name is a real RE-derived name -- skips FUN_*, thunk_*, _dynamic_*).

Run via pyghidra or analyzeHeadless ``-postScript bsim_query_apply.py
file:/path/to/SF_BSim 0.85 25.0``.

Args (positional):
  1. BSim DB URL (required), e.g. file:/path/to/bsim/SF_BSim
  2. min similarity threshold (values below 0.90 are refused)
  3. min significance bound (BSim's "self-significance" -- prunes tiny funcs)
  4. optional: --dry  (don't apply, just print stats)

Only renames functions whose current name starts with FUN_ or thunk_FUN_.
Preserves hand-named work.
"""
import re
import sys

# Args
args = list(getScriptArgs())
if not args or args[0].startswith('--'):
    raise RuntimeError('BSim database URL is required as argument 1')
DB_URL          = args[0]
MIN_SIMILARITY  = max(float(args[1]), 0.90) if len(args) > 1 else 0.92
MIN_SIGNIFICANCE = max(float(args[2]), 30.0) if len(args) > 2 else 40.0
DRY_RUN         = "--dry" in args
MIN_NAME_MARGIN = 0.05
target_args = [arg.split('=', 1)[1] for arg in args
               if arg.startswith('--target-sha256=')]
if not DRY_RUN and len(target_args) != 1:
    raise RuntimeError(
        'mutating BSim runs require exactly one --target-sha256=<sha256>')
if target_args:
    actual_sha = str(currentProgram.getExecutableSHA256() or '').lower()
    if len(target_args[0]) != 64 or actual_sha != target_args[0].lower():
        raise RuntimeError('BSim target executable SHA-256 mismatch')

MAX_MATCHES_PER_FUNCTION = 5

print(f"BSim DB:           {DB_URL}")
print(f"Min similarity:    {MIN_SIMILARITY}")
print(f"Min significance:  {MIN_SIGNIFICANCE}")
print(f"Dry run:           {DRY_RUN}")
print(f"Target program:    {currentProgram.getName()}")

from ghidra.features.bsim.query import BSimClientFactory, GenSignatures
from ghidra.features.bsim.query.protocol import QueryNearest
from ghidra.program.model.symbol import SourceType

NOISE_PREFIXES = ("FUN_", "thunk_FUN_", "sub_")
NOISE_SUBSTRINGS = ("_dynamic_initializer_for_", "_lambda_", "API-MS-")
PLACEHOLDER_METHOD_RE = re.compile(r'(?:^|::)(?:Func|Method|VFunc)\d+$', re.I)


def is_noise(name):
    if not name:
        return True
    if any(name.startswith(p) for p in NOISE_PREFIXES):
        return True
    if any(s in name for s in NOISE_SUBSTRINGS):
        return True
    return bool(PLACEHOLDER_METHOD_RE.search(name))


def is_overwritable(current_name):
    """We rename FUN_* / thunk_FUN_* / sub_* but never overwrite hand-named work."""
    if not current_name:
        return True
    return current_name.startswith("FUN_") or current_name.startswith("thunk_FUN_") or current_name.startswith("sub_")


_SAFE_RE = re.compile(r"[^A-Za-z0-9_<>$~?@:.-]")


def sanitize_name(name):
    parts = name.split("::")
    out = []
    for p in parts:
        p = p.strip()
        p = _SAFE_RE.sub("_", p)
        if p and p[0].isdigit():
            p = "_" + p
        out.append(p or "_")
    return "::".join(out)


_ACTIVE_DATABASE = None
_ACTIVE_GENSIG = None


def _main_impl():
    global _ACTIVE_DATABASE, _ACTIVE_GENSIG
    url = BSimClientFactory.deriveBSimURL(DB_URL)
    database = BSimClientFactory.buildClient(url, False)
    _ACTIVE_DATABASE = database
    if not database.initialize():
        err = database.getLastError()
        print(f"DB init failed: {err.message if err else '?'}")
        return

    def new_gensig():
        global _ACTIVE_GENSIG
        g = GenSignatures(False)
        g.setVectorFactory(database.getLSHVectorFactory())
        g.openProgram(currentProgram, None, None, None, None, None)
        _ACTIVE_GENSIG = g
        return g

    gensig = new_gensig()

    fm = currentProgram.getFunctionManager()
    func_count = fm.getFunctionCount()
    print(f"Total functions in program: {func_count}")

    n_scanned = 0
    n_renamed = 0
    n_below_thresh = 0
    n_no_match = 0
    n_db_err = 0
    n_already_named = 0
    n_noise_match = 0
    sample_renames = []

    monitor.setMaximum(func_count)
    monitor.setIndeterminate(False)
    funcs_iter = fm.getFunctions(True)

    # We must scan + query per function (or batch).  Process in chunks
    # to reduce overhead.
    BATCH = 50
    chunk = []
    def flush_chunk():
        nonlocal n_scanned, n_renamed, n_below_thresh, n_no_match
        nonlocal n_db_err, n_already_named, n_noise_match, gensig
        if not chunk:
            return
        # Reset the signature corpus by disposing + creating fresh; there's
        # no public clearVectors on GenSignatures.
        gensig.dispose()
        gensig = new_gensig()
        scanned_funcs = []
        for f in chunk:
            try:
                gensig.scanFunction(f)
                scanned_funcs.append(f)
            except Exception:
                pass
        query = QueryNearest()
        query.manage = gensig.getDescriptionManager()
        query.max = MAX_MATCHES_PER_FUNCTION
        query.thresh = MIN_SIMILARITY
        query.signifthresh = MIN_SIGNIFICANCE
        try:
            response = database.query(query)
        except Exception as e:
            n_db_err += len(chunk)
            chunk.clear()
            return
        if response is None:
            err = database.getLastError()
            print(f"  query returned None: {err.message if err else '?'}")
            n_db_err += len(chunk)
            chunk.clear()
            return

        # Map: source function description -> matches
        sim_iter = response.result.iterator()
        while sim_iter.hasNext():
            sim = sim_iter.next()
            base = sim.getBase()  # FunctionDescription of the local function being queried
            local_addr = base.getAddress()  # source RVA (= addr of the local function)
            local_func = fm.getFunctionAt(currentProgram.getImageBase().add(local_addr))
            if local_func is None:
                continue
            if local_func.getSymbol().getSource() in (
                    SourceType.USER_DEFINED, SourceType.IMPORTED):
                n_already_named += 1
                continue
            if not is_overwritable(local_func.getName()):
                n_already_named += 1
                continue

            # Find highest-similarity match across all source programs
            candidates = []
            sub_iter = sim.iterator()
            while sub_iter.hasNext():
                note = sub_iter.next()
                fdesc = note.getFunctionDescription()
                exerec = fdesc.getExecutableRecord()
                name = fdesc.getFunctionName()
                # Skip same-program self-matches and noisy names
                if exerec.getMd5() == currentProgram.getExecutableMD5():
                    continue
                if is_noise(name):
                    continue
                s = note.getSimilarity()
                candidates.append((s, note.getSignificance(), exerec.getMd5(),
                                   exerec.getNameExec(), name))

            if not candidates:
                # Either no match or only noise/self matches
                n_no_match += 1
                continue

            candidates.sort(reverse=True)
            best_sim, sig_score, best_md5, src_exe, src_name = candidates[0]
            if best_sim < MIN_SIMILARITY or sig_score < MIN_SIGNIFICANCE:
                n_below_thresh += 1
                continue

            # Multiple hits with the same fully qualified name corroborate
            # one another.  A close hit proposing a different name makes the
            # result ambiguous and must not mutate the program.
            competitor = next((s for s, _, _, _, n in candidates
                               if n != src_name), None)
            if competitor is not None and best_sim - competitor < MIN_NAME_MARGIN:
                n_below_thresh += 1
                continue
            consensus = len({md5 for s, _, md5, _, n in candidates
                             if n == src_name and s >= best_sim - 0.03})
            if consensus < 2 and not (best_sim >= 0.99 and sig_score >= 50.0):
                n_below_thresh += 1
                continue

            sim_score = best_sim
            new_name = sanitize_name(src_name)
            if DRY_RUN:
                n_renamed += 1
                if len(sample_renames) < 20:
                    sample_renames.append((local_func.getName(), new_name, src_exe, sim_score, sig_score))
            else:
                try:
                    # Parse namespace path
                    parts = new_name.split("::")
                    leaf = parts[-1]
                    ns_parts = parts[:-1]
                    parent = currentProgram.getGlobalNamespace()
                    sym = currentProgram.getSymbolTable()
                    for p in ns_parts:
                        sub = sym.getNamespace(p, parent)
                        if sub is None:
                            sub = sym.createNameSpace(parent, p, SourceType.ANALYSIS)
                        parent = sub
                    local_func.setParentNamespace(parent)
                    local_func.setName(leaf, SourceType.ANALYSIS)
                    n_renamed += 1
                    if len(sample_renames) < 20:
                        sample_renames.append((local_func.getName(), new_name, src_exe, sim_score, sig_score))
                except Exception as e:
                    n_db_err += 1
                    raise RuntimeError(
                        'BSim rename failed at {}: {}'.format(
                            local_func.getEntryPoint(), e))

        n_scanned += len(scanned_funcs)
        chunk.clear()

    while funcs_iter.hasNext():
        if monitor.isCancelled():
            break
        f = funcs_iter.next()
        if f.getSymbol().getSource() in (
                SourceType.USER_DEFINED, SourceType.IMPORTED):
            n_already_named += 1
            monitor.incrementProgress(1)
            continue
        if not is_overwritable(f.getName()):
            n_already_named += 1
            monitor.incrementProgress(1)
            continue
        chunk.append(f)
        if len(chunk) >= BATCH:
            flush_chunk()
            print(f"  scanned={n_scanned}  renamed={n_renamed}  already_named={n_already_named}  below_thresh={n_below_thresh}  no_match={n_no_match}  db_err={n_db_err}", flush=True)
            monitor.incrementProgress(BATCH)
    flush_chunk()

    print("\n=== Summary ===")
    print(f"  scanned:        {n_scanned}")
    print(f"  renamed:        {n_renamed}")
    print(f"  already named:  {n_already_named}")
    print(f"  below thresh:   {n_below_thresh}")
    print(f"  no match:       {n_no_match}")
    print(f"  db error:       {n_db_err}")
    print(f"  noise match:    {n_noise_match}")
    if sample_renames:
        print("\nSample renames (first 20):")
        for cur, new, exe, sim, sig in sample_renames:
            print(f"  {cur:24s}  ->  {new[:60]:60s}  ({exe[:20]}  sim={sim:.3f}  sig={sig:.1f})")

    # Resource cleanup and transaction commit/rollback are centralized in
    # ``main`` so exceptions and cancellation cannot leak handles or leave a
    # partially renamed Program.


def main():
    global _ACTIVE_DATABASE, _ACTIVE_GENSIG
    transaction = None
    commit = False
    if not DRY_RUN:
        transaction = currentProgram.startTransaction(
            'Apply identity-bound BSim names')
    try:
        _main_impl()
        if monitor.isCancelled():
            raise RuntimeError(
                'BSim application cancelled; rolling back all renames')
        commit = True
    finally:
        if _ACTIVE_GENSIG is not None:
            try:
                _ACTIVE_GENSIG.dispose()
            except Exception:
                pass
            _ACTIVE_GENSIG = None
        if _ACTIVE_DATABASE is not None:
            try:
                _ACTIVE_DATABASE.close()
            except Exception:
                pass
            _ACTIVE_DATABASE = None
        if transaction is not None:
            currentProgram.endTransaction(transaction, commit)


main()
