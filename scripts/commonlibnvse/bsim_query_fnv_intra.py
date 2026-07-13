"""Intra-binary BSim query for FNV.

For each FUN_* / thunk_FUN_ / LAB_ function in FalloutNV.exe, query
the FNV_BSim DB (populated with the same binary's NAMED functions)
and rename if a high-similarity match exists with a real name.

Unlike commonlibsf/bsim_query_apply.py (which skips same-MD5 self-
matches because it does cross-program queries), this script:
  - Allows same-MD5 matches (we're querying FNV against itself)
  - Skips same-VA self-matches (a function shouldn't rename itself)
  - Skips FUN_* / thunk_FUN_ / LAB_ matches (only real-name matches count)

Args (set via globals before running this script via eval_python):
  MIN_SIMILARITY  = 0.85    (0.0-1.0)
  MIN_SIGNIFICANCE = 25.0
  DRY_RUN = False
  OUT_CSV = path to write (RVA|name|sim|sig) pairs
"""
import os
import re
from ghidra.features.bsim.query import BSimClientFactory, GenSignatures
from ghidra.features.bsim.query.protocol import QueryNearest
from ghidra.program.model.symbol import SourceType


DB_URL = os.environ.get("BGS_FNV_BSIM_DB", "")
MIN_SIMILARITY = 0.85
MIN_SIGNIFICANCE = 25.0
DRY_RUN = True
# Same-binary nearest-neighbour results are not independent evidence: compiler
# boilerplate and tiny wrappers frequently match unrelated named functions.
# Keep this tool quarantined for diagnostics unless an analyst explicitly
# opts in for a reviewed experiment.  Even then DRY_RUN remains the default.
ALLOW_UNSAFE_INTRA_BSIM = False
OUT_CSV = os.environ.get("BGS_FNV_BSIM_OUT", "")


NOISE_PREFIXES = ("FUN_", "thunk_FUN_", "sub_", "LAB_")
NOISE_SUBSTRINGS = ("_dynamic_initializer_for_", "_lambda_", "API-MS-")
_SAFE_RE = re.compile(r"[^A-Za-z0-9_<>$~?@:.-]")


def is_noise(name):
    if not name:
        return True
    if any(name.startswith(p) for p in NOISE_PREFIXES):
        return True
    return any(s in name for s in NOISE_SUBSTRINGS)


def is_overwritable(current_name):
    if not current_name:
        return True
    return any(current_name.startswith(p) for p in NOISE_PREFIXES)


def sanitize(name):
    out = []
    for p in name.split("::"):
        p = p.strip()
        p = _SAFE_RE.sub("_", p)
        if p and p[0].isdigit():
            p = "_" + p
        out.append(p or "_")
    return "::".join(out)


def main():
    if not ALLOW_UNSAFE_INTRA_BSIM:
        print("Intra-binary BSim is quarantined: set "
              "ALLOW_UNSAFE_INTRA_BSIM=True for diagnostic export only.")
        return
    if not DB_URL or not OUT_CSV:
        print("Set BGS_FNV_BSIM_DB and BGS_FNV_BSIM_OUT explicitly.")
        return
    if not DRY_RUN:
        print("Refusing automatic same-binary BSim renames; use the CSV as a "
              "review queue and apply independently corroborated matches.")
        return
    url = BSimClientFactory.deriveBSimURL(DB_URL)
    db = BSimClientFactory.buildClient(url, False)
    if not db.initialize():
        print("DB init failed:", db.getLastError().message if db.getLastError() else "?")
        return

    fm = currentProgram.getFunctionManager()
    image_base = currentProgram.getImageBase()
    n_total = fm.getFunctionCount()
    print(f"Functions: {n_total}")

    BATCH = 100
    chunk = []
    n_scanned = n_renamed = n_below = n_no = n_named = n_err = 0
    matches_log = []

    def flush():
        nonlocal n_scanned, n_renamed, n_below, n_no, n_named, n_err
        if not chunk:
            return
        g = GenSignatures(False)
        g.setVectorFactory(db.getLSHVectorFactory())
        g.openProgram(currentProgram, None, None, None, None, None)
        for f in chunk:
            try:
                g.scanFunction(f)
            except Exception:
                pass
        q = QueryNearest()
        q.manage = g.getDescriptionManager()
        q.max = 10
        q.thresh = MIN_SIMILARITY
        q.signifthresh = MIN_SIGNIFICANCE
        try:
            resp = db.query(q)
        except Exception as e:
            n_err += len(chunk)
            chunk.clear()
            g.dispose()
            return
        if resp is None:
            n_err += len(chunk)
            chunk.clear()
            g.dispose()
            return

        it = resp.result.iterator()
        while it.hasNext():
            sim = it.next()
            base = sim.getBase()
            local_addr = base.getAddress()
            local_func = fm.getFunctionAt(image_base.add(local_addr))
            if local_func is None:
                continue
            if not is_overwritable(local_func.getName()):
                n_named += 1
                continue

            best = None
            best_sim = -1.0
            sub_it = sim.iterator()
            while sub_it.hasNext():
                note = sub_it.next()
                fdesc = note.getFunctionDescription()
                # Skip same-VA self-match
                if fdesc.getAddress() == base.getAddress():
                    continue
                name = fdesc.getFunctionName()
                if is_noise(name):
                    continue
                s = note.getSimilarity()
                if s > best_sim:
                    best_sim = s
                    best = (name, s, note.getSignificance())

            if best is None:
                n_no += 1
                continue
            if best_sim < MIN_SIMILARITY:
                n_below += 1
                continue

            src_name, sim_score, sig_score = best
            new_name = sanitize(src_name)
            matches_log.append((local_addr.getOffset(), local_func.getName(),
                                 new_name, sim_score, sig_score))
            if not DRY_RUN:
                try:
                    parts = new_name.split("::")
                    leaf = parts[-1]
                    parent = currentProgram.getGlobalNamespace()
                    sym = currentProgram.getSymbolTable()
                    for p in parts[:-1]:
                        sub = sym.getNamespace(p, parent)
                        if sub is None:
                            sub = sym.createNameSpace(parent, p, SourceType.ANALYSIS)
                        parent = sub
                    local_func.setParentNamespace(parent)
                    local_func.setName(leaf, SourceType.ANALYSIS)
                    n_renamed += 1
                except Exception:
                    n_err += 1
            else:
                n_renamed += 1
        n_scanned += len(chunk)
        chunk.clear()
        g.dispose()

    iter_ = fm.getFunctions(True)
    while iter_.hasNext():
        f = iter_.next()
        if not is_overwritable(f.getName()):
            n_named += 1
            continue
        chunk.append(f)
        if len(chunk) >= BATCH:
            flush()
            if n_scanned % 1000 == 0:
                print(f"  scanned={n_scanned}  candidates={n_renamed}  "
                      f"below={n_below}  no_match={n_no}", flush=True)
    flush()

    print(f"\n=== Summary ===")
    print(f"  scanned (FUN_*): {n_scanned}")
    print(f"  rename candidates: {n_renamed} (DRY={DRY_RUN})")
    print(f"  below thresh:   {n_below}")
    print(f"  no match:       {n_no}")
    print(f"  preserved (already named): {n_named}")
    print(f"  errors: {n_err}")

    # Write CSV
    IB = currentProgram.getImageBase().getOffset()
    with open(OUT_CSV, 'w', encoding='utf-8') as f:
        f.write("# BSim intra-FNV matches: 0xRVA|src_name|similarity|significance\n")
        for va, oldname, newname, s, sig in sorted(matches_log):
            rva = va  # local_addr is already RVA per BSim convention
            f.write(f"0x{rva:08X}|{newname}|{s:.3f}|{sig:.1f}\n")
    print(f"Wrote {OUT_CSV}: {len(matches_log)} matches")
    db.close()


main()
