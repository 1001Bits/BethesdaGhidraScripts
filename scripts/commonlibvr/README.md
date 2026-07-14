# commonlibvr — CommonLibVR (alandtse) multi-runtime source

Additive source module that imports Skyrim SE/AE/VR types from **`alandtse/CommonLibVR`**
instead of `powerof3/CommonLibSSE`. Nothing in `scripts/commonlibsse/` is modified; this lives
alongside it, exactly like `commonlibf4`/`commonlibsf`/`commonlibnvse`.

## Why a separate source
`powerof3/CommonLibSSE` has **no VR layouts** — BGS parses Skyrim VR using the SE define set and
only attaches VR offsets afterward (`commonlibsse/parse_commonlib_types.py`, `svr` config). So VR
*structs/vtables* are approximated as SE. `alandtse/CommonLibVR` is a true multi-runtime codebase
that models the real VR divergence (larger structs, shifted vtables), so it yields **accurate VR
layouts**.

## Dependency
This pipeline reads CommonLibVR's headers from `extern/CommonLibVR` (branch `ng`) --
clone <https://github.com/alandtse/CommonLibVR> there, alongside the sibling
`CommonLib*` checkouts. A directory junction to an existing local checkout works
just as well, and `CLVR_RE_DIR` overrides the location outright.

## The two layers

### 1. Types / vtables / layouts — a CONFIG change (validated)
CommonLibVR selects layout by runtime via `REL/Common.h`:
- exactly one `ENABLE_SKYRIM_{SE|AE|VR}=1` → `EXCLUSIVE_SKYRIM_{SE|AE|VR}` (concrete layout)
- two-or-more with VR → `SKYRIM_CROSS_VR` (strips runtime-divergent members; **never use for parsing**)

So the per-runtime parse is just the right define, isolated:

| version | define | resolves to |
|---|---|---|
| se | `-DENABLE_SKYRIM_SE=1` | EXCLUSIVE_SKYRIM_SE / FLAT |
| ae | `-DENABLE_SKYRIM_AE=1` | EXCLUSIVE_SKYRIM_AE / FLAT |
| svr | `-DENABLE_SKYRIM_VR=1` | EXCLUSIVE_SKYRIM_VR |

The umbrella `RE/Skyrim.h` self-primes (`#include "SKSE/Impl/PCH.h"`), so no extra prelude is needed.
The VR build pulls two deps the powerof3 path never did:
- **openvr** — real headers at `extern/CommonLibVR/extern/openvr/headers` (`-I`)
- **DirectXTK `SimpleMath.h`** — via `RE/State.h` (use BGS's stub/shadow pattern; a raw vcpkg include
  conflicts with the PCH macros — confirmed 20 errors)

**Validated** (clang 20.1.7, `--target=x86_64-pc-windows-msvc -std=c++23`):
`RE::NiAVObject` → `sizeof=0x138`, `flags @ 0x10C` under `ENABLE_SKYRIM_VR` — matches CommonLibVR's
VR `static_assert` exactly. (Flat is `0x110`.)

`scripts/commonlibsse/parse_commonlib_types.py` is import-safe (no top-level side effects), so the
type layer can be a **thin wrapper**: import it, override `COMMONLIB_INCLUDE`/`VERSIONS`, append the
openvr + DirectXTK `-I` args, reuse `core/clang_types`.

### 2. Addresses — additive `reloc_parser.py` + `main()` (built, validated)
CommonLibVR's address model differs from powerof3 in two spots; everything else is reused:

| item | powerof3 | CommonLibVR | how we handle it |
|---|---|---|---|
| functions | `RELOCATION_ID(se, ae)` | same (2-arg) | reuse base header/src scanners verbatim |
| VR func offset | `vr_db[se_id]` | same | reuse; src scanner extended to attach `vr_db[se_id]` |
| RTTI/VTABLE | `REL::ID` + `#ifdef SKYRIM_SUPPORT_AE` | `REL::VariantID(se, ae, vr_literal)`, single section | **new** scanner `_scan_variant_rtti_vtable_file` |
| `Offset::` ns | `Offsets.h` | none | offset maps empty (no-op) |
| VR DB source | meh321 | **`vr_address_tools/version-1-4-15-0.csv`** (from `database.csv`) | `BGS_VR_CSV` env, falls back to `addresslibrary/sse/` |

`reloc_parser.py` loads the powerof3 base by explicit path under a distinct module name
(`commonlibsse_reloc_parser`) to avoid the shared-basename `sys.modules` collision, reuses its
`_ContextTracker` + function scanners, and replaces only the RTTI/VTABLE scanner for the
`VariantID` form. `parse_commonlib_types.py main()` builds the SE/AE/VR address DBs, collects
symbols, attaches `si`/`ai` ids, and feeds them to the same `base.run_version`.

**Validated** (svr, address layer in isolation): 16540 labels (7687 RTTI + 410 NiRTTI + 8443
VTABLE) + 1161 functions = **17701 symbols, VR coverage 17149 (97%)**. Spot-checks:
`RTTI_AlchemyItem` → VR `0x1ed6d60` (the literal third `VariantID` arg); `ActorMagicCaster::
CheckAttachCastingArt` → VR `vr_db[33403]` from `RELOCATION_ID(33403, 34185)`.

Run: `python parse_commonlib_types.py svr` (full, with addresses) or `... svr --types-only` (fast,
layouts only).

### 3. Apply into Ghidra — conflict-aware, non-destructive (`conflict_report.py` + `apply_enrich.py`)
The generated import is clobber-by-default (REPLACE handler, creates parallel duplicate types in
`/CommonLibSSE/RE` alongside the program's real `/types.h` types). `apply_enrich.py` instead classifies
every struct against the live program (`conflict_report.classify`, single source of truth) and acts per
status, only ever *writing* existing types via `dtm.replaceDataType` (rewires refs, **leaves function
signatures intact**):

| status | action | why |
|---|---|---|
| NEW | create in `/types.h` | no existing type |
| MATCH / GEN_EMPTY | reuse existing | size match / CommonLib opaque |
| STUB_UPGRADE / EXTENDS | replace (fill / superset) | provably safe |
| DIVERGENT | replace (generated = validated VR layout) | existing is SE-sized/auto-extracted |
| HANDCURATED | **protect** | clean (PDB/hand) member names |
| VFTABLE_LOSS | **protect** | replace would drop a vtable pointer |
| SUSPICIOUS | **protect** | size ratio ≥4× ⇒ leaf-name collision (e.g. `RE::BSJobs::JobList`[8] vs `/types.h/JobList`[216]) |
| EMBED_BASE | **protect** | existing uses compositional base embedding |

Matching is namespace-aware (category → namespace; `/types.h`+pdb = RE/global) to avoid false collisions
like `RE::Color` vs `DirectX::SimpleMath::Color`. `apply_enrich.py` is DRY_RUN by default (writes a plan
CSV); `CLVR_APPLY=go` applies in one transaction. Sampling confirmed generated matches CommonLibVR's own
`static_assert(sizeof)`/`STATIC_ASSERT_SIZE(...,VR,...)` for every divergent case checked.

### 4. Inheritance representation — embed vs flatten (`embed_structs`)
By default the parser **embeds** each base as a struct member at its `pdb_bases` offset (compositional,
e.g. `NiNode { _base: NiAVObject; children; }`) rather than flattening base fields into every derived.
clang's `-fdump-record-layouts` supplies exact base offsets (incl. multiple inheritance, EBO, vbase) —
already parsed into `pdb_bases` — so no ABI layout logic is reimplemented. Where MSVC reuses a base's
**tail padding** (a sibling base/field starts before `base_off + base.size`), a **trimmed** base variant
(`X__embed_<size>`) is embedded instead, because a full-size embedded member is atomic and overlapping it
silently clears it (verified in Ghidra). Any base that can't be cleanly embedded falls back to a
flattened (byte-accurate) layout per struct, so field data is never lost. `CLVR_EMBED=0` reverts to pure
flatten. The primary base at offset 0 carries the shared vtable, so the derived's injected `__vftable@0`
is dropped (covered by the base member).

Implementation detail: this needs `SKIP_NESTED_BASE_FIELDS=True` in `clang_types` (set by the wrapper)
so `_parse_layouts_with_bases` records only **direct** bases + **own** fields (clang's layout dump nests
the full base tree under each record). `has_vtable` is detected from the whole layout block so the skip
does not suppress it; `dsize` is captured for the trim length.

**Tradeoff (inherent to embedding):** C++ shares the 8-byte vptr slot between base and derived, and a
Ghidra struct field can hold only one type, so a derived class's vptr ends up typed (through the `_base`
chain) to the **root** vtable struct, not the most-derived one. Per-class vtable structs and virtual-
function naming are unaffected (they go through the `VTABLE_*` symbols/addresses, not the field type) —
only the vptr field's *type* shows root methods. `CLVR_EMBED=0` (flatten) types the vptr to the
most-derived vtable instead, at the cost of no base composition. Pick per preference.

### 5. Improve phases (`CLVR_PHASE`) — run order for a full import
`apply_enrich.py` dispatches on the `CLVR_PHASE` env var. Run it inside Ghidra (exec the file,
or via the MCP eval) against the target program **in this order**; each is improve-safe and
idempotent, and each is **dry-run by default** with its own `*=go` flag to write:

| order | `CLVR_PHASE` | what it does | apply flag |
|---|---|---|---|
| 1 | `types` (default) | create/replace types per `conflict_report.classify` | `CLVR_APPLY=go` |
| 2 | `symbols` | label + name FUN_/sub_ functions, apply CommonLib sigs, vtable-slot + fallback naming. Upgrades auto-inferred (DEFAULT/ANALYSIS) sigs; never clobbers USER_DEFINED/IMPORTED | (writes in-txn) |
| 3 | `sigconflict` | where a CommonLib sig **differs** from an existing USER_DEFINED/IMPORTED one, decompile both ways and keep the cleaner (`decompile_score`) | `CLVR_SIGCONFLICT=go` |
| 4 | `classes` | reparent flat `Class::Method` names into namespaces, create/promote GhidraClass per class, re-point straggler vftable fields | `CLVR_CLASSES=go` |
| 5 | `thiscall` | normalize class members to proper `__thiscall` (delegates to `seed_this.py`): convert the `__fastcall`-with-explicit-`this` the symbols phase applies into `__thiscall` (auto-typed `this`), and seed a typed `this` on the non-id-bound tail | `CLVR_SEED=go` |

Phase 5 **must** follow phase 4 — the GhidraClass↔struct association `classes` creates is what lets
`__thiscall` auto-type `this`. The symbols phase deliberately leaves members as
`__fastcall`-with-explicit-`this` (a typed `this` helps phase 3's decompile scoring, and the class
association doesn't exist yet at symbols time); phase 5 is where that becomes the correct convention.
See §10 for the mechanism, the `this-type-mismatch`/struct-return guards, and the
nested-transaction rule. Phase 3 writes a decision CSV (`<import>.sigconflict.csv`);
`CLVR_SIGCONFLICT_MAX` caps the count. Phase 4 `CLVR_CLASSES_MAX` caps reparents. Pure decision logic is unit-tested
(`pytest scripts/commonlibvr/` — `apply_plan`, `decompile_score`); pre-commit runs ruff + these.

The program is modified **in-memory only** — the MCP/transaction layer can't save, so
**File→Save in Ghidra** after the phases to persist. Validated on SkyrimVR.exe: phase 3 chose
CommonLib in 429/913 conflicts (incl. 175/260 PDB overrides); phase 4 reparented ~14.3k
functions and produced ~2k GhidraClasses.

### 6. Version Tracking — exact cross-version matches from ids (`version_track.py`)
CommonLib's `RELOCATION_ID(se, ae)` / `VariantID(se, ae, vr)` give each symbol's exact address in
every runtime; the generated SYMBOLS carry them as `s`/`a`/`v` offsets. `version_track.py` turns
that ground truth into Ghidra Version Tracking ACCEPTED matches — far more precise than the
heuristic correlators (which match by bytes/instructions and drift onto adjacent functions):

- **SEED** — for a source address with no accepted match, inject the exact `src->dst` manual match
  and accept it (type Function for `func`, Data for labels).
- **AUDIT** — where a source already has an accepted match to a *different* dst, that is a
  correlator error (or a stale id); record it to `<import>.vt_audit.csv` for review. Never
  auto-changed.

Run inside Ghidra with the SE/AE/VR programs and the VT sessions open; dry-run by default,
`VT_APPLY=go` to seed. Decision logic is in `vt_plan.py` (unit-tested). Validated: seeded ~16.2k
(SE↔AE) + ~15.5k (SE↔VR) exact matches into the manual set (which had ~93 before), and surfaced
436 correlator conflicts to audit. Most conflicts were adjacent-function drift where the id mapping
is authoritative.

### 7. Write-back detection — Ghidra -> CommonLib (`commonlib_writeback.py`)
The pipeline imports CommonLib INTO Ghidra; this closes the other half of the loop by reporting
what the live program knows that CommonLib does not, so RE/PDB knowledge can flow back to the
canonical source. Per CommonLib function symbol it compares the live Ghidra name against
CommonLib's at that address (`commonlib_delta`, unit-tested):
- **NAME_DELTA** — Ghidra has a trusted (USER_DEFINED/IMPORTED) name whose base differs. Either a
  naming-convention difference to reconcile (`GetCurrentWeapon` vs PDB `GetCurrentlyEquippedWeapon`)
  or, when wildly different (`IsValid` vs `ResizeWindow`), a sign CommonLib's address for that
  runtime is wrong -- a `database.csv` bug to verify against the binary.
- **MISSING_IN_GHIDRA** — CommonLib named it but Ghidra is still generic: a gap in our own apply.

Read-only; writes `<import>.writeback.csv` with cross-version ids so each row is locatable in
CommonLib. The classes-phase `_<addr>` overload-disambiguation suffix is stripped before comparing.
Signature deltas are out of v1 (need cross-representation normalization; the `SIG_DELTA` path is
tested and ready). Validated: VR 143 / SE 155 / AE 281 name deltas.

`writeback_aggregate.py` (plain Python, no Ghidra) joins the three reports by symbol name and
triages each by HOW the disagreement is distributed across the runtimes it is *mapped* in
(presence comes from the generated SYMBOLS, so MATCH is distinguished from ABSENT = not yet
mapped). CommonLib is iterative -- a symbol may start SE/AE-only and gain a VR offset later -- so:
- **RUNTIME_SPECIFIC** (delta in some mapped runtimes, MATCH in others) names the suspect runtime
  vs the trusted ones. `suspect=vr` with SE MATCH (AE often ABSENT) is the prime case: an
  iteratively-added VR offset that may point at the wrong function -> verify against the binary /
  `vr_address_tools` database.csv.
- **RECONCILE** (delta in EVERY mapped runtime) -> one CommonLib name fix.
- **APPLY_GAP** -> our apply left it generic (often an AE-program intake gap).
Run: `python writeback_aggregate.py [import_dir] [out_csv]`. Validated: 263 RUNTIME_SPECIFIC /
79 RECONCILE / 90 APPLY_GAP, with the AE PDB intake the systematically noisiest source.

### 8. Discovery cycle — bootstrap Ghidra to find net-new RE (`commonlib_discover.py`)
The point of the bootstrap is not to re-export what CommonLib already knows -- it is to let
Ghidra's OWN tools discover what CommonLib doesn't, *because* the typed scaffold gives them anchors
to reason from. `commonlib_discover.py` drives Ghidra's decompiler dataflow inference
(`FillOutStructureHelper`, the engine behind "Auto Fill Out Structure") to infer field types at the
offsets CommonLib still marks `unkNN`:

- For each `/types.h` struct with unknown pointer-sized fields, it samples functions whose param-0 is
  that type (i.e. anything improvement gave a typed `this` -- not just CommonLib's id-bound symbols,
  which is what scales the yield), runs read-only structure inference, and records the inferred type
  at each `unk` offset. `discover_plan` ranks them (a named type beats a size-only `ulonglong`;
  consensus across functions raises confidence).
- **NON-DESTRUCTIVE**: `processStructure` returns an in-memory `Structure`; nothing is applied to the
  program (asserted: data-type count unchanged). It only writes `<import>.discovered_fields.csv`.
  That CSV's `observed_in` column carries the use-site provenance — the functions whose dataflow
  revealed each field — for EVERY field (not just the review queue). `crossver.py export` joins it
  into `<import>.resolved_fields.csv` (its own `observed_in` column), so a later semantic-naming pass
  jumps straight to a witness function instead of re-hunting construction sites.

This closes the loop and **compounds**: feed the discovered fields back to CommonLib, re-import, and
the now-typed field lets the decompiler propagate one level deeper next pass. Validated on SE: 60
classes / 92 functions -> 171 candidate fields, 142 high-confidence (e.g. `TESObjectCELL +0xB0 ->
TESForm*` x3, `CombatInventory +0xB0 -> BSTArray<TESForm*>`, `UI3DSceneManager +0x10 ->
NiPointer<BSShaderAccumulator>`) -- and only 60 of 217 unknown-bearing classes had typed methods this
pass, so coverage grows every cycle. Knobs: `CLVR_DISCOVER_PER_CLASS`, `CLVR_DISCOVER_FOLLOW=1`
(follow into callees, deeper + slower), `CLVR_DISCOVER_MAX_CLASSES`.

### 9. Scripts vs LLM-in-the-loop — division of labor
The **scripts are the focus**: the deterministic, reproducible artifact others run. They decide
everything rule-expressible — layouts, addresses, type/conflict classification, signature
application, and the bulk of conflict resolution and class population. Re-running them on a fresh
program reproduces that work.

A residual tail is genuine **judgment** the scripts can't reliably call: e.g. signature conflicts
where the two decompiles score within the margin, or dispositions that need reading the actual
code. There each script stops at a **defensible default** (keep the incumbent) and emits a
**decision log** (`<import>.sigconflict.csv`) so the picks are auditable. An LLM connected to
Ghidra — directly, or by reading that log plus both decompilations — can finish those cases by
reading the code. That step improves on the heuristic but is **not bit-reproducible**.

Working rules:
- **Fix the script when the failure is rule-expressible.** Fold the lesson back in so the
  deterministic core gets better over time (e.g. "an undeclared incoming-register param is a
  decisive signature defect" became a weight in `decompile_score`; static-method `this` handling
  became a generator fix).
- **Use the LLM for the irreducible-judgment tail**, and treat its applied corrections as
  authoritative. Do **not** regenerate over them with a script just to be "pure" — the decision
  logs keep LLM picks auditable, and a pure re-run can be *worse* (the heuristic is the fallback,
  not the ground truth).

### 10. `this`-seeding + call-graph type propagation (`seed_this.py`, `propagate.py`)
Two driving forces that widen the typed surface so 8 and the decompiler have more anchors.

**`seed_this.py` — make class methods proper `__thiscall`.** For every function in a GhidraClass
namespace with a `/types.h` struct, set the calling convention to `__thiscall`; Ghidra then
auto-inserts a `this` param and — because the class namespace is associated with its struct —
auto-*types* it to `Class*`. Members that already carry an explicit `this` under the wrong
convention (`__fastcall`) are *converted*: drop the explicit `this`, set `__thiscall`, so the
auto-`this` is the only one (no double / register-storage shift). A `this`-type-mismatch guard
skips a `convert` whose param-0 is typed to a *different* class (a real first arg, e.g.
`TESImageSpace::SetBaseData(BaseData*)`), and a struct-return guard skips members with a hidden
`__return_storage_ptr__`. `seed_plan.py` holds the decision logic (unit-tested). IMPORTED (PDB)
signatures are left alone. Applied + verified across all three: VR `__thiscall` 174→9908, AE →10237,
SE →10978.

**`propagate.py` — let the anchors radiate.** Decompile a function, read the types the decompiler's
dataflow inferred, and where it found a *concrete named* type (struct/class pointer) for a slot the DB
still has *generic*, commit just that slot; re-enqueue the function's callers+callees so the gain
flows one edge out; iterate to fixpoint / `MAX_ROUNDS`. It is **filtered + surgical, deliberately NOT
`HighFunctionDBUtil.commitParamsToDatabase`**: measuring the whole-prototype commit on this codebase
showed it is *net-negative* — the decompiler proposes `void` returns (clobbering an honest
`undefined`) and `longlong` params (false precision) far more than real struct pointers (~1 in 35
class methods), and the API is all-or-nothing per function. So only `safe_refinement()` slots
(generic → concrete named) are applied, per-slot via `setDataType`/`setReturnType`. `propagate_plan.py`
holds the rule + the empirical rationale (unit-tested). VR dry-run: of 184 *non-protected* class
methods (most now carry authoritative CommonLib signatures, correctly off-limits), 14 concrete
slot-gains — e.g. `BSOpenVR::GetHMDDeviceType ret → HMDDeviceType`, `GFxZlibSupport::Func3 p1 →
Stream*`. Dry-run by default (`CLVR_PROP=go` to apply) writes `<import>.propagated.csv`.

**Transaction gotcha (applies to any write-back driver here).** The Ghidra MCP wraps each `eval` in
its *own* outer transaction, so a script's per-function transactions are *nested* inside it — and
Ghidra rolls back the **entire** group if any nested transaction ends with `commit=False`. A driver
that rolled back individual anomalies therefore silently discarded its whole run while reporting
"APPLIED". The rule both drivers now follow: **never end a transaction with `commit=False`** — dry-run
mutates nothing (so there is nothing to roll back), and apply opens **one** transaction that is
**always committed**, restoring any bad change in-API (`ApplyFunctionSignatureCmd`) rather than via
rollback.

### 11. Population cycle — close the loop inside Ghidra (`populate_cycle.py`)
The forward import, the widening (10), the propagation (10) and the discovery (8) are stages; this
**orchestrates them into a convergent loop that never leaves Ghidra**, and measures when it is done.
The missing edge was that `commonlib_discover.py` was read-only — it found field types but never wrote
them back, so nothing compounded. It now has an **apply mode** (`CLVR_DISCOVER_APPLY=go`): for each
high-confidence *named* field it fills the unknown `/types.h` slot with that concrete same-size type
(`should_apply_field`) and renames the field off its `unk*/pad*` prefix (`unk50 → fld50`, offset digits
kept for write-back traceability) so it leaves the discovery surface. A field typed in cycle N is an
anchor the decompiler propagates from in cycle N+1.

`populate_cycle.py` runs, each cycle: **thiscall → propagate → discover+apply**, then snapshots four
coverage metrics — `__thiscall` members and concrete-typed params (up), still-unknown vs concrete
`/types.h` **bytes** (struct coverage is byte-based, not component count: carving a typed field out of a
larger `undefined` run fragments the remainder into more components, so a *count* can rise on a clean
apply — a false regression; bytes are conserved) — and computes one `progress` scalar. It stops at the
**fixpoint** (`0 ≤ progress < MIN_GAIN`, diminishing returns) and treats **negative progress as a
REGRESSION, not convergence** — a stage made the program worse, stop and inspect. **Per-stage skip:**
coverage is measured after each stage, and once a stage moves no metric it is marked done and skipped in
later cycles — `thiscall`/`propagate` converge in cycle 1, so only `discover` keeps re-running (without
this, AE re-decompiled propagate's ~7800-function seed every cycle for ~11 min / 0 gain). Decision logic
is in `populate_plan.py` (unit-tested); export back to CommonLib is deliberately out of scope (drive the
live program to a stable, maximally-populated state first). Dry-run prints a coverage snapshot;
`CLVR_CYCLE=go` runs the loop. Writes `<import>.coverage.csv`.

The coverage meter earned its keep twice. First it caught a metric keyed on field *name* (applied fields
kept their `unk` name, so progress read as a regression). Then, fixed to bytes, it caught a *real*
fragmentation artifact in the component count. VR: applies ~14 fields (`CombatGroup +0x50 → AITimer`,
`BSSynchronizedClipGenerator +0xE0 → hkQsTransform`) then converges. SE is richer — cycle 1 applies **41
fields** (`TESObjectCELL +0xB0 → TESForm*`, `TES +0x2A8 → NavMeshInfoMap*`, `BGSCameraShot +0xA8 →
NiPointer<NiAVObject>`), converging in 3 cycles. Non-destructive: only fills unknown slots with same-size
types, never creates a type, one always-committed transaction (never `commit=False`).

### 12. Optional LLM review — break the convergence plateau (`apply_review.py`)
The automated cycle (11) converges against rules it can express; what's left sits in skip buckets,
chiefly **`generic-size-only`** — offsets where the decompiler is sure a pointer-sized field EXISTS
(many functions agree) but could only infer a size, not a semantic type. Naming those is a judgement
call, so the loop hands them to a human/LLM via the established decision-log pattern (§9):

- **`commonlib_discover.py` emits `<import>.review_queue.csv`** every run: one row per
  size-only-consensus field (`is_review_worthy` — `named` False and `total ≥ 2` observers; single weak
  hits are left for more discovery first), strongest-evidence first, with the *observing functions* as
  the reviewer's leads (`observed_in`) and a blank `decision_type`.
- **A human/LLM fills `decision_type`** with a concrete Ghidra type (or `skip`) after reading those
  functions — the irreducible judgement tail.
- **`apply_review.py` writes the decisions back** (`CLVR_REVIEW_APPLY=go`): resolves the type string
  (pointer/`*64` decoration handled, `/types.h` preferred), and fills the slot under the same
  non-destructive guards as the automated apply (unknown slot only, exact size only) — but with no
  confidence/generic filter, because the human IS the authority. Renamed `fld*`, commented
  `clvr-review`. `review_plan.py` holds the pure decisions (`is_review_worthy`/`parse_decision`,
  unit-tested).

Why it matters: each resolved field is a **new anchor**, so the next cycle discovers more from it —
review raises the ceiling, then the cycle converges to a higher fixpoint. The loop is
**cycle → fill queue → `apply_review` → re-cycle**, optional and zero-cost if unused. It also produces
exactly the human-grade, authoritative fields you'd export to CommonLib first. Validated on VR: a
40-class discover queued **19** size-only fields (e.g. `BGSSaveLoadManager +0xA0`, observed in
`Load_Impl`/`GetSaveVersion`); `apply_review` resolves `TESForm *`, reports unresolved type names, and
rejects size-mismatches — all before writing.

### 13. Cross-version field propagation (`crossver.py`) — one runtime's win populates all three
The population cycle (11) and review (12) resolve fields per-program; this carries a field
resolved in ONE runtime to the SAME field in the others (SE <-> AE <-> VR). The three share
CommonLib's class layout but at DIFFERENT Ghidra offsets (VR structs are larger, fields shift); what
is stable is the **CommonLib offset encoded in the field name** (`unkNN`/`padNN`, and the population
apply's `fldNN` keeps those digits). So propagation keys on the NAME, not the raw offset.

Two modes (`CLVR_XVER`): **export** writes a runtime's resolved `/types.h` fields
(`is_resolved` — offset-keyed name + concrete type) to `<import>.resolved_fields.csv`; **apply** reads
every sibling export, reconciles per `(class, cl_offset)` across runtimes (`pick_best_type` — consensus
wins, conflicts flagged), and fills the current runtime's still-unknown field at that CommonLib offset.
Run export on all three, then apply on all three. Decision logic is in `crossver_plan.py` (unit-tested:
`field_key`, `is_resolved`/`is_unknown_target`, `pick_best_type`).

Reuses the **improve-or-nop guarantee** (validate on a `struct.copy()`, `is_struct_change_safe`, never
grow/clobber). Because LLM review decisions become resolved `fldNN` fields, this propagates them too —
one review populates all three. Dry-run by default (`CLVR_XVER_APPLY=go`); run programs SEQUENTIALLY
(the env race). Validated: SE/AE/VR exported 257/223/278 resolved fields; cross-apply added VR 9 / SE 3
/ AE 7 (e.g. `Crime +0x18 -> TESBoundObject*`, `INFO_RUNTIME_DATA` matched VR Ghidra `+0x5C` to
CommonLib `0x70`), 0 type-conflicts, VR unknown bytes 83835 -> 83749 (monotonic, no growth).

### 14. Constructor mining (`ctor_mine.py`) — high-accuracy field names + types from ctors
The discovery cycle (11) infers field TYPES from dataflow but only SIZES the opaque ones, and can
mis-type them (it guessed `Crime +0x58` was a `TESFaction*`; reading the constructor showed `0x58` is a
4-byte scalar and the real faction is `0x60`). A class CONSTRUCTOR is the highest-signal source: it
assigns each member from a typed, named parameter (`this->Object_18 = a_object`,
`a_object:TESBoundObject*`), so one decompile yields a field's NAME and TYPE together.

For each `/types.h` class with unknown fields, this finds its constructor (param-0 is the class, name
looks like a ctor -- `ctor_plan.is_ctor`), picks the one that assigns the most fields, and reads the
`this->field@offset = a_param` assignments out of the pcode (STORE whose address back-traces to
`this + offset` and whose value traces to a parameter). It writes proposals -- (class, offset, type,
name, slot_state) -- to `<import>.ctor_fields.csv`, unknown-slot fills first. **READ-ONLY**: only
decompiles + writes a CSV. Decision logic (`is_ctor`, `field_label`, `best_ctor`) is in `ctor_plan.py`
(unit-tested). A gotcha learned here: match `this`/params by NAME, not HighVariable identity -- Ghidra
hands out distinct HighVariable objects for param-0's body instances, so `is paramHighVar` fails.

Feed the proposals into the review queue / cross-version apply: a human rubber-stamps real names+types
instead of guessing. Validated on SE: of 6208 unk-bearing classes only 24 have a clearly-named ctor
(coverage is gated by ctor identification), but the proposals are trustworthy -- it reproduced
`Crime +0x18 -> TESBoundObject* object`, added `+0x20 count` / `+0x40 owner:TESForm*` /
`CombatBehaviorIdle +0x4 interval` (net-new), and proposed nothing for `0x58` (correctly).

### 15. String-anchored naming — functions, settings, and the broader pattern (`string_anchored_rename.py`)
The binary names a lot of itself in plain text; these are the cheapest, highest-signal anchors and need
no call-graph crawl. `string_anchored_rename.py` matches three self-naming string patterns and renames
`FUN_/sub_/thunk_` to the real `Namespace::method`:
- **timer zones** -- a `HK_TIMER_BEGIN` profiler label stored into the monitor-stream TLS buffer at
  function entry (`TthkbWorld::step`, `LtBSOffsetAnimationGenerator::generate` -- Havok AND Bethesda's
  hkbGenerator subclasses). The `Lt`/`Tt` is the macro marker; the rest is the function's own name.
- **self-naming messages** -- an assert/log that leads with the qualified name
  (`"BGSSaveLoadManager::CopySaveGamesFromHost failed to..."`).
- **telemetry SDKs** -- a bare qualified name an SDK logs per call (`bnet`, allowlisted via TELEMETRY_NS).
Match is by STRING, so it propagates across SE/AE/VR with no address mapping; conflict-aware (single
consistent name + uniqueness). Dry-run default, `CLVR_RENAME=go`.

Two table-shaped variable patterns extend the same idea (no script here yet -- one-off passes / external
tools): **GameSettings / INI settings** are found by the `Setting` object layout (4-byte value, 4 null,
name-ptr) and Hungarian prefix names the global AND its type (`f`->float, `b`->bool, ...) -- see
`ghidraTools/FindBethesdaVariablesScript`; **console commands** by the `SCRIPT_FUNCTION[]` table
(name@0x00, help@0x18, handler@0x30). Lesson: discovery field TYPES are NOT authoritative (it conflated
`Crime::unk58`), so anchor names in the binary -- ctor for layout, dtor for smart-ptr type, the embedded
string for intent.

### 16. RTTI vtable recovery + the VTABLE naming convergence (`ghidraTools/RecoverRttiVtablesScript`)
MSVC RTTI is compiler-emitted ground truth -- richer than an incomplete PDB. The recovery (a *working*
x64 replacement for Ghidra's legacy `FixUpRttiAnalysisScript`, whose 64-bit RVA path was never finished)
finds Complete Object Locators by their self-reference, resolves the type descriptor as
`imageBase + (int32)rva` directly, maps each to its vtable (`vtable-8` holds the COL), and names it from
Ghidra's MS demangler. On SkyrimVR it surfaced ~130 VR-exclusive classes the SE-based PDB never had
(`BSVRInterface`, `BSOpenVRControllerDevice`, `BSTrackedControllerDevice`, VR shaders).

**Naming convergence.** CommonLib's `Offsets_VTABLE.h` declares `VTABLE_*` as C++ `constexpr`
identifiers, so they MUST be mangled there (`<>,:* &`->`_`, `::`->`__`). Ghidra has no such rule -- so the
canonical convention is **readable in Ghidra** (`VTABLE_ConcreteFormFactory<AlchemyItem,46>`,
`VTABLE_NiTMap<char_const*,Setting*>`, `::`/`<>`/`*` intact) with the mangle **confined to the CommonLib
import/export boundary**. The import currently emits a half-mangled form (templates `_`, namespaces
`::`) and the vtable-walk lookup uses the proper `<>` form, so template lookups miss -- run
`RecoverRttiVtablesScript` post-import as the canonical normalizer: RTTI is ground truth, so it renames
any existing `VTABLE_*` (incl. a half-mangled import) to the authoritative readable name, indexing
multiple-inheritance subobjects by COL offset. Export back to `Offsets_VTABLE.h` re-mangles readable ->
`_`/`__` (deterministic in that direction).

## Status
- [x] Additive submodule + junction; powerof3 path untouched
- [x] Per-runtime define set validated (VR layout correct)
- [x] Thin type-layer wrapper (config + openvr/DirectXTK includes) → emits `CommonLibImport_CLVR_{SE,AE,VR}.py`
      — VR run validated end-to-end: 846 enums / 27646 structs, 2761 vtable structs; `RE::NiAVObject`
      came out **312 (0x138)** with `flags @ 0x10C` and the VR-only `ApplyLocalTransformToWorld` slot
      (not the flat 0x110 the powerof3 path yields).
- [x] Address layer (`reloc_parser.py` VariantID 3-arg + RELOCATION_ID, VR addrlib from
      vr_address_tools) — validated in isolation: 17701 symbols, 97% VR coverage. Full
      generation (clang VR parse + symbols → `CommonLibImport_CLVR_VR.py`) wired into `main()`.
- [x] Conflict-aware non-destructive apply (`conflict_report.py` classify + `apply_enrich.py`
      replaceDataType); dry-run plan validated: CREATE ~25.8k / REUSE ~1.4k / REPLACE ~445 / PROTECT 17
      (0 vftable loss). Protect guards: HANDCURATED / VFTABLE_LOSS / SUSPICIOUS / EMBED_BASE.
- [x] Inheritance embedding (`embed_structs`, default on; trimmed variants for tail-padding reuse;
      per-struct flatten fallback). `CLVR_EMBED=0` to flatten.
- [x] Apply for real — all four phases applied to SkyrimVR.exe (`types`/`symbols`/`sigconflict`/
      `classes`). Improve phases documented above; pure logic unit-tested.
- [x] `this`-seeder (`seed_this.py`) applied + verified across SE/AE/VR (`__thiscall` 174→9908 VR,
      →10237 AE, →10978 SE; 0 anomalies/errors). Root-caused + fixed the nested-transaction
      rollback poison (never `commit=False` under the MCP outer transaction).
- [x] Call-graph type-propagation fixpoint (`propagate.py`) built + applied SE/AE/VR (34 concrete
      slot-gains; AE proved 7803 PDB-named seeds → 3 gains, so the lever is discovery, not propagation);
      filtered/surgical, measured against the net-negative whole-prototype commit.
- [x] In-Ghidra population cycle (`populate_cycle.py` + discover apply-mode) — orchestrates
      thiscall→propagate→discover+apply to a coverage fixpoint; regression-aware. VR demo: cycle 1
      +14 fields, cycle 2 converged. CommonLib export still out of scope (deliberate).
