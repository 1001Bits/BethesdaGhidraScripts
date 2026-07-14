# Third-Party Notices

This repository (and any release bundle built from it) aggregates several
third-party components, each under its own license. The aggregate work is
distributed under **GPL v3** (see `LICENSE`) because that is the strongest
copyleft license among the components that are redistributed in source form.

If you want a permissive-licensed core, the original pipeline code under
`run.py`, `scripts/`, and `tools/` (excluding any inlined snippets from
GPL-licensed sources) is also available under the **MIT License** terms at
the top of this file. The MIT grant applies only to the original
BethesdaGhidraScripts code in this repository — it does not extend to
bundled submodules, which retain their own licenses below.

---

## Original code — MIT License

Copyright (c) 2024-2026 BethesdaGhidraScripts contributors
(1001Bits, doodlum, and contributors)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

---

## Bundled third-party components

### CommonLibSSE (`extern/CommonLibSSE/`)

- Upstream: <https://github.com/powerof3/CommonLibSSE>
- License: **MIT**
- Copyright (c) 2018 Ryan-rsm-McKenzie
- See `extern/CommonLibSSE/LICENSE` for the full text.

Used by `scripts/commonlibsse/parse_commonlib_types.py` to extract type
definitions and address-library symbols for Skyrim SE/AE/VR import scripts.

### CommonLibF4 (`extern/CommonLibF4/`)

- Upstream: <https://github.com/libxse/commonlibf4>
- License: **MIT**
- Copyright (c) 2019 Ryan-rsm-McKenzie
- See `extern/CommonLibF4/LICENSE` for the full text.

Used by `scripts/commonlibf4/parse_commonlib_types.py` to extract type
definitions and address-library symbols for Fallout 4 OG/NG/AE/VR import
scripts. Fallout New Vegas (x86) reuses portions of this pipeline.

### CommonLibSF (`extern/CommonLibSF/`)

- Upstream: <https://github.com/Starfield-Reverse-Engineering/CommonLibSF>
- License: **GPL v3 with Modding Exception + GPL-3.0 Linking Exception**
- See `extern/CommonLibSF/COPYING` (GPL v3) and
  `extern/CommonLibSF/EXCEPTIONS` (Modding + Linking exceptions).

This is the most restrictive license among the bundled components. Because
this repository redistributes CommonLibSF in source form, the aggregate
release bundle is licensed under **GPL v3** (see top-level `LICENSE`). The
Modding Exception covers runtime linking between a mod and the library —
it does not waive the source-distribution requirements of GPL v3.

If you fork or redistribute this bundle, you must:

1. Preserve `LICENSE`, `extern/CommonLibSF/COPYING`, and
   `extern/CommonLibSF/EXCEPTIONS`.
2. Make Corresponding Source available for the combined work (the bundle
   itself is the source, so the requirement is satisfied by redistributing
   the bundle unmodified or with patches included).
3. Preserve all attribution and license notices in modified files.

### CommonLibVR (`extern/CommonLibVR/`)

- Upstream: <https://github.com/alandtse/CommonLibVR> (branch `ng`)
- License: **MIT**
- Copyright (c) 2018 Ryan-rsm-McKenzie; alandtse and contributors.
- See `extern/CommonLibVR/LICENSE` for the full text.  Its own `extern/openvr`
  submodule (Valve, BSD-3-Clause) supplies the OpenVR headers.
- Credit chain: original CommonLibSSE by
  [Ryan-rsm-McKenzie](https://github.com/Ryan-rsm-McKenzie); the multi-runtime
  (NG) fork by [CharmedBaryon](https://github.com/CharmedBaryon); VR support and
  the `ng` branch by [alandtse](https://github.com/alandtse).

Used by `scripts/commonlibvr/` to extract true Skyrim VR type/vtable layouts.
Unlike CommonLibSSE -- which approximates VR structs as SE -- CommonLibVR is a
genuine multi-runtime codebase that models the real VR divergence.

### CommonLibF4VR (`extern/CommonLibF4VR/`)

- Upstream: <https://github.com/ArthurHub/CommonLibF4VR> (a fork of
  <https://github.com/alandtse/CommonLibF4>)
- License: **MIT**
- Copyright (c) 2019 Ryan-rsm-McKenzie; ArthurHub, alandtse and contributors.
- See `extern/CommonLibF4VR/LICENSE` for the full text.
- Credit chain, per the fork's own README: original CommonLibF4 by
  [Ryan-rsm-McKenzie](https://github.com/Ryan-rsm-McKenzie); the F4 fork and its
  VR support by [alandtse](https://github.com/alandtse); the multi-runtime (NG)
  design it builds on by [CharmedBaryon](https://github.com/CharmedBaryon)
  (CommonLibSSE-NG); the VR split maintained by
  [ArthurHub](https://github.com/ArthurHub).

Used by `scripts/commonlibf4vr/` to extract true Fallout 4 VR (1.2.72) type and
vtable layouts.  CommonLibF4 models flatscreen Fallout 4, so VR structs come out
OG-shaped and VR vtables are (correctly) refused by its vtable policy; this fork
carries VR-exclusive members pinned by `static_assert`s against `Fallout4VR.exe`.
It does not yet model VR's inserted virtual at Actor slot `0xD1`, so this
repository supplies that one slot itself as a parse-time overlay, verified
against `scripts/commonlibf4vr/anchors/vr.csv`.

### CommonLibVR improvement pipeline + core fixes — alandtse

- Upstream: <https://github.com/alandtse/BethesdaGhidraScripts>
- License: **GPL-3.0** (same as this repository's aggregate)
- Author: **alandtse**

`scripts/commonlibvr/` (the layout-drift/conflict-aware type improvement pipeline)
is ported from alandtse's fork of this project, along with three
`scripts/core/ghidra_import_gen.py` fixes: namespaced-template struct
resolution, the degenerate `TEMPLATE_TYPE_MAP` self-alias fall-through, and the
existing-type reuse guard that stops a re-import from duplicating types.

### DirectXMath (`extern/DirectXMath/`) and DirectXTK (`extern/DirectXTK/`)

- Upstream: <https://github.com/microsoft/DirectXMath> and
  <https://github.com/microsoft/DirectXTK>
- License: **MIT**
- Copyright (c) Microsoft Corporation.
- See each submodule's `LICENSE` for the full text.

Headers only, and only at parse time.  CommonLibVR's `RE/S/State.h` holds
DirectXTK `SimpleMath::Vector4` / `Matrix` members *by value*, so their real
sizes determine real struct offsets -- `scripts/commonlibvr/` parses against
the genuine headers rather than a stub, because a wrong size there would
silently shift every field that follows it.  No Microsoft code is compiled
into, or redistributed by, anything this repository produces.

### xNVSE — New Vegas Script Extender (`extern/xNVSE/`)

- Upstream: <https://github.com/xNVSE/NVSE>
- License: **No explicit license file in the upstream repository.**
- Original NVSE by Ian Patterson; xNVSE maintained by korri123 (Kormákur),
  cnf13, jazzisparis, Demorome, and contributors.

Used by `scripts/commonlibnvse/parse_commonlib_types.py` to parse Fallout
New Vegas game-type headers under libclang. If you are an xNVSE maintainer
and would like a specific license declaration applied to this bundle's use,
please open an issue on
<https://github.com/1001Bits/BethesdaGhidraScripts>.

### JIP LN NVSE Plugin (FalloutNV name/address data)

- Upstream: <https://github.com/jazzisparis/JIP-LN-NVSE>
- License: **GPL-3.0**
- Author: jazzisparis and contributors.

`scripts/commonlibnvse/refs/fnv_pc_symbols.txt` contains ~7.7k `FalloutNV.exe`
addresses and labels extracted from the xNVSE and JIP LN NVSE source trees;
the Fallout New Vegas naming pipeline uses them as known-address anchors. The
plugin source itself is not redistributed here. Because this data derives from
a GPL-3.0 source, it is one of the components that make the aggregate bundle
GPL-3.0 (see top-level `LICENSE`).

### Fallout 4 community symbol PDBs — Perchik71

- Author: **Perchik71**
- The `Fallout4_1_11_221_for_debug.pdb` family of community-reconstructed,
  public-symbol-only PDBs for Fallout 4.

`scripts/commonlibf4/refs/f4_221_pdb_publics.txt` is a deterministic text
corpus extracted from these PDBs (38,029 publics for 1.11.221), and is the
basis for the Fallout 4 naming and cross-version ID-porting pipelines. The raw
PDB itself is **not** redistributed here — obtain the author's
permission/license before redistributing it.

### Fallout 4 IDA function-name cross-map — Zzyxzz

- Author: **Zzyxzz**
- `IDA_Functions_OG_AE.csv` — ~267k demangled Fallout 4 function signatures
  keyed by both the OG (1.10.163) and AE (1.11.191) RVA.

Consumed by `scripts/commonlibf4/apply_ida_csv_names.py` to name Ghidra
programs (it is the source of tens of thousands of AE names). The CSV is
user-supplied and is **not** redistributed in this repository or its release
bundles.

### AddressLibraryDatabase (`extern/AddressLibraryDatabase/`)

- Upstream: <https://github.com/meh321/AddressLibraryDatabase>
- License: **No explicit license file in the upstream repository.**

The upstream `meh321/AddressLibraryDatabase` repository contains only
auxiliary data (CSVs / shift maps) used by Address Library tooling. We
include it as a submodule for parity with the upstream CommonLib*
pipelines. The pre-built address-library `.bin` / `.csv` files we ship
under `addresslibrary/` are sourced from meh321's public Nexus releases
(Address Library for SKSE / F4SE / SFSE Plugins) which are publicly
distributed under the project's own terms.

If you are the maintainer of `meh321/AddressLibraryDatabase` and would
like a specific license declaration applied to this bundle's use of your
data, please open an issue on
<https://github.com/1001Bits/BethesdaGhidraScripts>.

### Address Library binary files (`addresslibrary/*.bin`, `addresslibrary/*.csv`)

- Source: meh321's public Nexus mod pages (Address Library for SKSE /
  F4SE / SFSE Plugins).
- These files are factual offset tables — Bethesda binary RVAs keyed by
  numeric IDs — and are widely redistributed across SKSE/F4SE/SFSE plugin
  source repositories under each plugin's own license.

### Clang / libclang stub headers (`scripts/core/_clang_stubs/`)

- Minimal `<intrin.h>` / `<mmintrin.h>` etc. shims required to make
  CommonLib* headers parse under libclang. Original code, MIT-licensed
  (see "Original code" above).

---

## What we do NOT redistribute

- Bethesda game binaries (`*.exe`, `*.dll` from the Skyrim / Fallout /
  Starfield install). Users supply these from their own legitimately
  purchased copy.
- Microsoft PDB files. Where these appear in the development repository
  they are excluded from release bundles by `tools/build_release_bundle.ps1`.
- Reverse-engineered name corpora that were derived directly from game
  binaries (e.g. `*.relib`, raw `*.pdb` dumps). These are excluded from
  release bundles.

---

## Tooling that the pipeline downloads at runtime

`run.py`'s "Install prerequisites" step downloads:

- **Ghidra** (Apache 2.0) — <https://github.com/NationalSecurityAgency/ghidra>
- **LLVM/Clang** (Apache 2.0 with LLVM Exception) — <https://github.com/llvm/llvm-project>
- **Steamless** (MIT) — <https://github.com/atom0s/Steamless>
- **FakePDB** (Apache 2.0) — <https://github.com/Mixaill/FakePDB> — invoked to
  generate public-symbol PDBs from exported symbols. Pinned by
  `toolchain.lock.json` (v0.3, commit `2d84f49`). Not redistributed in the
  source bundle; only its generated PDB output feeds downstream tooling.
- **JDK 21** (GPL v2 with Classpath Exception, when using OpenJDK
  distributions) — installed by the user manually if not present.

These are fetched into local working directories (`tools/`,
`C:\Development\LLVM\`, etc.) and are not redistributed in the source
bundle. Each carries its own license at the download location.
