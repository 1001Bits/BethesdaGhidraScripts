"""Cross-version byte-signature port for Fallout 4 binaries.

For each known (name, source_rva) pair in a source PE, extracts W bytes at
the source RVA and searches the target PE's .text section for an exact,
unique match.  Successful matches yield a (name, target_rva) entry.

Enables porting CommonLibF4's AE-resolved symbols into NG (and reverse),
plus porting fo4_database's OG+VR entries into NG and AE.

F4 NG unpacked and F4 AE unpacked share an identical PDB GUID, so their
code sections are nearly byte-identical — raw 32-byte anchors almost always
resolve uniquely.  Cross-build ports (OG↔NG, VR↔AE) have lower hit rates.

Usage (library):
    from bytesig_port import load_pe_text, build_prefix_index, port_symbols
"""
import os
import struct


def load_pe_text(path):
    """Return (image_base, text_rva, text_bytes) for the .text section."""
    with open(path, 'rb') as fh:
        data = fh.read()
    if data[:2] != b'MZ':
        raise ValueError('not a PE: {}'.format(path))
    pe_off = struct.unpack_from('<I', data, 0x3c)[0]
    if data[pe_off:pe_off + 4] != b'PE\0\0':
        raise ValueError('PE sig missing')
    opt_magic = struct.unpack_from('<H', data, pe_off + 0x18)[0]
    is_pe32p = (opt_magic == 0x20b)
    if is_pe32p:
        image_base = struct.unpack_from('<Q', data, pe_off + 0x18 + 0x18)[0]
    else:
        image_base = struct.unpack_from('<I', data, pe_off + 0x18 + 0x1c)[0]
    nsec = struct.unpack_from('<H', data, pe_off + 6)[0]
    sec_off = pe_off + 0x18 + (0xf0 if is_pe32p else 0xe0)
    for i in range(nsec):
        s = sec_off + i * 0x28
        name = data[s:s + 8].rstrip(b'\0')
        if name != b'.text':
            continue
        v_rva = struct.unpack_from('<I', data, s + 12)[0]
        r_size = struct.unpack_from('<I', data, s + 16)[0]
        r_off = struct.unpack_from('<I', data, s + 20)[0]
        return image_base, v_rva, data[r_off:r_off + r_size]
    raise ValueError('no .text section')


def build_prefix_index(text_bytes, k=6):
    """Dict[bytes] -> list[int]: positions of each k-byte prefix in .text."""
    idx = {}
    n = len(text_bytes) - k
    for i in range(n + 1):
        p = bytes(text_bytes[i:i + k])
        lst = idx.get(p)
        if lst is None:
            idx[p] = [i]
        else:
            lst.append(i)
    return idx


def _unique_match(src_bytes, window, tgt_text, tgt_idx, prefix_k=6):
    """Return unique match offset or None."""
    if len(src_bytes) < window:
        return None
    prefix = bytes(src_bytes[:prefix_k])
    cands = tgt_idx.get(prefix)
    if not cands:
        return None
    src_cmp = bytes(src_bytes[:window])
    found = -1
    for c in cands:
        if tgt_text[c:c + window] == src_cmp:
            if found >= 0:
                return None  # ambiguous
            found = c
    return found if found >= 0 else None


_CS = {}


def _get_cs(pointer_size=8):
    key = int(pointer_size)
    if key not in _CS:
        import capstone
        mode = capstone.CS_MODE_32 if key == 4 else capstone.CS_MODE_64
        md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        md.detail = True
        _CS[key] = md
    return _CS[key]


def compute_masked_sig(text, offset, window=48, pointer_size=8):
    """Return (sig_bytes, mask_bytes) of length `window`, mask=0 for wildcards.

    Wildcards rel32 operands in call/jmp/Jcc and rip-relative mem disp32 —
    those bytes drift between different builds even for identical functions.
    """
    import capstone
    cs = _get_cs(pointer_size)
    # Disassemble a bit extra so we never truncate mid-instruction inside the window.
    extra = 16
    data = bytes(text[offset:offset + window + extra])
    sig = bytearray(data[:window])
    mask = bytearray([1] * window)
    for ins in cs.disasm(data, 0):
        if ins.address >= window:
            break
        end = ins.address + ins.size
        # Use Capstone's exact encoding offsets.  Displacements/immediates are
        # not necessarily the final four bytes once prefixes/SIB/imm operands
        # are involved.
        mnem = ins.mnemonic
        is_relative_cf = mnem in ('call', 'jmp') or mnem.startswith('j')
        imm_off = getattr(ins, 'imm_offset', 0)
        imm_size = getattr(ins, 'imm_size', 0)
        if is_relative_cf and imm_off and imm_size:
            for k in range(imm_size):
                p = ins.address + imm_off + k
                if 0 <= p < window:
                    sig[p] = 0
                    mask[p] = 0
        # RIP-relative memory displacement, again using exact encoding data.
        try:
            ops = ins.operands
        except Exception:
            ops = []
        for op in ops:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                disp_off = getattr(ins, 'disp_offset', 0)
                disp_size = getattr(ins, 'disp_size', 0)
                for k in range(disp_size):
                    p = ins.address + disp_off + k
                    if 0 <= p < window:
                        sig[p] = 0
                        mask[p] = 0
                break
    return bytes(sig), bytes(mask)


def _unique_match_masked(src_sig, src_mask, window, tgt_text, tgt_idx, prefix_k=6):
    """Match `src_sig` against `tgt_text` candidates, comparing only where `src_mask` is 1.

    Requires first `prefix_k` bytes fully unmasked (so the prefix index hits).
    Uses numpy for the vectorized byte compare — 50×+ faster than a Python
    per-byte loop, which dominated runtime on large candidate lists (e.g.
    OG↔NG cross-build masked pairs with 180 K source RVAs).
    """
    import numpy as np
    if sum(1 for b in src_mask[:window] if b) < max(12, window // 2):
        return None
    if any(b == 0 for b in src_mask[:prefix_k]):
        return None
    prefix = bytes(src_sig[:prefix_k])
    cands = tgt_idx.get(prefix)
    if not cands:
        return None
    sig_np = np.frombuffer(src_sig, dtype=np.uint8, count=window)
    # Convert 0/1 mask bytes to 0x00/0xff for XOR+AND-based compare.
    mask_np = np.frombuffer(bytes(0xff if b else 0x00 for b in src_mask[:window]),
                            dtype=np.uint8, count=window)
    sig_masked = sig_np & mask_np
    tgt_view = memoryview(tgt_text)
    tgt_len = len(tgt_text)
    found = -1
    for c in cands:
        if c + window > tgt_len:
            continue
        tgt_np = np.frombuffer(tgt_view, dtype=np.uint8, count=window, offset=c)
        if ((tgt_np & mask_np) == sig_masked).all():
            if found >= 0:
                return None  # ambiguous
            found = c
    return found if found >= 0 else None


def port_symbols(src_rvas, src_text_rva, src_text,
                 tgt_text_rva, tgt_text, tgt_idx,
                 window=32, prefix_k=6, masked=False, progress_every=0,
                 src_sig_cache=None, pointer_size=8,
                 src_function_sizes=None, target_function_starts=None):
    """Port list of (name, src_rva) → list of (name, tgt_rva).

    src_rva / tgt_rva are PE RVAs (not absolute VAs).  Skips symbols that
    fall outside .text or match ambiguously.  With `masked=True`, wildcards
    rel32/rip-rel displacements so cross-build matches (OG↔VR, NG↔VR) work.
    If `progress_every` > 0, prints a stats dump every N source symbols.

    ``src_sig_cache`` is an optional dict ``{rva: (src_sig, src_mask)}``
    that lets callers share masked-signature computations across multiple
    target passes (Capstone disasm of 90k+ source RVAs is otherwise
    repeated per target, doubling the runtime when going 1->N).
    Populated in place when ``masked=True``.
    """
    proposals = []
    stats = {'ok': 0, 'missing_src': 0, 'no_prefix': 0,
             'ambiguous_or_zero': 0, 'not_function_boundary': 0,
             'crosses_function_boundary': 0, 'target_conflict': 0}
    src_text_len = len(src_text)
    processed = 0
    total = len(src_rvas)
    for name, rva in src_rvas:
        processed += 1
        if progress_every and processed % progress_every == 0:
            print('      ...{}/{} (ok={} noprefix={} ambig={})'.format(
                processed, total, stats['ok'], stats['no_prefix'], stats['ambiguous_or_zero']),
                flush=True)
        off = rva - src_text_rva
        if off < 0 or off + window > src_text_len:
            stats['missing_src'] += 1
            continue
        if src_function_sizes is not None:
            size = src_function_sizes.get(rva)
            if size is None:
                stats['not_function_boundary'] += 1
                continue
            if int(size) < window:
                stats['crosses_function_boundary'] += 1
                continue
        if masked:
            cache_hit = src_sig_cache is not None and rva in src_sig_cache
            if cache_hit:
                src_sig, src_mask = src_sig_cache[rva]
            else:
                src_sig, src_mask = compute_masked_sig(
                    src_text, off, window=window, pointer_size=pointer_size)
                if src_sig_cache is not None:
                    src_sig_cache[rva] = (src_sig, src_mask)
            tgt_off = _unique_match_masked(src_sig, src_mask, window, tgt_text, tgt_idx, prefix_k)
            if tgt_off is None:
                prefix = bytes(src_sig[:prefix_k])
                if any(b == 0 for b in src_mask[:prefix_k]) or prefix not in tgt_idx:
                    stats['no_prefix'] += 1
                else:
                    stats['ambiguous_or_zero'] += 1
                continue
        else:
            src_bytes = src_text[off:off + window]
            tgt_off = _unique_match(src_bytes, window, tgt_text, tgt_idx, prefix_k)
            if tgt_off is None:
                prefix = bytes(src_bytes[:prefix_k])
                if prefix not in tgt_idx:
                    stats['no_prefix'] += 1
                else:
                    stats['ambiguous_or_zero'] += 1
                continue
        target_rva = tgt_off + tgt_text_rva
        if target_function_starts is not None and target_rva not in target_function_starts:
            stats['not_function_boundary'] += 1
            continue
        proposals.append((name, target_rva, rva))

    # Reciprocal ownership: different source functions/names may not silently
    # collapse onto the same target entry.  Preserve only unambiguous targets.
    by_target = {}
    for name, target_rva, source_rva in proposals:
        by_target.setdefault(target_rva, []).append((name, source_rva))
    ported = []
    for target_rva, claims in sorted(by_target.items()):
        unique_sources = set(source for _name, source in claims)
        unique_names = set(name for name, _source in claims)
        if len(unique_sources) != 1 or len(unique_names) != 1:
            stats['target_conflict'] += len(claims)
            continue
        ported.append((next(iter(unique_names)), target_rva))
        stats['ok'] += 1
    return ported, stats
