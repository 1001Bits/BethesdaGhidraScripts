#!/usr/bin/env python3
r"""Conservatively port names between analyzed Ghidra programs.

The implementation is target-configurable.  Its default configuration remains
the Skyrim Creation Kit workflow exposed by ``bytesig_port_skyrim_to_ck.py``;
other Creation Kit wrappers supply a distinct exact target identity, source
set, evidence path, and transaction labels.

This script deliberately does *not* consume an address library.  A game runtime
address is not a Creation Kit address.  Instead, the source name pool comes
from function names already present at analyzed function entries in the same
Ghidra project.  Names are proposed only when their code bytes produce an exact
or relocation-masked unique match at an analyzed target function entry.

Safety properties:

* every target configuration pins an exact executable SHA-256;
* source and target signatures may not cross an analyzed function boundary;
* each signature must match uniquely in both its source image and the target,
  and the combined source set must form a one-to-one
  (qualified name <-> target RVA) mapping;
* an existing non-default target function name is never replaced;
* dry-run is the default and every proposal/decision is written to an
  identity-bound CSV plus a SHA-256 sidecar;
* applying names requires an explicit ``--apply`` or ``apply=True``.

Standalone usage (the project must not be open in the Ghidra GUI)::

    python scripts/creationkit/bytesig_port_skyrim_to_ck.py \
      --project-dir C:\\GhidraProjects --project-name ExampleProject \
      --target-path /CreationKit.exe

Add ``--apply`` only after reviewing the CSV.  Sources can be selected with a
repeatable ``--source TAG=/Project/Path.exe`` argument.

Live-Ghidra usage (including the local MCP ``eval_python`` bridge)::

    import sys
    sys.path.insert(0, r'C:\Development\Tools\BethesdaGhidraScripts\scripts\creationkit')
    import bytesig_port_skyrim_to_ck as ck_port
    result = ck_port.run_live(currentProgram, state, monitor=monitor,
                              apply=False, save=False)

Review the evidence, then repeat with ``apply=True, save=True``.  ``currentProgram``
must be the pinned Creation Kit program.  No project lock is acquired in live
mode; source programs are opened read-only and released one at a time.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_DIR = SCRIPT_DIR.parent.parent
CORE_DIR = REPO_DIR / "scripts" / "core"
GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR") or (REPO_DIR / "tools" / "ghidra"))
DEFAULT_EVIDENCE = SCRIPT_DIR / "refs" / "skyrim_to_creationkit_1_6_1378_1.csv"

if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

# Shared matcher.  It imports Capstone/Numpy lazily for masked matching only.
from bytesig_port import (  # noqa: E402
    _unique_match,
    _unique_match_masked,
    compute_masked_sig,
    port_symbols,
)


TARGET_SHA256 = "3e8f7215303a82d8991f87fbc42eb84ef2672d5d8ab038212447faecfdf37b23"
TARGET_PRODUCT_VERSION = "1.6.1378.1"
EVIDENCE_SCHEMA_VERSION = 1
PREFIX_BYTES = 6
EXACT_WINDOW = 32
MASKED_WINDOW = 48

DEFAULT_SOURCES = (
    ("SkyrimAE-1.6.1170", "/Skyrim/SkyrimAE_1_6_1170.exe"),
    ("SkyrimSE-1.5.97", "/Skyrim/SkyrimSE_1_5_97.exe"),
)


@dataclass(frozen=True)
class PortConfig:
    """Identity and user-facing policy for one reciprocal bytesig target."""

    target_sha256: str
    target_product_version: str
    default_sources: tuple[tuple[str, str], ...]
    default_evidence: Path
    target_display_name: str
    default_target_path: str
    transaction_name: str
    save_description: str
    source_help: str
    allowed_source_sha256: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        sha = str(self.target_sha256).strip().lower()
        if len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
            raise ValueError("target_sha256 must be exactly 64 hexadecimal digits")
        if not self.target_product_version:
            raise ValueError("target_product_version is required")
        if not self.target_display_name:
            raise ValueError("target_display_name is required")
        if not str(self.default_target_path).startswith("/"):
            raise ValueError("default_target_path must be an absolute project path")
        normalized_target_path = "/" + str(
            self.default_target_path).strip().strip("/")
        normalized_sources = []
        seen_tags = set()
        for tag, path in self.default_sources:
            tag = str(tag).strip()
            path = "/" + str(path).strip().strip("/")
            if not tag or tag in seen_tags:
                raise ValueError("default source tags must be non-empty and unique")
            seen_tags.add(tag)
            normalized_sources.append((tag, path))
        normalized_identities = []
        seen_paths = set()
        for path, source_sha256 in self.allowed_source_sha256:
            path = "/" + str(path).strip().strip("/")
            source_sha256 = str(source_sha256).strip().lower()
            if path in seen_paths:
                raise ValueError("allowed source paths must be unique")
            if (len(source_sha256) != 64 or
                    any(ch not in "0123456789abcdef" for ch in source_sha256)):
                raise ValueError(
                    "allowed source SHA-256 must be exactly 64 hexadecimal digits")
            if source_sha256 == sha:
                raise ValueError("configured source may not be the target")
            seen_paths.add(path)
            normalized_identities.append((path, source_sha256))
        missing = [path for _tag, path in normalized_sources
                   if path not in seen_paths]
        if missing:
            raise ValueError(
                "every default source requires an exact SHA-256 pin: " +
                ", ".join(missing))
        object.__setattr__(self, "target_sha256", sha)
        object.__setattr__(self, "default_target_path", normalized_target_path)
        object.__setattr__(self, "default_sources", tuple(normalized_sources))
        object.__setattr__(
            self, "allowed_source_sha256", tuple(normalized_identities))
        object.__setattr__(self, "default_evidence", Path(self.default_evidence))

    def source_sha256_for_path(self, path: str) -> str:
        normalized = "/" + str(path).strip().strip("/")
        for allowed_path, sha256 in self.allowed_source_sha256:
            if allowed_path == normalized:
                return sha256
        raise ValueError(
            "source path is not identity-pinned for {}: {}".format(
                self.target_display_name, normalized))


SKYRIM_CONFIG = PortConfig(
    target_sha256=TARGET_SHA256,
    target_product_version=TARGET_PRODUCT_VERSION,
    default_sources=DEFAULT_SOURCES,
    default_evidence=DEFAULT_EVIDENCE,
    target_display_name="Skyrim Creation Kit 1.6.1378.1",
    default_target_path="/CreationKit.exe",
    transaction_name=(
        "Creation Kit Skyrim reciprocal-unique byte-signature names"),
    save_description=(
        "Creation Kit reciprocal-unique Skyrim byte-signature names"),
    source_help=(
        "repeatable configured identity-pinned source; defaults to analyzed "
        "AE 1.6.1170 and SE 1.5.97 programs in ExampleProject"),
    allowed_source_sha256=(
        ("/Skyrim/SkyrimAE_1_6_1170.exe",
         "80c1ea737d33c6bfac09b101b8d77ab0f9f6630128c3ed052f9d945bed54e7e4"),
        ("/Skyrim/SkyrimSE_1_5_97.exe",
         "5666e1bddd01bcab31ecf11691ef1a3f22e1541af79f2bc0e55318533cfe5d12"),
    ),
)

_DEFAULT_FUNCTION_RE = re.compile(
    r"^(?:FUN_|sub_|thunk_FUN_|thunk_sub_)[0-9A-Fa-f]+$")

CSV_FIELDS = (
    "target_sha256",
    "target_program_path",
    "target_rva",
    "qualified_name",
    "namespace",
    "local_name",
    "match_kind",
    "signature_bytes",
    "decision",
    "target_name_before",
    "source_tag",
    "source_sha256",
    "source_program_path",
    "source_name_type",
    "source_rva",
)


@dataclass(frozen=True)
class SourceName:
    """A meaningful primary name at an exact source function entry."""

    qualified_name: str
    local_name: str
    namespace: tuple[str, ...]
    source_name_type: str
    rva: int


@dataclass(frozen=True)
class Proposal:
    """One independently identity-bound source claim."""

    source_tag: str
    source_sha256: str
    source_program_path: str
    source_name_type: str
    source_rva: int
    target_rva: int
    qualified_name: str
    local_name: str
    namespace: tuple[str, ...]
    match_kind: str
    signature_bytes: int


def _valid_sha256(value: object) -> str:
    sha = str(value or "").strip().lower()
    if len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
        raise RuntimeError("Ghidra program has no valid executable SHA-256 metadata")
    return sha


def _program_path(program) -> str:
    domain_file = program.getDomainFile()
    if domain_file is None:
        return "/" + str(program.getName())
    try:
        return str(domain_file.getPathname())
    except Exception:
        return "/" + str(domain_file.getName())


def _program_manifest(program, program_path: str) -> dict:
    sha = _valid_sha256(program.getExecutableSHA256())
    image_base = program.getImageBase().getOffset() & 0xFFFFFFFFFFFFFFFF
    sections = []
    for block in program.getMemory().getBlocks():
        sections.append({
            "name": str(block.getName()),
            "rva": ((block.getStart().getOffset() & 0xFFFFFFFFFFFFFFFF) -
                    image_base),
            "size": int(block.getSize()),
            "read": bool(block.isRead()),
            "write": bool(block.isWrite()),
            "execute": bool(block.isExecute()),
        })
    return {
        "identity_kind": "ghidra_program_executable_sha256",
        "sha256": sha,
        "program_path": program_path,
        "program_name": str(program.getName()),
        "image_base": image_base,
        "sections": sections,
    }


def _assert_target_identity(
        program, program_path: str,
        config: PortConfig = SKYRIM_CONFIG) -> dict:
    normalized_path = "/" + str(program_path).strip().strip("/")
    if normalized_path != config.default_target_path:
        raise RuntimeError(
            "refusing target {}: expected exact project path {}".format(
                normalized_path, config.default_target_path))
    manifest = _program_manifest(program, program_path)
    if manifest["sha256"] != config.target_sha256:
        raise RuntimeError(
            "refusing target {}: SHA-256 {} != pinned {} {}".format(
                program_path, manifest["sha256"], config.target_display_name,
                config.target_sha256))
    return manifest


def _assert_analysis_idle(program) -> None:
    """Reject a moving function-boundary/name snapshot."""
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager

    manager = AutoAnalysisManager.getAnalysisManager(program)
    if manager.isAnalyzing():
        raise RuntimeError(
            "{} is still being analyzed; wait for auto-analysis to finish".format(
                program.getName()))


def _namespace_parts(symbol) -> tuple[str, ...]:
    parts = []
    namespace = symbol.getParentNamespace()
    while namespace is not None:
        try:
            if namespace.isGlobal():
                break
        except Exception:
            # Older Ghidra Namespace interfaces do not expose isGlobal().
            if str(namespace.getName()) == "Global":
                break
        parts.append(str(namespace.getName()))
        namespace = namespace.getParentNamespace()
    parts.reverse()
    return tuple(parts)


def _contiguous_entry_size(function) -> int | None:
    """Length of the function-body range containing its entry point."""
    try:
        body = function.getBody()
        address_range = body.getRangeContaining(function.getEntryPoint())
        if address_range is None:
            return None
        size = int(address_range.getLength())
        return size if size > 0 else None
    except Exception:
        return None


def _function_boundaries(program) -> tuple[dict[int, int], set[int]]:
    base = program.getImageBase().getOffset() & 0xFFFFFFFFFFFFFFFF
    sizes: dict[int, int] = {}
    starts: set[int] = set()
    for function in program.getFunctionManager().getFunctions(True):
        entry = function.getEntryPoint().getOffset() & 0xFFFFFFFFFFFFFFFF
        rva = entry - base
        starts.add(rva)
        size = _contiguous_entry_size(function)
        if size is not None:
            sizes[rva] = size
    return sizes, starts


def _extract_source_names(program) -> tuple[dict[str, SourceName], dict[str, int]]:
    """Read only meaningful primary names already present in the program.

    This is intentionally independent of CommonLib import/address-library
    files.  Duplicate qualified names are discarded rather than guessed.
    """
    from ghidra.program.model.symbol import SourceType

    base = program.getImageBase().getOffset() & 0xFFFFFFFFFFFFFFFF
    candidates: list[SourceName] = []
    stats = Counter()
    for function in program.getFunctionManager().getFunctions(True):
        stats["functions_seen"] += 1
        try:
            if function.isExternal():
                stats["external"] += 1
                continue
            symbol = function.getSymbol()
            if symbol is None or symbol.getSource() == SourceType.DEFAULT:
                stats["default_name"] += 1
                continue
            local_name = str(symbol.getName())
            if not local_name or _DEFAULT_FUNCTION_RE.match(local_name):
                stats["placeholder_name"] += 1
                continue
            namespace = _namespace_parts(symbol)
            qualified = "::".join(namespace + (local_name,))
            entry = function.getEntryPoint().getOffset() & 0xFFFFFFFFFFFFFFFF
            candidates.append(SourceName(
                qualified_name=qualified,
                local_name=local_name,
                namespace=namespace,
                source_name_type=str(symbol.getSource()),
                rva=entry - base,
            ))
        except Exception:
            stats["read_error"] += 1

    qualified_counts = Counter(item.qualified_name for item in candidates)
    unique: dict[str, SourceName] = {}
    for item in candidates:
        if qualified_counts[item.qualified_name] != 1:
            stats["duplicate_qualified_name"] += 1
            continue
        unique[item.qualified_name] = item
    stats["accepted_names"] = len(unique)
    return unique, dict(stats)


def _load_text_block(program) -> tuple[int, int, bytes]:
    """Return (image_base, .text RVA, bytes), using chunked Java reads."""
    import jpype

    block = program.getMemory().getBlock(".text")
    if block is None:
        raise RuntimeError("{} has no .text memory block".format(program.getName()))
    image_base = program.getImageBase().getOffset() & 0xFFFFFFFFFFFFFFFF
    start = block.getStart()
    text_rva = ((start.getOffset() & 0xFFFFFFFFFFFFFFFF) - image_base)
    size = int(block.getSize())
    byte_array = jpype.JArray(jpype.JByte)
    chunk_size = 64 * 1024
    output = bytearray(size)
    for offset in range(0, size, chunk_size):
        length = min(chunk_size, size - offset)
        chunk = byte_array(length)
        block.getBytes(start.add(offset), chunk, 0, length)
        output[offset:offset + length] = bytes(chunk)
    return image_base, text_rva, bytes(output)


def _build_filtered_prefix_index(
        text: bytes, wanted_prefixes: Iterable[bytes],
        prefix_bytes: int = PREFIX_BYTES) -> dict[bytes, list[int]]:
    """Index only source prefixes instead of every prefix in target .text.

    The shared matcher consumes the same ``bytes -> positions`` shape as its
    full index.  Restricting it to prefixes that can actually be queried keeps
    a ~33 MiB Creation Kit .text scan to hundreds of MiB (or less), rather
    than a multi-gigabyte dictionary with one entry per byte offset.
    """
    wanted = {bytes(item) for item in wanted_prefixes
              if len(item) == prefix_bytes}
    if not wanted or len(text) < prefix_bytes:
        return {}
    wanted_ints = {
        int.from_bytes(prefix, "little"): prefix for prefix in wanted
    }
    result: dict[bytes, list[int]] = {}
    count = len(text) - prefix_bytes + 1

    try:
        import numpy as np

        source = np.frombuffer(text, dtype=np.uint8)
        sorted_wanted = np.array(sorted(wanted_ints), dtype=np.uint64)
        chunk_entries = 1_000_000
        for start in range(0, count, chunk_entries):
            length = min(chunk_entries, count - start)
            values = np.zeros(length, dtype=np.uint64)
            for byte_index in range(prefix_bytes):
                component = source[
                    start + byte_index:start + byte_index + length
                ].astype(np.uint64, copy=False)
                values |= component << (8 * byte_index)
            positions = np.searchsorted(sorted_wanted, values)
            in_bounds = positions < len(sorted_wanted)
            matches = np.zeros(length, dtype=bool)
            if in_bounds.any():
                selected = np.nonzero(in_bounds)[0]
                matches[selected] = (
                    sorted_wanted[positions[selected]] == values[selected])
            for relative in np.nonzero(matches)[0].tolist():
                value = int(values[relative])
                prefix = wanted_ints[value]
                result.setdefault(prefix, []).append(start + int(relative))
        return result
    except ImportError:
        # Allocation-free rolling fallback.  Slower than NumPy but bounded.
        mask = (1 << (8 * prefix_bytes)) - 1
        value = int.from_bytes(text[:prefix_bytes], "little")
        shift = 8 * (prefix_bytes - 1)
        for offset in range(count):
            prefix = wanted_ints.get(value)
            if prefix is not None:
                result.setdefault(prefix, []).append(offset)
            if offset + prefix_bytes < len(text):
                value = ((value >> 8) |
                         (text[offset + prefix_bytes] << shift)) & mask
        return result


def _eligible_source_pairs(
        names: dict[str, SourceName], sizes: dict[int, int], text_rva: int,
        text: bytes, window: int) -> list[tuple[str, int]]:
    end_rva = text_rva + len(text)
    return sorted(
        (qualified, item.rva)
        for qualified, item in names.items()
        if text_rva <= item.rva and item.rva + window <= end_rva
        and sizes.get(item.rva, 0) >= window
    )


def _source_unique_exact_pairs(
        pairs: Sequence[tuple[str, int]], source_text_rva: int,
        source_text: bytes, window: int) -> tuple[list[tuple[str, int]], int]:
    """Keep exact signatures occurring once across the whole source .text."""
    prefixes = (
        source_text[rva - source_text_rva:
                    rva - source_text_rva + PREFIX_BYTES]
        for _name, rva in pairs
    )
    index = _build_filtered_prefix_index(source_text, prefixes)
    unique = []
    rejected = 0
    for pair in pairs:
        _name, rva = pair
        offset = rva - source_text_rva
        signature = source_text[offset:offset + window]
        if _unique_match(
                signature, window, source_text, index,
                prefix_k=PREFIX_BYTES) == offset:
            unique.append(pair)
        else:
            rejected += 1
    return unique, rejected


def _source_unique_masked_pairs(
        pairs: Sequence[tuple[str, int]], source_text_rva: int,
        source_text: bytes, window: int,
        signature_cache: dict[int, tuple[bytes, bytes]]) -> tuple[
            list[tuple[str, int]], int]:
    """Keep masked signatures occurring once across the whole source .text."""
    prefixes = (
        signature_cache[rva][0][:PREFIX_BYTES]
        for _name, rva in pairs
        if all(signature_cache[rva][1][:PREFIX_BYTES])
    )
    index = _build_filtered_prefix_index(source_text, prefixes)
    unique = []
    rejected = 0
    for pair in pairs:
        _name, rva = pair
        offset = rva - source_text_rva
        signature, mask = signature_cache[rva]
        if _unique_match_masked(
                signature, mask, window, source_text, index,
                prefix_k=PREFIX_BYTES) == offset:
            unique.append(pair)
        else:
            rejected += 1
    return unique, rejected


def _proposal_from_match(
        match: tuple[str, int], names: dict[str, SourceName],
        source_tag: str, source_manifest: dict, match_kind: str,
        window: int) -> Proposal:
    qualified, target_rva = match
    item = names[qualified]
    return Proposal(
        source_tag=source_tag,
        source_sha256=source_manifest["sha256"],
        source_program_path=source_manifest["program_path"],
        source_name_type=item.source_name_type,
        source_rva=item.rva,
        target_rva=int(target_rva),
        qualified_name=item.qualified_name,
        local_name=item.local_name,
        namespace=item.namespace,
        match_kind=match_kind,
        signature_bytes=window,
    )


def _match_source(
        source_program, source_tag: str, source_path: str,
        target_text_rva: int, target_text: bytes,
        target_function_sizes: dict[int, int],
        target_function_starts: set[int],
        config: PortConfig = SKYRIM_CONFIG) -> tuple[list[Proposal], dict, dict]:
    """Return proposals, matcher statistics, and the source manifest."""
    source_manifest = _program_manifest(source_program, source_path)
    if source_manifest["sha256"] == config.target_sha256:
        raise RuntimeError("source {} is the configured target".format(source_path))
    try:
        expected_source_sha256 = config.source_sha256_for_path(source_path)
    except ValueError as error:
        raise RuntimeError(str(error)) from error
    if source_manifest["sha256"] != expected_source_sha256:
        raise RuntimeError(
            "refusing source {}: SHA-256 {} != pinned {}".format(
                source_path, source_manifest["sha256"],
                expected_source_sha256))

    names, extraction_stats = _extract_source_names(source_program)
    source_sizes, _ = _function_boundaries(source_program)
    _, source_text_rva, source_text = _load_text_block(source_program)

    eligible_exact_pairs = _eligible_source_pairs(
        names, source_sizes, source_text_rva, source_text, EXACT_WINDOW)
    exact_pairs, source_ambiguous_exact = _source_unique_exact_pairs(
        eligible_exact_pairs, source_text_rva, source_text, EXACT_WINDOW)
    exact_prefixes = (
        source_text[rva - source_text_rva:rva - source_text_rva + PREFIX_BYTES]
        for _name, rva in exact_pairs
    )
    exact_index = _build_filtered_prefix_index(target_text, exact_prefixes)
    exact_matches, exact_stats = port_symbols(
        exact_pairs, source_text_rva, source_text,
        target_text_rva, target_text, exact_index,
        window=EXACT_WINDOW, prefix_k=PREFIX_BYTES, masked=False,
        src_function_sizes=source_sizes,
        target_function_starts=target_function_starts,
    )
    # A target signature must also remain inside the target function body.
    exact_matches = [
        match for match in exact_matches
        if target_function_sizes.get(int(match[1]), 0) >= EXACT_WINDOW
    ]
    proposals = [
        _proposal_from_match(match, names, source_tag, source_manifest,
                             "exact", EXACT_WINDOW)
        for match in exact_matches
    ]

    exact_names = {name for name, _rva in exact_matches}
    eligible_masked_pairs = [
        pair for pair in _eligible_source_pairs(
            names, source_sizes, source_text_rva, source_text, MASKED_WINDOW)
        if pair[0] not in exact_names
    ]
    masked_pairs = eligible_masked_pairs
    source_ambiguous_masked = 0
    masked_stats: dict = {"skipped": 0}
    if masked_pairs:
        signature_cache: dict[int, tuple[bytes, bytes]] = {}
        try:
            masked_prefixes = []
            for _name, rva in masked_pairs:
                offset = rva - source_text_rva
                signature, mask = compute_masked_sig(
                    source_text, offset, window=MASKED_WINDOW, pointer_size=8)
                signature_cache[rva] = (signature, mask)
                if all(mask[:PREFIX_BYTES]):
                    masked_prefixes.append(signature[:PREFIX_BYTES])
            masked_pairs, source_ambiguous_masked = (
                _source_unique_masked_pairs(
                    masked_pairs, source_text_rva, source_text,
                    MASKED_WINDOW, signature_cache))
            masked_prefixes = [
                signature_cache[rva][0][:PREFIX_BYTES]
                for _name, rva in masked_pairs
                if all(signature_cache[rva][1][:PREFIX_BYTES])
            ]
            masked_index = _build_filtered_prefix_index(
                target_text, masked_prefixes)
            masked_matches, masked_stats = port_symbols(
                masked_pairs, source_text_rva, source_text,
                target_text_rva, target_text, masked_index,
                window=MASKED_WINDOW, prefix_k=PREFIX_BYTES, masked=True,
                src_sig_cache=signature_cache, pointer_size=8,
                src_function_sizes=source_sizes,
                target_function_starts=target_function_starts,
            )
            masked_matches = [
                match for match in masked_matches
                if target_function_sizes.get(int(match[1]), 0) >= MASKED_WINDOW
            ]
            proposals.extend(
                _proposal_from_match(match, names, source_tag,
                                     source_manifest, "masked", MASKED_WINDOW)
                for match in masked_matches
            )
        except ImportError as error:
            masked_stats = {
                "skipped": len(masked_pairs),
                "reason": "masked matcher dependency unavailable: {}".format(error),
            }

    stats = {
        "source_tag": source_tag,
        "source_path": source_path,
        "source_sha256": source_manifest["sha256"],
        "name_extraction": extraction_stats,
        "eligible_exact": len(eligible_exact_pairs),
        "eligible_masked": len(eligible_masked_pairs),
        "source_ambiguous_exact": source_ambiguous_exact,
        "source_ambiguous_masked": source_ambiguous_masked,
        "exact": exact_stats,
        "masked": masked_stats,
        "proposals": len(proposals),
    }
    return proposals, stats, source_manifest


def _deduplicate_proposals(proposals: Iterable[Proposal]) -> list[Proposal]:
    """Deduplicate identical claims, preferring exact over masked evidence."""
    ranked: dict[tuple, Proposal] = {}
    for proposal in proposals:
        key = (
            proposal.source_sha256,
            proposal.source_rva,
            proposal.target_rva,
            proposal.qualified_name,
        )
        old = ranked.get(key)
        if old is None or (old.match_kind == "masked" and
                           proposal.match_kind == "exact"):
            ranked[key] = proposal
    return sorted(ranked.values(), key=lambda item: (
        item.target_rva, item.qualified_name, item.source_sha256,
        item.source_rva))


def resolve_proposals(
        proposals: Iterable[Proposal]) -> tuple[list[Proposal], dict[Proposal, str],
                                                list[tuple[str, int]]]:
    """Enforce artifact-wide reciprocal uniqueness across all sources.

    All claims participating in a contradiction are rejected; source order is
    never used as a tiebreaker.  Multiple sources may corroborate the exact
    same qualified-name/target-RVA pair.
    """
    unique = _deduplicate_proposals(proposals)
    names_by_target: dict[int, set[str]] = defaultdict(set)
    targets_by_name: dict[str, set[int]] = defaultdict(set)
    for item in unique:
        names_by_target[item.target_rva].add(item.qualified_name)
        targets_by_name[item.qualified_name].add(item.target_rva)

    decisions: dict[Proposal, str] = {}
    accepted_pairs = set()
    for item in unique:
        target_conflict = len(names_by_target[item.target_rva]) != 1
        name_conflict = len(targets_by_name[item.qualified_name]) != 1
        if target_conflict and name_conflict:
            decision = "rejected_target_and_name_conflict"
        elif target_conflict:
            decision = "rejected_target_conflict"
        elif name_conflict:
            decision = "rejected_name_conflict"
        else:
            decision = "accepted"
            accepted_pairs.add((item.qualified_name, item.target_rva))
        decisions[item] = decision
    return unique, decisions, sorted(accepted_pairs, key=lambda pair: (pair[1], pair[0]))


def _qualified_target_name(function) -> str:
    symbol = function.getSymbol()
    local = str(symbol.getName())
    namespace = _namespace_parts(symbol)
    return "::".join(namespace + (local,))


def _target_mapping_decisions(
        target_program, accepted_pairs: Sequence[tuple[str, int]]) -> tuple[
            dict[tuple[str, int], str], dict[tuple[str, int], str]]:
    """Classify accepted mappings without changing the target."""
    from ghidra.program.model.symbol import SourceType

    base = target_program.getImageBase()
    manager = target_program.getFunctionManager()
    decisions = {}
    before_names = {}
    for qualified_name, rva in accepted_pairs:
        function = manager.getFunctionAt(base.add(int(rva)))
        key = (qualified_name, rva)
        if function is None:
            decisions[key] = "rejected_not_target_function_entry"
            before_names[key] = ""
            continue
        current = _qualified_target_name(function)
        before_names[key] = current
        symbol = function.getSymbol()
        if current == qualified_name:
            decisions[key] = "preserved_existing_same_name"
        elif (symbol.getSource() != SourceType.DEFAULT or
              not _DEFAULT_FUNCTION_RE.match(str(symbol.getName()))):
            decisions[key] = "preserved_existing_nondefault_name"
        else:
            decisions[key] = "would_apply"
    return decisions, before_names


def _ensure_namespace(program, parts: Sequence[str]):
    from ghidra.program.model.symbol import SourceType

    symbol_table = program.getSymbolTable()
    current = program.getGlobalNamespace()
    for part in parts:
        namespace = symbol_table.getNamespace(part, current)
        if namespace is None:
            namespace = symbol_table.createNameSpace(
                current, part, SourceType.ANALYSIS)
        current = namespace
    return current


def _name_is_occupied(program, namespace, local_name: str, address) -> bool:
    symbol_table = program.getSymbolTable()
    symbols = symbol_table.getSymbols(local_name, namespace)
    for symbol in symbols:
        try:
            if symbol.getAddress() != address:
                return True
        except Exception:
            return True
    return False


def _apply_mappings(
        target_program, accepted_pairs: Sequence[tuple[str, int]],
        mapping_decisions: dict[tuple[str, int], str],
        proposal_by_pair: dict[tuple[str, int], Proposal],
        config: PortConfig = SKYRIM_CONFIG) -> dict[tuple[str, int], str]:
    """Apply only mappings classified as ``would_apply`` in one transaction."""
    from ghidra.program.model.symbol import SourceType

    outcomes = dict(mapping_decisions)
    base = target_program.getImageBase()
    manager = target_program.getFunctionManager()
    had_parent_transaction = (
        target_program.getCurrentTransactionInfo() is not None)
    tx = target_program.startTransaction(config.transaction_name)
    commit = False
    try:
        for qualified_name, rva in accepted_pairs:
            key = (qualified_name, rva)
            if outcomes.get(key) != "would_apply":
                continue
            function = manager.getFunctionAt(base.add(int(rva)))
            if function is None:
                outcomes[key] = "apply_skipped_not_function_entry"
                continue
            # Re-check immediately before mutation so a concurrent/manual name
            # cannot be overwritten after the dry-run classification.
            refreshed, _ = _target_mapping_decisions(target_program, [key])
            if refreshed[key] != "would_apply":
                outcomes[key] = refreshed[key]
                continue
            proposal = proposal_by_pair[key]
            try:
                namespace = _ensure_namespace(target_program, proposal.namespace)
                if _name_is_occupied(
                        target_program, namespace, proposal.local_name,
                        function.getEntryPoint()):
                    outcomes[key] = "apply_skipped_qualified_name_occupied"
                    continue
                function.getSymbol().setNameAndNamespace(
                    proposal.local_name, namespace, SourceType.ANALYSIS)
                outcomes[key] = "applied"
            except Exception as error:
                outcomes[key] = "apply_error_{}".format(
                    type(error).__name__.replace(",", "_"))
        apply_errors = [decision for decision in outcomes.values()
                        if str(decision).startswith("apply_error_")]
        if apply_errors:
            raise RuntimeError(
                "reciprocal byte-signature apply had {} mutation error(s); "
                "rolling back the pass".format(len(apply_errors)))
        commit = True
    finally:
        committed = bool(target_program.endTransaction(tx, commit))
        if commit and not had_parent_transaction and not committed:
            raise RuntimeError(
                "reciprocal byte-signature transaction did not commit")
    return outcomes


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _write_evidence(
        evidence_path: Path, proposals: Sequence[Proposal],
        proposal_decisions: dict[Proposal, str],
        mapping_decisions: dict[tuple[str, int], str],
        before_names: dict[tuple[str, int], str], target_manifest: dict,
        source_manifests: Sequence[dict], run_stats: Sequence[dict],
        mode: str, config: PortConfig = SKYRIM_CONFIG) -> None:
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=evidence_path.name + ".", suffix=".tmp",
        dir=str(evidence_path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for proposal in proposals:
                pair = (proposal.qualified_name, proposal.target_rva)
                decision = proposal_decisions[proposal]
                if decision == "accepted":
                    decision = mapping_decisions.get(pair, "accepted")
                writer.writerow({
                    "target_sha256": config.target_sha256,
                    "target_program_path": target_manifest["program_path"],
                    "target_rva": "0x{:08X}".format(proposal.target_rva),
                    "qualified_name": proposal.qualified_name,
                    "namespace": "::".join(proposal.namespace),
                    "local_name": proposal.local_name,
                    "match_kind": proposal.match_kind,
                    "signature_bytes": proposal.signature_bytes,
                    "decision": decision,
                    "target_name_before": before_names.get(pair, ""),
                    "source_tag": proposal.source_tag,
                    "source_sha256": proposal.source_sha256,
                    "source_program_path": proposal.source_program_path,
                    "source_name_type": proposal.source_name_type,
                    "source_rva": "0x{:08X}".format(proposal.source_rva),
                })
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, evidence_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

    counts = Counter()
    for proposal in proposals:
        decision = proposal_decisions[proposal]
        if decision == "accepted":
            decision = mapping_decisions.get(
                (proposal.qualified_name, proposal.target_rva), "accepted")
        counts[decision] += 1
    sidecar = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "artifact": evidence_path.name,
        "artifact_sha256": _sha256_file(evidence_path),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "matcher": {
            "exact_window": EXACT_WINDOW,
            "masked_window": MASKED_WINDOW,
            "prefix_bytes": PREFIX_BYTES,
            "requirements": [
                "unique_signature_match",
                "source_function_entry_and_bounds",
                "target_function_entry_and_bounds",
                "artifact_wide_qualified_name_target_rva_reciprocity",
                "preserve_nondefault_target_names",
            ],
        },
        "target": target_manifest,
        "expected_target": {
            "product_version": config.target_product_version,
            "sha256": config.target_sha256,
        },
        "sources": list(source_manifests),
        "proposal_count": len(proposals),
        "decision_counts": dict(sorted(counts.items())),
        "run_stats": list(run_stats),
    }
    _atomic_json(Path(str(evidence_path) + ".identity.json"), sidecar)


def _record_apply_provenance(
        program, evidence_path: Path,
        mapping_decisions: dict[tuple[str, int], str],
        accepted_pairs: Sequence[tuple[str, int]], config: PortConfig) -> None:
    """Bind a completed apply ledger back into the mutable Program."""
    from ghidra.program.model.listing import Program

    applied = sum(1 for decision in mapping_decisions.values()
                  if decision == "applied")
    satisfied = sum(1 for decision in mapping_decisions.values()
                    if decision in ("applied", "preserved_existing_same_name"))
    apply_errors = [decision for decision in mapping_decisions.values()
                    if str(decision).startswith("apply_error_")]
    if apply_errors:
        raise RuntimeError(
            "reciprocal byte-signature apply had {} mutation error(s)".format(
                len(apply_errors)))
    info = program.getOptions(Program.PROGRAM_INFO)
    had_parent_transaction = program.getCurrentTransactionInfo() is not None
    transaction = program.startTransaction(
        "Record reciprocal byte-signature provenance")
    success = False
    try:
        info.setString("BGS Reciprocal Bytesig Target SHA256",
                       config.target_sha256)
        info.setString("BGS Reciprocal Bytesig Evidence SHA256",
                       _sha256_file(evidence_path))
        info.setLong("BGS Reciprocal Bytesig Accepted Count",
                     int(len(accepted_pairs)))
        info.setLong("BGS Reciprocal Bytesig Applied Count", int(applied))
        info.setLong("BGS Reciprocal Bytesig Satisfied Count", int(satisfied))
        info.setString(
            "BGS Reciprocal Bytesig Source Pins",
            json.dumps(dict(config.allowed_source_sha256), sort_keys=True))
        success = True
    finally:
        committed = bool(program.endTransaction(transaction, success))
        if success and not had_parent_transaction and not committed:
            raise RuntimeError(
                "byte-signature provenance transaction did not commit")


def _find_domain_file(root, exact_path: str):
    wanted = "/" + exact_path.strip("/")
    found = []

    def walk(folder, prefix=""):
        for domain_file in folder.getFiles():
            path = prefix + "/" + str(domain_file.getName())
            if path == wanted:
                found.append(domain_file)
        for child in folder.getFolders():
            walk(child, prefix + "/" + str(child.getName()))

    walk(root)
    if len(found) != 1:
        raise RuntimeError("expected one Ghidra program at {}, found {}".format(
            wanted, len(found)))
    return found[0]


def _parse_source_specs(
        specs: Sequence[str] | None,
        config: PortConfig = SKYRIM_CONFIG) -> list[tuple[str, str]]:
    if not specs:
        return list(config.default_sources)
    parsed = []
    seen_tags = set()
    for spec in specs:
        if "=" not in spec:
            raise ValueError("source must be TAG=/exact/project/path: {!r}".format(spec))
        tag, path = spec.split("=", 1)
        tag = tag.strip()
        path = "/" + path.strip().strip("/")
        if not tag or not path or tag in seen_tags:
            raise ValueError("invalid or duplicate source specification: {!r}".format(spec))
        config.source_sha256_for_path(path)
        seen_tags.add(tag)
        parsed.append((tag, path))
    return parsed


def _run(
        target_program, target_path: str,
        source_specs: Sequence[tuple[str, str]],
        open_source: Callable[[str], tuple[object, Callable[[], None]]],
        evidence_path: Path, apply: bool, save: bool, monitor=None,
        config: PortConfig = SKYRIM_CONFIG) -> dict:
    target_manifest = _assert_target_identity(
        target_program, target_path, config=config)
    _assert_analysis_idle(target_program)
    target_sizes, target_starts = _function_boundaries(target_program)
    _, target_text_rva, target_text = _load_text_block(target_program)
    print("Target: {} sha256={} .text={:#x}+{:,}".format(
        target_path, config.target_sha256, target_text_rva, len(target_text)))
    print("Target analyzed function entries: {:,}".format(len(target_starts)))

    proposals: list[Proposal] = []
    source_manifests = []
    run_stats = []
    for source_tag, source_path in source_specs:
        print("Source {}: {}".format(source_tag, source_path))
        source_program, release = open_source(source_path)
        try:
            _assert_analysis_idle(source_program)
            matched, stats, manifest = _match_source(
                source_program, source_tag, source_path,
                target_text_rva, target_text, target_sizes, target_starts,
                config=config)
            proposals.extend(matched)
            source_manifests.append(manifest)
            run_stats.append(stats)
            print("  named={:,} exact={} masked={} proposals={:,}".format(
                stats["name_extraction"].get("accepted_names", 0),
                stats["exact"].get("ok", 0),
                stats["masked"].get("ok", 0),
                len(matched)))
        finally:
            release()

    proposals, proposal_decisions, accepted_pairs = resolve_proposals(proposals)
    mapping_decisions, before_names = _target_mapping_decisions(
        target_program, accepted_pairs)
    # Persist a complete pre-mutation ledger even if an apply later fails.
    _write_evidence(
        evidence_path, proposals, proposal_decisions, mapping_decisions,
        before_names, target_manifest, source_manifests, run_stats,
        mode="apply_preflight" if apply else "dry_run", config=config)

    if apply:
        proposal_by_pair = {}
        accepted_pair_set = set(accepted_pairs)
        for proposal in proposals:
            pair = (proposal.qualified_name, proposal.target_rva)
            if pair in accepted_pair_set:
                proposal_by_pair.setdefault(pair, proposal)
        mapping_decisions = _apply_mappings(
            target_program, accepted_pairs, mapping_decisions,
            proposal_by_pair, config=config)
        _write_evidence(
            evidence_path, proposals, proposal_decisions, mapping_decisions,
            before_names, target_manifest, source_manifests, run_stats,
            mode="apply", config=config)
        _record_apply_provenance(
            target_program, evidence_path, mapping_decisions,
            accepted_pairs, config)
        if save:
            if monitor is None:
                from ghidra.util.task import ConsoleTaskMonitor
                monitor = ConsoleTaskMonitor()
            target_program.save(config.save_description, monitor)

    final_counts = Counter()
    for proposal in proposals:
        decision = proposal_decisions[proposal]
        if decision == "accepted":
            decision = mapping_decisions.get(
                (proposal.qualified_name, proposal.target_rva), "accepted")
        final_counts[decision] += 1
    result = {
        "target_sha256": config.target_sha256,
        "evidence_path": str(evidence_path),
        "proposal_count": len(proposals),
        "accepted_mapping_count": len(accepted_pairs),
        "decision_counts": dict(sorted(final_counts.items())),
        "applied": bool(apply),
        "saved": bool(apply and save),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def run_live(
        target_program, state, monitor=None,
        source_specs: Sequence[tuple[str, str]] | None = None,
        evidence_path: str | os.PathLike | None = None,
        apply: bool = False, save: bool = False,
        config: PortConfig = SKYRIM_CONFIG) -> dict:
    """Run against ``currentProgram`` without opening/locking the project.

    ``source_specs`` is a sequence of ``(tag, exact_project_path)`` pairs.
    Dry-run remains the default.  Set both ``apply=True`` and ``save=True`` to
    persist accepted names into the live project after evidence review.
    """
    import java.lang
    if monitor is None:
        from ghidra.util.task import ConsoleTaskMonitor
        monitor = ConsoleTaskMonitor()

    project = state.getProject()
    if project is None:
        raise RuntimeError("live Ghidra state has no open project")
    root = project.getProjectData().getRootFolder()
    sources = list(source_specs or config.default_sources)
    consumer = java.lang.Object()

    def open_source(path: str):
        domain_file = _find_domain_file(root, path)
        program = domain_file.getDomainObject(consumer, False, False, monitor)
        return program, lambda: program.release(consumer)

    return _run(
        target_program=target_program,
        target_path=_program_path(target_program),
        source_specs=sources,
        open_source=open_source,
        evidence_path=(Path(evidence_path) if evidence_path else
                       config.default_evidence),
        apply=apply,
        save=save,
        monitor=monitor,
        config=config,
    )


def main(
        argv: Sequence[str] | None = None,
        config: PortConfig = SKYRIM_CONFIG,
        description: str | None = None) -> int:
    parser = argparse.ArgumentParser(description=description or __doc__)
    parser.add_argument("--project-dir", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--target-path", default=config.default_target_path,
                        help="exact target path inside the Ghidra project")
    parser.add_argument(
        "--source", action="append", default=None,
        metavar="TAG=/PROJECT/PATH", help=config.source_help)
    parser.add_argument("--evidence", default=str(config.default_evidence))
    parser.add_argument("--apply", action="store_true",
                        help="apply accepted names (default is dry-run)")
    args = parser.parse_args(argv)
    source_specs = _parse_source_specs(args.source, config=config)

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    import java.lang
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    consumer = java.lang.Object()
    with pyghidra.open_project(
            args.project_dir, args.project_name, create=False) as project:
        root = project.getProjectData().getRootFolder()
        target_file = _find_domain_file(root, args.target_path)
        target_program = target_file.getDomainObject(
            consumer, bool(args.apply), False, monitor)
        try:
            def open_source(path: str):
                source_file = _find_domain_file(root, path)
                program = source_file.getDomainObject(
                    consumer, False, False, monitor)
                return program, lambda: program.release(consumer)

            _run(
                target_program=target_program,
                target_path="/" + args.target_path.strip("/"),
                source_specs=source_specs,
                open_source=open_source,
                evidence_path=Path(args.evidence),
                apply=bool(args.apply),
                save=bool(args.apply),
                monitor=monitor,
                config=config,
            )
        finally:
            target_program.release(consumer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
