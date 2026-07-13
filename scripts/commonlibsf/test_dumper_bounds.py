#!/usr/bin/env python3
"""Standalone test for dump_vtable_layouts.py's vtable-bound strategies.

Reproduces dump_vtable_layouts.py's slot-walking logic in pure Python so
we can test it without a Ghidra session.  Three strategies tested:

  current : end_addr = typed_len-from-ghidra-data-type (under-reads when
            Ghidra applied a small <Class>::vftable struct)
  next_va : end_addr = next VTABLE_<Class> symbol address (under-reads
            when intra-vtable labels exist within a vtable)
  block   : end_addr = .text/.rdata block boundary; rely on the slot's
            .text check to terminate at the next vtable's COL pointer
            (which sits in .rdata)

Synthetic input: Actor-shaped vtable (400 function pointers, followed by
the next vtable's COL pointer in .rdata).  Verifies each strategy
produces the expected slot count.

Run: python -m pytest test_dumper_bounds.py  (or just `python ...py`)
"""
from typing import Callable, Dict, List


# ---------------------------------------------------------------------------
# Pure-python mimic of _read_slot_pointers from dump_vtable_layouts.py
# ---------------------------------------------------------------------------

IMAGE_LO = 0x140000000
IMAGE_HI = 0x200000000


def slot_walk(vaddr: int, end_addr: int,
              read_qword: Callable[[int], int],
              is_executable: Callable[[int], bool]) -> List[int]:
    out: List[int] = []
    cur = vaddr
    while cur + 8 <= end_addr:
        ptr = read_qword(cur)
        if ptr == 0:
            break
        if ptr < IMAGE_LO or ptr > IMAGE_HI:
            break
        if not is_executable(ptr):
            break
        out.append(ptr)
        cur += 8
    return out


# ---------------------------------------------------------------------------
# Synthetic memory + executability oracle
# ---------------------------------------------------------------------------

TEXT_START   = 0x140001000
TEXT_END     = 0x140800000
RDATA_START  = 0x144000000
RDATA_END    = 0x145000000

VTABLE_ACTOR     = 0x144B00000          # in .rdata
VTABLE_NEXT_LBL  = VTABLE_ACTOR + 24    # intra-vtable label, only 24 bytes in
                                        # (mimics what we saw in the tester's CSV)
ACTOR_REAL_SLOTS = 400                  # actual primary vtable slot count

# Lay out Actor's vtable: 400 .text pointers, then a COL pointer (.rdata).
MEM: Dict[int, int] = {}
for i in range(ACTOR_REAL_SLOTS):
    MEM[VTABLE_ACTOR + i * 8] = TEXT_START + i * 16   # synthetic .text func pointer
# slot ACTOR_REAL_SLOTS is the next vtable's COL pointer (in .rdata):
MEM[VTABLE_ACTOR + ACTOR_REAL_SLOTS * 8] = RDATA_START + 0x100


def read_qword(addr: int) -> int:
    return MEM.get(addr, 0)


def is_executable(addr: int) -> bool:
    return TEXT_START <= addr < TEXT_END


# ---------------------------------------------------------------------------
# Three bound strategies
# ---------------------------------------------------------------------------

# (1) "current": typed_len = 16 (Ghidra's RTTI analyzer applied a 2-slot
#     <Class>::vftable struct at the address -- this is what we see in
#     the tester's project for Actor/TESForm/PlayerCharacter)
end_current = VTABLE_ACTOR + 16

# (2) "next_va": next VTABLE_<X> symbol address, which is only 24 bytes
#     into Actor's vtable (some intra-vtable label)
end_next_va = VTABLE_NEXT_LBL

# (3) "block": let the slot's .text check terminate; only the .rdata
#     block boundary acts as an upper bound
end_block = RDATA_END


# ---------------------------------------------------------------------------
# Run + report
# ---------------------------------------------------------------------------

def main() -> int:
    print('Synthetic: Actor-shaped vtable, real slot count = {}'.format(ACTOR_REAL_SLOTS))
    print('No fixed slot cap; terminate on mapped/executable pointer validity')
    print()

    cases = [
        ('current  (typed_len=16 from Ghidra)', end_current, 2),
        ('next_va  (next VTABLE_* @ +24)',      end_next_va, 3),
        ('block    (rely on .text check)',      end_block, ACTOR_REAL_SLOTS),
    ]
    failures = 0
    for label, end, expected in cases:
        got = slot_walk(VTABLE_ACTOR, end, read_qword, is_executable)
        n = len(got)
        ok = 'PASS' if n == expected else 'FAIL'
        print('  {}  {:50s}  got={:3d}  expected={:3d}'.format(ok, label, n, expected))
        if n != expected:
            failures += 1

    print()
    if failures:
        print('FAILED: {} test(s) did not match expected'.format(failures))
        return 1
    print('All three bounds produce the predicted slot counts.')
    print('Conclusion: use the memory-block bound plus executable-pointer terminator.')
    return 0


def test_block_bound_does_not_truncate_large_vtable():
    got = slot_walk(VTABLE_ACTOR, end_block, read_qword, is_executable)
    assert len(got) == ACTOR_REAL_SLOTS


if __name__ == '__main__':
    raise SystemExit(main())
