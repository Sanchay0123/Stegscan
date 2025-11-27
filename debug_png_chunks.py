#!/usr/bin/env python3
import struct, sys

path = sys.argv[1]
data = open(path, "rb").read()

assert data.startswith(b"\x89PNG\r\n\x1a\n")

print("FILE:", path)
i = 8
while i < len(data):
    if i + 8 > len(data):
        break
    length = struct.unpack(">I", data[i:i+4])[0]
    ctype = data[i+4:i+8]
    print(f"Chunk: {ctype.decode(errors='ignore')}  | size: {length}")
    i += length + 12
