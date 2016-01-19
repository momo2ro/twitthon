#!/usr/bin/python
# -*- coding: utf-8 -*-
import codecs
from itertools import zip_longest


def text_encode(text):
    return byte_encode(codecs.encode(text))


def byte_encode(bytes):
    byte_iter = (x for x in bytes)
    chars = ""
    for x, y, z in zip_longest(*[byte_iter]*3, fillvalue=None):
        if y is None:
            sub_split_bytes = [
                x >> 2,
                ((x & 3) << 4)
            ]
        elif z is None:
            sub_split_bytes = [
                x >> 2,
                ((x & 3) << 4) + (y >> 4),
                ((y & 15) << 2)
            ]
        else:
            sub_split_bytes = [
                x >> 2,
                ((x & 3) << 4) + (y >> 4),
                ((y & 15) << 2) + (z >> 6),
                z & 63
            ]
        chars += __bytes_to_chars(sub_split_bytes)
    return chars


def __bytes_to_chars(bytes):
    chars = ""
    for b in bytes:
        if 0 <= b <= 25:
            chars += chr(b + 65)
        elif 26 <= b <= 51:
            chars += chr(b + 71)
        elif 52 <= b <= 61:
            chars += chr(b - 4)
        elif b == 62:
            chars += "+"
        elif b == 63:
            chars += "/"
        else:
            print("fuck")
    return chars + "=" * (4 - len(chars))

if __name__ == "__main__":
    import sys
    print(text_encode(sys.stdin.read()))
