#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Run against a hashcat potfile to convert HEX[...] entries to plaintext.

USAGE:
    ./hexcat2plain.py /path/to/potfile

Mostly taken from https://github.com/ins1gn1a/Hexcat, with some
additions to handle usernames and such.
"""

import sys
import os

with open(sys.argv[1], "r") as passfile:
    passlist = passfile.read().splitlines()


def decode_hex(password):
    decoded = []
    pwd = password
    if "$HEX" in password:
        multihex = list(filter(None, password.split("$")))

        for x in multihex:
            if "HEX[" in x:
                endhex = x.find("]")
                try:
                    decoded.append((bytes.fromhex(x[4:endhex]).decode("utf-8")))
                except:
                    decoded.append((bytes.fromhex(x[4:endhex]).decode("cp1252")))
            else:
                decoded.append(x)

        if len(decoded) != 0:
            pwd = "".join(decoded)
        return pwd

    else:
        return pwd


for line in passlist:
    if ":" in line:
        username, password = line.split(":", 1)
        print(username + ":" + str(decode_hex(password)))
    else:
        print(line, str(decode_hex(line)))
