#!/usr/bin/env python

from sys import argv
import time
import datetime
from math import floor

with open(argv[1]) as infile:
    raw = [line.strip() for line in infile.read().split("\n")]

words = argv[2].split(" ")

lines = {}
for l in raw:
    if not l:
        continue

    split = l.split()
    lines[split[0]] = " ".join(split[1:])

pw = []
for word in words:
    if len(word.split(":")) == 3:
        h, m, index = word.split(":")
        pw.append(lines[f"{h}:{m}"].split()[int(index)-1])
    else:
        hh, h, m, index = word.split(":")
        pw.append(lines[f"{hh}:{h}:{m}"].split()[int(index)-1])

    # print(index, lines[f"{h}:{m}"].split()[int(index)])

print(" ".join(pw))
