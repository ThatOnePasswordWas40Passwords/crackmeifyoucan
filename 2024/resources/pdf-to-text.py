#!/usr/bin/env python

from pypdf import PdfReader
from sys import argv

reader = PdfReader(argv[1])

lines = [page.extract_text() for page in reader.pages if page.extract_text().strip() != ""]

if len(lines) == 0:
    print(f"{argv[1]} failed to get text")

if len(argv) == 3:
    with open(argv[2], "w") as outfile:
        for line in lines:
            outfile.write(f"{line}\n")
else:
    print("\n".join(lines))
