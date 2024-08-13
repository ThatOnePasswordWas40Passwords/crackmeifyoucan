#!/usr/bin/env python

from sys import argv
from json import load
from pathlib import Path

OUTDIR = "hash_outputs"

try:
    from name_that_hash import runner
except ImportError:
    print("Run 'pip install name-that-hash' and retry")
    exit(1)


def load_file(fpath: str) -> list[str]:
    with open(fpath) as infile:
        return [
            line.strip() for line in infile.read().split("\n") if line.strip() != ""
        ]


def main():
    source_hash_list = load_file(argv[1])

    Path(OUTDIR).mkdir(parents=True, exist_ok=True)
    fname = Path(argv[1]).name

    for line in source_hash_list:
        line = line.split(":")
        user = line[0]
        hash = "".join(line[1:])
        if "$RC2" in hash:
            with open(f"{OUTDIR}/{fname}_nth.rc2.hash", "a") as outfile:
                outfile.write(f"{user}:{hash}\n")
            continue

        if "x-isSHA512" in hash:
            with open(f"{OUTDIR}/{fname}_nth.10300.hash", "a") as outfile:
                outfile.write(f"{user}:{hash}\n")
            continue

        if hash.startswith("$2k$"):
            with open(f"{OUTDIR}/{fname}_nth.2k_bcrypt.hash", "a") as outfile:
                outfile.write(f"{user}:{hash}\n")
            continue

        if hash.startswith("$2b$"):
            with open(f"{OUTDIR}/{fname}_nth.2b_bcrypt.hash", "a") as outfile:
                outfile.write(f"{user}:{hash}\n")
            continue

        if hash.startswith("$sm3$"):
            with open(f"{OUTDIR}/{fname}_nth.sm3.hash", "a") as outfile:
                outfile.write(f"{user}:{hash}\n")
            continue

        if hash.startswith("$shiro2$"):
            with open(f"{OUTDIR}/{fname}_nth.shiro2.hash", "a") as outfile:
                outfile.write(f"{user}:{hash}\n")
            continue

        if hash.startswith("v1;PPH1_MD4,"):
            with open(f"{OUTDIR}/{fname}_nth.12800.hash", "a") as outfile:
                outfile.write(f"{user}:{hash}\n")
            continue

        top_result = runner.api_return_hashes_as_dict([hash])[hash][0]

        with open(
            f"{OUTDIR}/{fname}_nth.{top_result['hashcat']}.hash", "a"
        ) as outfile:
            outfile.write(f"{user}:{hash}\n")


if __name__ == "__main__":
    main()
