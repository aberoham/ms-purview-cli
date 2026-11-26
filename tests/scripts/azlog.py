#!/usr/bin/env python3
"""Reads the call log that tests/scripts/fake-bin/az writes.

Usage: azlog.py calls LOG | mutations LOG | sleeps LOG

  calls      each az call, its arguments joined by spaces (sleeps left out)
  mutations  each Graph write as "METHOD path body", taken from the exact
             arguments, so a body split over several arguments shows up
  sleeps     the number of polling sleeps
"""

import json
import sys

GRAPH = "https://graph.microsoft.com/v1.0"


def read(path):
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def options(argv):
    """Maps each option to its value; command words come first."""
    values, i = {}, 0
    while i < len(argv) and not argv[i].startswith("-"):
        i += 1
    while i + 1 < len(argv):
        values[argv[i]] = argv[i + 1]
        i += 2
    return values


def main():
    mode, path = sys.argv[1], sys.argv[2]
    calls = read(path)
    if mode == "sleeps":
        print(sum(1 for argv in calls if argv[:1] == ["sleep"]))
        return 0
    for argv in calls:
        if argv[:1] == ["sleep"]:
            continue
        if mode == "calls":
            print(" ".join(argv))
            continue
        given = options(argv)
        if argv[:1] != ["rest"] or given.get("--method") == "GET":
            continue
        path_part = given.get("--url", "").removeprefix(GRAPH)
        print(f"{given.get('--method')} {path_part} {given.get('--body', '(no body)')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
