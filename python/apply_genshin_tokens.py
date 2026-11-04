#!/usr/bin/env python3
"""Rewrite the obfuscated tokens in source files to a new game build's tokens.

Reads the TSV that map_genshin_tokens.py writes beside its JSON report. Every 11-uppercase-letter word the map
lists is replaced in one pass, in code, strings and comments alike, because the obfuscator gives one original name
one token everywhere. Words the map does not list are left alone and reported.

Only tokens at the accepted confidences are applied (high by default; add medium with --accept high,medium).
Any other token used by the files needs an entry in a reviewed overrides file, a JSON object of
{"OLDTOKEN": {"new": "NEWTOKEN", "evidence": "why"}}. Without one the run stops and changes nothing.

Hard-coded field offsets, code RVAs and byte patterns are not tokens; find and re-derive them separately.

usage: apply_genshin_tokens.py <map.tsv> [--overrides overrides.json] [--accept high,medium] <file>...
"""

import argparse
import json
import re
import sys
from pathlib import Path

TOKEN = re.compile(r"\b[A-Z]{11}\b")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("map", type=Path, help="the TSV beside map_genshin_tokens.py's JSON report")
    parser.add_argument("files", type=Path, nargs="+")
    parser.add_argument("--overrides", type=Path, help="reviewed answers that win over the map")
    parser.add_argument("--accept", default="high", help="comma-separated confidences to apply without review")
    parser.add_argument("--dry-run", action="store_true", help="report only")
    args = parser.parse_args()

    accepted = set(args.accept.split(","))
    rows = {}
    for line in args.map.read_text().splitlines()[1:]:
        old, new, confidence = line.split("\t")[:3]
        rows[old] = (new, confidence)
    overrides = {k: v["new"] for k, v in json.loads(args.overrides.read_text()).items()} if args.overrides else {}

    table, blocked = dict(overrides), {}
    for old, (new, confidence) in rows.items():
        if old in table:
            continue
        if new and confidence in accepted:
            table[old] = new
        else:
            blocked[old] = confidence

    targets = list(table.values())
    if len(targets) != len(set(targets)):
        sys.exit("two old tokens map to one new token; fix the overrides")

    texts = {path: path.read_text() for path in args.files}
    used = {word for text in texts.values() for word in TOKEN.findall(text)}
    unknown = sorted(word for word in used if word not in rows and word not in overrides)
    if unknown:
        print("not in the map, left alone:", " ".join(unknown))
    review = sorted(word for word in used if word in blocked)
    if review:
        sys.exit("review these first and add them to the overrides: "
                 + " ".join(f"{word}({blocked[word]})" for word in review))
    for path, text in texts.items():
        count = sum(1 for word in TOKEN.findall(text) if word in table)
        if count and not args.dry_run:
            path.write_text(TOKEN.sub(lambda m: table.get(m.group(0), m.group(0)), text))
        if count:
            print(f"{path}: {count} tokens")


if __name__ == "__main__":
    main()
