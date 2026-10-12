#!/usr/bin/env python3
"""Write a copy of dump.cs with each recovered name in a comment after its token, as in `AENMNOIOLNP/*SetMPBParamFloat*/`.

The tokens stay, because the game and the interop wrappers know members only by them.
"""

import argparse
import re
from pathlib import Path


TOKEN = re.compile(r"\b[A-Z]{11}\b")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path, help="dump.cs from GenshinDumpWriter")
    parser.add_argument("names", type=Path, help="nameTranslation.txt from recover_genshin_names.py")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    names = dict(line.rstrip("\n").split("⇨", 1) for line in args.names.read_text(encoding="utf-8").splitlines() if "⇨" in line)
    annotated = 0

    def annotate(match: re.Match) -> str:
        nonlocal annotated
        name = names.get(match.group(0))
        if name is None:
            return match.group(0)
        annotated += 1
        return f"{match.group(0)}/*{name}*/"

    text = TOKEN.sub(annotate, args.dump.read_text(encoding="utf-8"))
    args.output.write_text(text, encoding="utf-8")
    print(f"Annotated {annotated} token occurrences with {len(names)} recovered names")


if __name__ == "__main__":
    main()
