#!/usr/bin/env python3
"""Map obfuscated tokens from one Genshin build to the next.

Each game build re-rolls the salt of the name obfuscator, so every 11-letter
token changes while plain names stay. The obfuscator maps one original name to
one token, so a token pair found at one site holds at every site. This tool
pairs types, methods and fields of the two builds and counts, per old token,
which new token sits at the paired sites.

Sites are paired from these signals, strongest first:
- the same plain name (types by namespace and name, members within a paired type),
- the same recovered original name in both builds' names.tsv,
- the same set of string literals in a method's metadata usages, unique in both builds,
- members of paired types whose signatures agree, in declaration order,
- usage lists of paired methods, aligned by position,
- parameter, return, field and parent types of paired sites.

With both EXEs given, method code joins in: same-length bodies that mostly
match, and the callees of paired functions by call position.

After pairing, genshin_token_checks.py checks every answer independently (the
classes that use each token) and, for the tokens passed with --tokens, also by
signature, call graph, one-line getters and field offsets in code. Each token
gets a confidence: high (a check agrees), medium or low (the matcher alone, or
a proposal from the checks for a token the matcher left open), conflict (a check
prefers another token; review it by hand) or none.

Inputs per build: the output folder of the README's name-recovery steps, which
holds GenshinAllImagesAPI.json, GenshinUsages.json, literals.json,
GenshinGenericTypes.json and GenshinNames/names.tsv, and optionally the build's
GenshinImpact.exe.

Outputs: the JSON report for --tokens, a TSV of every mapped token beside it,
and a TSV of the method pairs with their code RVAs.
"""

import argparse
import bisect
import collections
import difflib
import json
import re
import struct
from pathlib import Path

from genshin_token_checks import Checker


TOKEN = re.compile(r"[A-Z]{11}")
WHOLE_TOKEN = re.compile(r"^[A-Z]{11}$")
DEFINITION_KINDS = (17, 18, 28)
ELEMENT_KINDS = (15, 29)
GENERIC_INSTANCE = 21
USAGE_CLASS, USAGE_METHOD, USAGE_FIELD, USAGE_STRING, USAGE_METHOD_REF = 1, 3, 4, 5, 6
ROUNDS = 20
MIN_LITERALS = 1


def is_token(name: str) -> bool:
    return WHOLE_TOKEN.match(name) is not None


def template(name: str) -> tuple[str, list[str]]:
    """Splits a name into its plain frame and its tokens: `<ABCDEFGHIJK>k__BackingField` -> (`<#>k__BackingField`, [token])."""
    return TOKEN.sub("#", name), TOKEN.findall(name)


class Code:
    """Function bodies of a game EXE, bounded by its .pdata entries."""

    def __init__(self, exe: Path):
        self.data = exe.read_bytes()
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        count = struct.unpack_from("<H", self.data, pe + 6)[0]
        optional = pe + 24
        table = optional + struct.unpack_from("<H", self.data, pe + 20)[0]
        self.sections = [struct.unpack_from("<IIII", self.data, table + 40 * i + 8) for i in range(count)]
        self.section_flags = [struct.unpack_from("<IIII", self.data, table + 40 * i + 8)
                              + (struct.unpack_from("<I", self.data, table + 40 * i + 36)[0],) for i in range(count)]
        rva, size = struct.unpack_from("<II", self.data, optional + 112 + 8 * 3)
        start = self.offset(rva)
        ranges = sorted(set(struct.unpack_from("<II", self.data, start + 12 * i) for i in range(size // 12)))
        self.starts = [a for a, _ in ranges]
        self.ends = [b for _, b in ranges]
        self.cache: dict[int, bytes | None] = {}
        self.start_set = set(self.starts)
        self.known = self.starts

    def learn_starts(self, rvas) -> None:
        """Adds function starts that .pdata lacks, such as leaf methods, so their bodies end at the next known start."""
        self.start_set |= set(rvas)
        self.known = sorted(self.start_set)
        self.cache.clear()

    def callees(self, rva: int | None) -> list[int]:
        """Targets of the rel32 calls and jumps in a function body that land on a function start, in code order."""
        body = self.body(rva)
        if body is None:
            return []
        found = []
        for i in range(len(body) - 4):
            if body[i] in (0xE8, 0xE9):
                target = rva + i + 5 + struct.unpack_from("<i", body, i + 1)[0]
                if target in self.start_set and target != rva:
                    found.append(target)
        return found

    def offset(self, rva: int) -> int:
        for virtual_size, virtual_address, raw_size, raw_offset in self.sections:
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                return rva - virtual_address + raw_offset
        raise ValueError(hex(rva))

    def body(self, rva: int | None) -> bytes | None:
        if not rva:
            return None
        if rva in self.cache:
            return self.cache[rva]
        result = None
        i = bisect.bisect_right(self.starts, rva) - 1
        if i >= 0 and self.starts[i] == rva:
            end = self.ends[i]
        else:
            j = bisect.bisect_right(self.known, rva)
            end = min(self.known[j], rva + 4096) if j < len(self.known) and rva in self.start_set else None
        if end is not None:
            try:
                start = self.offset(rva)
                result = bytes(self.data[start:start + end - rva])
            except ValueError:
                result = None
        self.cache[rva] = result
        return result


def code_similarity(old: bytes | None, new: bytes | None) -> float | None:
    """Share of equal bytes between two same-length bodies, skipping the rel32 after call and jmp opcodes."""
    if old is None or new is None:
        return None
    if len(old) != len(new):
        return 0.0
    equal = total = 0
    i = 0
    while i < len(old):
        if old[i] == new[i] and old[i] in (0xE8, 0xE9) and i + 5 <= len(old):
            equal += 1
            total += 1
            i += 5
            continue
        equal += old[i] == new[i]
        total += 1
        i += 1
    return equal / total if total else None


class Build:
    def __init__(self, folder: Path, exe: Path | None = None):
        self.code = Code(exe) if exe else None
        api = json.loads((folder / "GenshinAllImagesAPI.json").read_text())
        self.types: dict[int, dict] = {}
        self.image_of: dict[int, str] = {}
        self.methods: dict[int, dict] = {}
        self.fields: dict[int, dict] = {}
        self.method_owner: dict[int, int] = {}
        self.field_owner: dict[int, int] = {}
        self.type_refs: dict[int, dict] = {}
        for image in api["images"]:
            for type_def in image["types"]:
                self.types[type_def["index"]] = type_def
                self.image_of[type_def["index"]] = image["name"]
                for method in type_def["methods"]:
                    self.methods[method["index"]] = method
                    self.method_owner[method["index"]] = type_def["index"]
                    self.remember_ref(method["return_type"])
                    for parameter in method["parameters"]:
                        self.remember_ref(parameter["type"])
                for field in type_def["fields"]:
                    self.fields[field["index"]] = field
                    self.field_owner[field["index"]] = type_def["index"]
                    self.remember_ref(field["type"])
                if type_def["parent"]:
                    self.remember_ref(type_def["parent"])
        del api
        self.generics = {int(k): v for k, v in json.loads((folder / "GenshinGenericTypes.json").read_text())["types"].items()}
        self.literals = {row["index"]: row["value"] for row in json.loads((folder / "literals.json").read_text())}
        self.usages: dict[int, list[tuple[int, int]]] = {}
        for function in json.loads((folder / "GenshinUsages.json").read_text())["functions"]:
            pairs = [(kind, index) for kind, index, _slot in function["usages"]]
            for method_index in function["methods"]:
                self.usages[method_index] = pairs
        self.by_code: dict[int, list[int]] = collections.defaultdict(list)
        for index, method in self.methods.items():
            if method["code_rva"]:
                self.by_code[method["code_rva"]].append(index)
        if self.code:
            self.code.learn_starts(self.by_code)
        self.recovered: dict[str, str] = {}
        for line in (folder / "GenshinNames" / "names.tsv").read_text().splitlines()[1:]:
            token, name, tier = line.split("\t")[:3]
            if tier in ("certain", "inferred"):
                self.recovered[token] = name

    def remember_ref(self, ref: dict) -> None:
        if "index" in ref and ref["index"] not in self.type_refs:
            self.type_refs[ref["index"]] = ref

    def definition(self, ref: dict) -> int | None:
        if ref["kind"] in DEFINITION_KINDS:
            return ref.get("definition")
        if ref["kind"] in ELEMENT_KINDS:
            return self.definition(ref["element_type"]) if "element_type" in ref else None
        if ref["kind"] == GENERIC_INSTANCE:
            generic = self.generics.get(ref["index"])
            return generic["generic_definition"] if generic else None
        return None

    def type_parts(self, ref: dict) -> list[int]:
        """Every type definition a type reference names, generic arguments included, in order."""
        kind = ref["kind"]
        if kind in DEFINITION_KINDS:
            return [ref["definition"]] if "definition" in ref else []
        if kind in ELEMENT_KINDS:
            return self.type_parts(ref["element_type"]) if "element_type" in ref else []
        if kind == GENERIC_INSTANCE:
            generic = self.generics.get(ref["index"])
            if generic is None:
                return []
            parts = [generic["generic_definition"]]
            for argument in generic["arguments"]:
                parts.extend(self.type_parts(argument))
            return parts
        return []

    def usage_classes(self, type_index: int) -> list[int]:
        """The type definitions a class usage names, generic arguments included: Singleton<X> gives Singleton and X."""
        ref = self.type_refs.get(type_index)
        if ref is None and type_index in self.generics:
            ref = {"index": type_index, "kind": GENERIC_INSTANCE}
        return self.type_parts(ref) if ref is not None else []


class Pairing:
    """Votes for site pairs of one kind (type, method or field) and the pairs accepted so far."""

    def __init__(self, kind: str):
        self.kind = kind
        self.votes: dict[int, collections.Counter] = collections.defaultdict(collections.Counter)
        self.why: dict[tuple[int, int], set[str]] = collections.defaultdict(set)
        self.sources: dict[tuple[int, int], dict] = collections.defaultdict(dict)
        self.forward: dict[int, int] = {}
        self.backward: dict[int, int] = {}

    def vote(self, old: int, new: int, rule: str, weight: float, source) -> None:
        """Counts one source once, with the largest weight it gave, so propagating a pair again adds nothing."""
        seen = self.sources[(old, new)]
        before = seen.get(source, 0.0)
        if weight > before:
            seen[source] = weight
            self.votes[old][new] += weight - before
        self.why[(old, new)].add(rule)

    def evidence(self, old: int) -> tuple[float, float]:
        """The accepted candidate's votes and the runner-up's."""
        counter = self.votes.get(old, collections.Counter())
        new = self.forward.get(old)
        top = counter.get(new, 0.0)
        rest = max((v for k, v in counter.items() if k != new), default=0.0)
        return top, rest

    def accept(self, old: int, new: int) -> bool:
        if self.forward.get(old, new) != new or self.backward.get(new, old) != old:
            return False
        self.forward[old] = new
        self.backward[new] = old
        return True

    def resolve(self, min_share: float = 0.75) -> int:
        """Accepts each old site's leading candidate when it holds most of the votes and its new site is not claimed."""
        claims: dict[int, list[tuple[float, int]]] = collections.defaultdict(list)
        for old, counter in self.votes.items():
            if old in self.forward:
                continue
            (new, top), *rest = counter.most_common(2) or [(None, 0)]
            total = sum(counter.values())
            if new is None or new in self.backward or top / total < min_share:
                continue
            claims[new].append((top, old))
        added = 0
        for new, olds in claims.items():
            olds.sort(reverse=True)
            if len(olds) > 1 and olds[0][0] < 2 * olds[1][0]:
                continue
            added += self.accept(olds[0][1], new)
        return added


class Matcher:
    def __init__(self, old: Build, new: Build):
        self.old, self.new = old, new
        self.types = Pairing("type")
        self.methods = Pairing("method")
        self.fields = Pairing("field")
        self.token_votes: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
        self.token_rules: dict[tuple[str, str], set[str]] = collections.defaultdict(set)
        self.token_map: dict[str, str] = {}
        self.token_sites: dict[tuple[str, str], list] = collections.defaultdict(list)
        self.propagated_methods: set[int] = set()
        self.code_match: dict[tuple[int, int], float] = {}
        self.propagated_fields: set[int] = set()

    # Seeds.

    def seed_plain_types(self) -> None:
        def keys(build: Build):
            found = collections.defaultdict(list)
            for index, type_def in build.types.items():
                if not TOKEN.search(type_def["name"]) and not TOKEN.search(type_def["namespace"]):
                    found[(build.image_of[index], type_def["namespace"], type_def["name"])].append(index)
            return found

        old_keys, new_keys = keys(self.old), keys(self.new)
        for key, olds in old_keys.items():
            news = new_keys.get(key, [])
            if len(olds) == 1 and len(news) == 1:
                self.types.vote(olds[0], news[0], "plain-name", 100, "plain-name")
                self.types.accept(olds[0], news[0])

    def seed_recovered_names(self) -> None:
        by_name = collections.defaultdict(list)
        for token, name in self.new.recovered.items():
            by_name[name].append(token)
        for token, name in self.old.recovered.items():
            news = by_name.get(name, [])
            if len(news) == 1:
                self.token_vote(token, news[0], "recovered-name", 10)

    def seed_literals(self) -> None:
        def literal_sets(build: Build):
            found = collections.defaultdict(list)
            for method_index, usages in build.usages.items():
                texts = tuple(sorted(build.literals[index] for kind, index in usages if kind == USAGE_STRING))
                if len(texts) >= MIN_LITERALS:
                    found[texts].append(method_index)
            return found

        old_sets, new_sets = literal_sets(self.old), literal_sets(self.new)
        for texts, olds in old_sets.items():
            news = new_sets.get(texts, [])
            if len(olds) == 1 and len(news) == 1:
                weight = 3 if len(texts) > 1 or len(texts[0]) >= 12 else 1
                self.methods.vote(olds[0], news[0], "literals", weight, "literals")

    def type_key(self, build: Build, index: int, old_side: bool):
        """A type as both builds can name it: its paired new index, its plain name, or unknown."""
        if old_side and index in self.types.forward:
            return ("T", self.types.forward[index])
        if not old_side and index in self.types.backward:
            return ("T", index)
        type_def = build.types[index]
        return ("?",) if TOKEN.search(type_def["name"]) else ("N", type_def["namespace"], type_def["name"])

    def ref_key(self, build: Build, ref: dict, old_side: bool):
        return (ref["kind"],) + tuple(self.type_key(build, part, old_side) for part in build.type_parts(ref))

    def fingerprint(self, build: Build, type_def: dict, old_side: bool):
        plain = lambda name: "#" if TOKEN.search(name) else name
        parent = self.ref_key(build, type_def["parent"], old_side) if type_def["parent"] else None
        fields = tuple((f["flags"], plain(f["name"]), self.ref_key(build, f["type"], old_side)) for f in type_def["fields"])
        methods = tuple(
            (m["flags"], plain(m["name"]), self.ref_key(build, m["return_type"], old_side),
             tuple((plain(p["name"]), self.ref_key(build, p["type"], old_side)) for p in m["parameters"]))
            for m in type_def["methods"]
        )
        return hash((type_def["flags"], plain(type_def["name"]), parent, fields, methods))

    def seed_structure(self) -> None:
        """Pairs unpaired types whose whole shape (parent, fields, methods, with plain names and paired types) is unique in both builds."""
        def groups(build: Build, paired: dict, old_side: bool):
            found = collections.defaultdict(list)
            for index, type_def in build.types.items():
                if index not in paired and len(type_def["fields"]) + len(type_def["methods"]) >= 3:
                    found[self.fingerprint(build, type_def, old_side)].append(index)
            return found

        old_groups = groups(self.old, self.types.forward, True)
        new_groups = groups(self.new, self.types.backward, False)
        for key, olds in old_groups.items():
            news = new_groups.get(key, [])
            if len(olds) == 1 and len(news) == 1:
                self.types.vote(olds[0], news[0], "structure", 3, "structure")

    # Propagation.

    def token_vote(self, old: str, new: str, rule: str, weight: float = 1.0) -> None:
        self.token_votes[old][new] += weight
        self.token_rules[(old, new)].add(rule)

    def names_compatible(self, old_name: str, new_name: str) -> bool | None:
        """True if the names agree, False if they contradict, None if the tokens are not mapped yet."""
        old_frame, old_tokens = template(old_name)
        new_frame, new_tokens = template(new_name)
        if old_frame != new_frame or len(old_tokens) != len(new_tokens):
            return False
        unknown = False
        for a, b in zip(old_tokens, new_tokens):
            mapped = self.token_map.get(a)
            if mapped is None:
                unknown = True
            elif mapped != b:
                return False
        return None if unknown else True

    def ref_compatible(self, old_ref: dict, new_ref: dict) -> bool | None:
        if old_ref["kind"] != new_ref["kind"]:
            return False
        old_parts, new_parts = self.old.type_parts(old_ref), self.new.type_parts(new_ref)
        if len(old_parts) != len(new_parts):
            return False if old_ref["kind"] != GENERIC_INSTANCE or (old_parts and new_parts) else None
        unknown = False
        for a, b in zip(old_parts, new_parts):
            mapped = self.types.forward.get(a)
            if mapped is not None:
                if mapped != b:
                    return False
                continue
            if b in self.types.backward:
                return False
            verdict = self.names_compatible(self.old.types[a]["name"], self.new.types[b]["name"])
            if verdict is False:
                return False
            unknown = True
        return None if unknown else True

    def vote_ref(self, old_ref: dict, new_ref: dict, rule: str, weight: float, source) -> None:
        if old_ref["kind"] != new_ref["kind"]:
            return
        old_parts, new_parts = self.old.type_parts(old_ref), self.new.type_parts(new_ref)
        if len(old_parts) == len(new_parts):
            for a, b in zip(old_parts, new_parts):
                if self.names_compatible(self.old.types[a]["name"], self.new.types[b]["name"]) is not False:
                    self.types.vote(a, b, rule, weight, source)

    def method_score(self, old: dict, new: dict) -> float | None:
        """Agreement between two methods of paired types, or None when they contradict."""
        if (old["flags"] & 0xFFF7) != (new["flags"] & 0xFFF7) or len(old["parameters"]) != len(new["parameters"]):
            return None
        score = 0.0
        verdict = self.names_compatible(old["name"], new["name"])
        if verdict is False:
            return None
        score += 4 if verdict else 0
        checks = [(old["return_type"], new["return_type"])] + [(a["type"], b["type"]) for a, b in zip(old["parameters"], new["parameters"])]
        for a, b in checks:
            verdict = self.ref_compatible(a, b)
            if verdict is False:
                return None
            score += 1 if verdict else 0.25
        for a, b in zip(old["parameters"], new["parameters"]):
            verdict = self.names_compatible(a["name"], b["name"])
            if verdict is False:
                return None
            score += 1 if verdict else 0
        if self.old.code and self.new.code:
            similarity = code_similarity(self.old.code.body(old["code_rva"]), self.new.code.body(new["code_rva"]))
            if similarity is not None:
                self.code_match[(old["index"], new["index"])] = similarity
                score += 4 if similarity >= 0.9 else 2 if similarity >= 0.7 else 0
        return score

    def field_score(self, old: dict, new: dict) -> float | None:
        if old["flags"] != new["flags"] or old.get("default_value") != new.get("default_value") and not (
            isinstance(old.get("default_value"), (int, float)) and isinstance(new.get("default_value"), (int, float))
        ):
            return None
        verdict = self.names_compatible(old["name"], new["name"])
        if verdict is False:
            return None
        score = 4.0 if verdict else 0.0
        type_verdict = self.ref_compatible(old["type"], new["type"])
        if type_verdict is False:
            return None
        score += 1 if type_verdict else 0.25
        if "default_value" in old and old.get("default_value") == new.get("default_value"):
            score += 1
        return score

    def align_members(self, old_items: list[dict], new_items: list[dict], score, pairing: Pairing, rule: str, source) -> None:
        """Pairs members in declaration order within each shape bucket (flags and parameter count, or flags and type kind)."""
        def shape(item: dict):
            if "parameters" in item:
                return item["flags"], len(item["parameters"])
            return item["flags"], item["type"]["kind"]

        buckets = collections.defaultdict(lambda: ([], []))
        for item in old_items:
            buckets[shape(item)][0].append(item)
        for item in new_items:
            buckets[shape(item)][1].append(item)
        for old_bucket, new_bucket in buckets.values():
            self.align_bucket(old_bucket, new_bucket, score, pairing, rule, source)

    def align_bucket(self, old_items: list[dict], new_items: list[dict], score, pairing: Pairing, rule: str, source) -> None:
        """An order-preserving alignment of compatible members, best total score first."""
        if not old_items or not new_items:
            return
        n, m = len(old_items), len(new_items)
        if n * m > 2_000_000:
            return
        table = [[None] * m for _ in range(n)]
        for i, a in enumerate(old_items):
            for j, b in enumerate(new_items):
                s = score(a, b)
                if s is not None:
                    table[i][j] = s + 1
        best = [[0.0] * (m + 1) for _ in range(n + 1)]
        for i in range(n - 1, -1, -1):
            row, below = best[i], best[i + 1]
            for j in range(m - 1, -1, -1):
                s = table[i][j]
                value = below[j] if below[j] > row[j + 1] else row[j + 1]
                if s is not None and s + below[j + 1] > value:
                    value = s + below[j + 1]
                row[j] = value
        i = j = 0
        while i < n and j < m:
            s = table[i][j]
            if s is not None and best[i][j] == s + best[i + 1][j + 1]:
                candidates = sum(1 for x in table[i] if x is not None)
                weight = 2.0 if candidates == 1 else 1.0
                if self.code_match.get((old_items[i]["index"], new_items[j]["index"]), 0.0) >= 0.9:
                    weight += 2.0
                pairing.vote(old_items[i]["index"], new_items[j]["index"], rule, weight, source)
                i += 1
                j += 1
            elif best[i][j] == best[i + 1][j]:
                i += 1
            else:
                j += 1

    def propagate_types(self) -> None:
        for old_index, new_index in list(self.types.forward.items()):
            old_type, new_type = self.old.types[old_index], self.new.types[new_index]
            source = ("members", old_index)
            if any(m["index"] not in self.methods.forward for m in old_type["methods"]):
                self.align_members(old_type["methods"], new_type["methods"], self.method_score, self.methods, "member-order", source)
            if any(f["index"] not in self.fields.forward for f in old_type["fields"]):
                self.align_members(old_type["fields"], new_type["fields"], self.field_score, self.fields, "member-order", source)
            if old_type["parent"] and new_type["parent"]:
                self.vote_ref(old_type["parent"], new_type["parent"], "parent", 2, ("parent", old_index))

    def propagate_methods(self) -> None:
        for old_index, new_index in list(self.methods.forward.items()):
            if old_index in self.propagated_methods:
                continue
            self.propagated_methods.add(old_index)
            old_method, new_method = self.old.methods[old_index], self.new.methods[new_index]
            self.types.vote(self.old.method_owner[old_index], self.new.method_owner[new_index], "owner", 2, ("method", old_index))
            source = ("signature", old_index)
            self.vote_ref(old_method["return_type"], new_method["return_type"], "signature", 1, source + (-1,))
            if len(old_method["parameters"]) == len(new_method["parameters"]):
                for position, (a, b) in enumerate(zip(old_method["parameters"], new_method["parameters"])):
                    self.vote_ref(a["type"], b["type"], "signature", 1, source + (position,))
            self.align_usages(self.old.usages.get(old_index, []), self.new.usages.get(new_index, []), ("usage", old_index))
            self.align_calls(old_method, new_method, old_index)

    def align_usages(self, old_usages: list, new_usages: list, source) -> None:
        if not old_usages or not new_usages:
            return
        old_kinds = [kind for kind, _ in old_usages]
        new_kinds = [kind for kind, _ in new_usages]
        matcher = difflib.SequenceMatcher(None, old_kinds, new_kinds, autojunk=False)
        for block in matcher.get_matching_blocks():
            for k in range(block.size):
                (kind, a), (_, b) = old_usages[block.a + k], new_usages[block.b + k]
                if kind == USAGE_STRING and self.old.literals.get(a) != self.new.literals.get(b):
                    return
        exact = old_kinds == new_kinds
        weight = 1.0 if exact else 0.5
        for block in matcher.get_matching_blocks():
            for k in range(block.size):
                (kind, a), (_, b) = old_usages[block.a + k], new_usages[block.b + k]
                if kind == USAGE_METHOD and a in self.old.methods and b in self.new.methods:
                    if self.names_compatible(self.old.methods[a]["name"], self.new.methods[b]["name"]) is not False:
                        self.methods.vote(a, b, "usage", weight, source)
                elif kind == USAGE_CLASS:
                    old_defs, new_defs = self.old.usage_classes(a), self.new.usage_classes(b)
                    if len(old_defs) == len(new_defs):
                        for old_def, new_def in zip(old_defs, new_defs):
                            if self.names_compatible(self.old.types[old_def]["name"], self.new.types[new_def]["name"]) is not False:
                                self.types.vote(old_def, new_def, "usage", weight, source + (block.a + k, old_def))

    def align_calls(self, old_method: dict, new_method: dict, old_index: int) -> None:
        """Pairs the methods two paired functions call, by call position, when both make the same number of calls."""
        if not (self.old.code and self.new.code):
            return
        old_calls = self.old.code.callees(old_method["code_rva"])
        new_calls = self.new.code.callees(new_method["code_rva"])
        if not old_calls or len(old_calls) != len(new_calls):
            return
        for position, (a, b) in enumerate(zip(old_calls, new_calls)):
            olds, news = self.old.by_code.get(a, []), self.new.by_code.get(b, [])
            if len(olds) == 1 and len(news) == 1:
                old_callee, new_callee = self.old.methods[olds[0]], self.new.methods[news[0]]
                if self.names_compatible(old_callee["name"], new_callee["name"]) is not False:
                    self.methods.vote(olds[0], news[0], "call", 1, ("call", old_index, position))

    def propagate_fields(self) -> None:
        for old_index, new_index in list(self.fields.forward.items()):
            if old_index in self.propagated_fields:
                continue
            self.propagated_fields.add(old_index)
            self.vote_ref(self.old.fields[old_index]["type"], self.new.fields[new_index]["type"], "field-type", 1, ("field", old_index))
            self.types.vote(self.old.field_owner[old_index], self.new.field_owner[new_index], "owner", 2, ("field", old_index))

    def harvest_tokens(self) -> None:
        self.token_votes = collections.defaultdict(collections.Counter, {k: collections.Counter(v) for k, v in self.recovered_votes.items()})
        self.token_rules = collections.defaultdict(set, {k: set(v) for k, v in self.recovered_rules.items()})

        self.token_sites = collections.defaultdict(list)

        def add(old_name: str, new_name: str, site: str, rules: set[str], evidence=None) -> None:
            old_frame, old_tokens = template(old_name)
            new_frame, new_tokens = template(new_name)
            if old_frame == new_frame and len(old_tokens) == len(new_tokens):
                for a, b in zip(old_tokens, new_tokens):
                    self.token_vote(a, b, site, 1)
                    self.token_rules[(a, b)].update(rules)
                    if evidence is not None:
                        self.token_sites[(a, b)].append(evidence)

        for old, new in self.types.forward.items():
            add(self.old.types[old]["name"], self.new.types[new]["name"], "type", self.types.why[(old, new)], ("type", old) + self.types.evidence(old))
        for old, new in self.methods.forward.items():
            old_method, new_method = self.old.methods[old], self.new.methods[new]
            rules = self.methods.why[(old, new)]
            add(old_method["name"], new_method["name"], "method", rules, ("method", old) + self.methods.evidence(old))
            if len(old_method["parameters"]) == len(new_method["parameters"]):
                for a, b in zip(old_method["parameters"], new_method["parameters"]):
                    add(a["name"], b["name"], "parameter", rules)
        for old, new in self.fields.forward.items():
            add(self.old.fields[old]["name"], self.new.fields[new]["name"], "field", self.fields.why[(old, new)], ("field", old) + self.fields.evidence(old))

        self.token_map = {}
        claimed = {}
        for old, counter in self.token_votes.items():
            new, top = counter.most_common(1)[0]
            if top / sum(counter.values()) >= 0.75 and claimed.setdefault(new, old) == old:
                self.token_map[old] = new

    def run(self, log, rounds: int = ROUNDS) -> None:
        self.seed_plain_types()
        self.seed_recovered_names()
        self.recovered_votes = {k: collections.Counter(v) for k, v in self.token_votes.items()}
        self.recovered_rules = {k: set(v) for k, v in self.token_rules.items()}
        self.token_map = {old: counter.most_common(1)[0][0] for old, counter in self.token_votes.items()}
        self.seed_literals()
        self.methods.resolve(min_share=0.99)
        for round_number in range(rounds):
            self.seed_structure()
            self.propagate_types()
            self.propagate_methods()
            self.propagate_fields()
            added = self.types.resolve() + self.methods.resolve() + self.fields.resolve()
            self.harvest_tokens()
            log(f"round {round_number + 1}: types {len(self.types.forward)}, methods {len(self.methods.forward)}, "
                f"fields {len(self.fields.forward)}, tokens {len(self.token_map)}, new pairs {added}")
            if added < 50:
                break

    def site_label(self, build: Build, kind: str, index: int) -> str:
        if kind == "type":
            type_def = build.types[index]
            return f"type {type_def['namespace'] + '.' if type_def['namespace'] else ''}{type_def['name']}"
        owner = build.method_owner[index] if kind == "method" else build.field_owner[index]
        member = build.methods[index] if kind == "method" else build.fields[index]
        return f"{kind} {build.types[owner]['name']}.{member['name']}"

    def old_sites(self, token: str) -> list[str]:
        """Where the token occurs in the old build, and whether each site's owner type is paired."""
        sites = []
        for index, type_def in self.old.types.items():
            if token in type_def["name"]:
                sites.append(f"{self.site_label(self.old, 'type', index)} paired={index in self.types.forward}")
        for kind, table, owners, pairing in (("method", self.old.methods, self.old.method_owner, self.methods),
                                             ("field", self.old.fields, self.old.field_owner, self.fields)):
            for index, member in table.items():
                if token in member["name"]:
                    owner = owners[index]
                    sites.append(f"{self.site_label(self.old, kind, index)} owner_paired={owner in self.types.forward} "
                                 f"paired={index in pairing.forward}")
        return sites[:12]

    def describe(self, old_token: str, explain: bool = True) -> dict:
        counter = self.token_votes.get(old_token, collections.Counter())
        total = sum(counter.values())
        candidates = [
            {"token": new, "votes": votes, "rules": sorted(self.token_rules[(old_token, new)])}
            for new, votes in counter.most_common(4)
        ]
        new = self.token_map.get(old_token)
        sites = self.token_sites.get((old_token, new), []) if new else []
        agreeing = counter[new] if new else 0
        share = agreeing / total if total else 0.0
        strong = [site for site in sites if site[2] >= 3 and site[2] >= 3 * site[3]]
        rules = self.token_rules[(old_token, new)] if new else set()
        if new is None:
            confidence = "none"
        elif share >= 0.95 and (agreeing >= 3 or strong or "recovered-name" in rules):
            confidence = "high"
        elif share >= 0.9 and any(site[2] >= 2 and site[2] > site[3] for site in sites):
            confidence = "medium"
        else:
            confidence = "low"
        row = {"old": old_token, "new": new, "confidence": confidence, "total_votes": total, "candidates": candidates,
               "sites": [{"site": self.site_label(self.old, kind, index), "votes": top, "runner_up": rest}
                         for kind, index, top, rest in sites[:6]]}
        if explain and confidence in ("none", "low"):
            row["old_sites"] = self.old_sites(old_token)
        return row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("old", type=Path, help="output folder of the old build")
    parser.add_argument("new", type=Path, help="output folder of the new build")
    parser.add_argument("output", type=Path, help="JSON report to write; the TSVs go beside it")
    parser.add_argument("--tokens", type=Path, help="text file of the old tokens to report and check in depth, "
                        "for example every token a mod's source uses")
    parser.add_argument("--rounds", type=int, default=ROUNDS, help="most propagation rounds to run")
    parser.add_argument("--old-exe", type=Path, help="old GenshinImpact.exe, to compare method code")
    parser.add_argument("--new-exe", type=Path, help="new GenshinImpact.exe, to compare method code")
    args = parser.parse_args()

    log = lambda text: print(text, flush=True)
    log("loading the old build")
    old = Build(args.old, args.old_exe)
    log("loading the new build")
    new = Build(args.new, args.new_exe)
    matcher = Matcher(old, new)
    matcher.run(log, args.rounds)

    checker = Checker(matcher, log)
    if args.tokens:
        wanted = sorted({word for word in args.tokens.read_text().split() if is_token(word)})
    else:
        wanted = sorted(matcher.token_map)
    log(f"checking {len(wanted)} tokens")
    rows = []
    for token in wanted:
        row = matcher.describe(token)
        row.update(checker.verdict(token, row["confidence"], row["new"], deep=bool(args.tokens)))
        rows.append(row)
    args.output.write_text(json.dumps({"format": "genshin-token-map-v2", "tokens": rows}, indent=1))
    with args.output.with_suffix(".tsv").open("w") as table:
        table.write("old\tnew\tconfidence\tmatcher\tchecks\n")
        checked = {row["old"]: row for row in rows}
        for token in sorted(set(matcher.token_map) | set(wanted)):
            row = checked.get(token)
            if row is None:
                row = matcher.describe(token, explain=False)
                row.update(checker.verdict(token, row["confidence"], row["new"], deep=False))
            checks = ";".join(f"{name}={c['verdict']}:{c['token']}" for name, c in row["checks"].items())
            table.write(f"{token}\t{row['new'] or ''}\t{row['confidence']}\t{row['matcher']}\t{checks}\n")
    with args.output.with_suffix(".methods.tsv").open("w") as table:
        table.write("old_index\tnew_index\told_rva\tnew_rva\told_owner\told_name\tnew_owner\tnew_name\tvotes\trunner_up\n")
        for old_index, new_index in sorted(matcher.methods.forward.items()):
            a, b = old.methods[old_index], new.methods[new_index]
            top, rest = matcher.methods.evidence(old_index)
            table.write(f"{old_index}\t{new_index}\t{a['code_rva'] or 0:#x}\t{b['code_rva'] or 0:#x}\t"
                        f"{old.types[old.method_owner[old_index]]['name']}\t{a['name']}\t"
                        f"{new.types[new.method_owner[new_index]]['name']}\t{b['name']}\t{top:g}\t{rest:g}\n")
    counts = collections.Counter(row["confidence"] for row in rows)
    log(f"wrote {len(rows)} tokens to {args.output}: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))


if __name__ == "__main__":
    main()
