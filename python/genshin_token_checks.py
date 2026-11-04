"""Independent checks of a token map, run after map_genshin_tokens.py has paired the two builds.

The matcher can pair same-shaped members wrongly, for example two getters of one class that return the same type.
Each check below looks at evidence the matcher's pairing does not decide on its own, and says whether it agrees
with the matcher's answer, prefers another token, or has nothing to say. For tokens the matcher left unmapped,
the checks propose an answer.

- owners: the obfuscator gives one name one token, so the classes that declare members named with the old token,
  translated through the type pairs, should be the classes that declare the new token.
- signature: the method's return and parameter types, translated, must fit; a method that is the only fit in its
  paired class is proposed.
- calls: a method's callers and callees, translated through the method pairs, should be the new method's, and its
  code should look alike.
- getters: a one-line getter reads a field; the field's pair names the getter's pair.
- fields: the offsets that the class's own paired methods use for a field, read at the same place in both builds'
  code, name the field's new offset, and the computed layout names the field there.
"""

import bisect
import collections
import difflib
import re
import struct

from genshin_layout import Layout

TOKEN = re.compile(r"[A-Z]{11}")
EXECUTABLE = 0x20000000
GETTER_FINAL = [
    (re.compile(rb"\x8b\x81(.{4})\xc3", re.S), 4), (re.compile(rb"\x8b\x41(.)\xc3", re.S), 1),
    (re.compile(rb"\x48\x8b\x81(.{4})\xc3", re.S), 4), (re.compile(rb"\x48\x8b\x41(.)\xc3", re.S), 1),
    (re.compile(rb"\x0f\xb6\x81(.{4})\xc3", re.S), 4), (re.compile(rb"\x0f\xb6\x41(.)\xc3", re.S), 1),
    (re.compile(rb"\xf3\x0f\x10\x81(.{4})\xc3", re.S), 4), (re.compile(rb"\xf3\x0f\x10\x41(.)\xc3", re.S), 1),
]
# `mov rax, [rcx+d8]; test rax, rax; je; mov eax, [rax+d32]`, with or without a stack frame: a getter through one field.
GETTER_CHAIN = re.compile(rb"(?:\x48\x83\xec\x28)?\x48\x8b\x41(.)\x48\x85\xc0\x74.\x8b\x80(.{4})(?:\xc3|\xeb)", re.S)
MAX_DIFF_BYTES = 6000


def masked(body: bytes) -> bytes:
    """The body with the rel32 operands of call and jmp opcodes zeroed, so moved callees do not count as changes."""
    out = bytearray(body)
    i = 0
    while i < len(out) - 4:
        if out[i] in (0xE8, 0xE9):
            out[i + 1:i + 5] = b"\0\0\0\0"
            i += 5
        else:
            i += 1
    return bytes(out)


def getter_chain(body: bytes | None) -> list[int] | None:
    """The field offsets a one-line getter reads, outermost first, or None for any other code."""
    if body is None:
        return None
    match = GETTER_CHAIN.match(body)
    if match:
        return [match.group(1)[0], struct.unpack("<i", match.group(2))[0]]
    for pattern, size in GETTER_FINAL:
        match = pattern.match(body)
        if match:
            raw = match.group(1)
            return [raw[0] if size == 1 else struct.unpack("<i", raw)[0]]
    return None


def call_graph(code) -> tuple[dict, dict]:
    """Callees and callers of every function, from rel32 calls and jumps that land on a known function start."""
    starts = sorted(code.start_set)
    ends = {start: end for start, end in zip(code.starts, code.ends)}
    callees, callers = collections.defaultdict(set), collections.defaultdict(set)
    for virtual_size, virtual_address, raw_size, raw_offset, flags in code.section_flags:
        if not flags & EXECUTABLE:
            continue
        data = code.data[raw_offset:raw_offset + raw_size]
        for opcode in (b"\xe8", b"\xe9"):
            i = data.find(opcode)
            while 0 <= i <= len(data) - 5:
                target = virtual_address + i + 5 + int.from_bytes(data[i + 1:i + 5], "little", signed=True)
                if target in code.start_set:
                    site = virtual_address + i
                    k = bisect.bisect_right(starts, site) - 1
                    if k >= 0:
                        owner = starts[k]
                        end = ends.get(owner)
                        if (end is None or site < end) and owner != target:
                            callees[owner].add(target)
                            callers[target].add(owner)
                i = data.find(opcode, i + 1)
    return callees, callers


class Checker:
    def __init__(self, matcher, log):
        self.m = matcher
        self.old, self.new = matcher.old, matcher.new
        self.log = log
        self.old_owners = self.owners_by_token(self.old)
        self.new_owners = self.owners_by_token(self.new)
        self.claimed = {new: old for old, new in matcher.token_map.items()}
        self.graphs = None
        self.layouts = None

    @staticmethod
    def owners_by_token(build) -> dict[str, set[int]]:
        found = collections.defaultdict(set)
        for index, owner in build.method_owner.items():
            for token in TOKEN.findall(build.methods[index]["name"]):
                found[token].add(owner)
        for index, owner in build.field_owner.items():
            for token in TOKEN.findall(build.fields[index]["name"]):
                found[token].add(owner)
        return found

    # Shared helpers.

    def translate(self, name: str) -> str:
        return TOKEN.sub(lambda m: self.m.token_map.get(m.group(0), "?"), name)

    def paired_owner(self, old_owner: int) -> dict | None:
        new_owner = self.m.types.forward.get(old_owner)
        return self.new.types[new_owner] if new_owner is not None else None

    def old_sites(self, token: str, kind: str) -> list[tuple[dict, dict]]:
        """(owner class, member) for each old member of this kind named with the token."""
        if not hasattr(self, "_sites"):
            self._sites = collections.defaultdict(list)
            for site_kind, table, owners in (("method", self.old.methods, self.old.method_owner),
                                             ("field", self.old.fields, self.old.field_owner)):
                for index, member in table.items():
                    for found in set(TOKEN.findall(member["name"])):
                        self._sites[(found, site_kind)].append((self.old.types[owners[index]], member))
        return self._sites.get((token, kind), [])

    def new_name(self, old_name: str, token: str, candidate: str) -> str:
        return TOKEN.sub(lambda m: candidate if m.group(0) == token else self.m.token_map.get(m.group(0), "?"), old_name)

    def signature_fits(self, old_method: dict, new_method: dict) -> bool:
        if (old_method["flags"] & 0xFFF7) != (new_method["flags"] & 0xFFF7) or len(old_method["parameters"]) != len(new_method["parameters"]):
            return False
        refs = [(old_method["return_type"], new_method["return_type"])]
        refs += [(a["type"], b["type"]) for a, b in zip(old_method["parameters"], new_method["parameters"])]
        return all(self.m.ref_compatible(a, b) is not False for a, b in refs)

    def ensure_code(self) -> bool:
        if self.graphs is None and self.old.code and self.new.code:
            self.log("building the call graphs")
            for build in (self.old, self.new):
                build.code.learn_starts(m["code_rva"] for m in build.methods.values() if m["code_rva"])
            self.graphs = (call_graph(self.old.code), call_graph(self.new.code))
            self.anchor = {}
            for old_index, new_index in self.m.methods.forward.items():
                a, b = self.old.methods[old_index]["code_rva"], self.new.methods[new_index]["code_rva"]
                if a and b and len(self.old.by_code[a]) == 1 and len(self.new.by_code[b]) == 1:
                    self.anchor[a] = b
        return self.graphs is not None

    def ensure_layouts(self) -> None:
        if self.layouts is None:
            self.layouts = (Layout(self.old.types, self.old.generics), Layout(self.new.types, self.new.generics))

    # Checks. Each returns (verdict, token) with verdict "agree", "prefer" (another token), or None.

    def check_owners(self, token: str, answer: str | None):
        olds = self.old_owners.get(token, set())
        if len(olds) < 2:
            return None, None
        expected = {self.m.types.forward[o] for o in olds if o in self.m.types.forward}
        unknown = len(olds) - len(expected)
        got = self.new_owners.get(answer, set()) if answer else set()
        if answer and expected <= got and len(got) == len(olds):
            return "agree", answer
        pool = collections.Counter(t for owner in expected for t in self.tokens_of_owner(owner))
        best, best_score = None, 0.0
        for candidate, hits in pool.most_common(40):
            owners = self.new_owners[candidate]
            if expected <= owners and len(owners) == len(olds):
                score = 1.0
            else:
                score = hits / len(expected | owners) if expected | owners else 0.0
            if score > best_score:
                best, best_score = candidate, score
        if best and best != answer and best_score == 1.0 and unknown < len(olds):
            return "prefer", best
        return None, None

    def tokens_of_owner(self, owner: int) -> set[str]:
        cache = getattr(self, "_owner_tokens", None)
        if cache is None:
            cache = self._owner_tokens = collections.defaultdict(set)
            for token, owners in self.new_owners.items():
                for o in owners:
                    cache[o].add(token)
        return cache.get(owner, set())

    def method_candidates(self, old_type: dict, old_method: dict, token: str) -> list[dict]:
        new_type = self.paired_owner(old_type["index"])
        if new_type is None:
            return []
        frame = TOKEN.sub("#", old_method["name"])
        return [m for m in new_type["methods"]
                if TOKEN.sub("#", m["name"]) == frame and self.signature_fits(old_method, m)]

    def candidate_token(self, old_name: str, token: str, new_name: str) -> str | None:
        """The new token that sits where `token` sits in the old name."""
        old_tokens, new_tokens = TOKEN.findall(old_name), TOKEN.findall(new_name)
        if len(old_tokens) != len(new_tokens):
            return None
        return dict(zip(old_tokens, new_tokens)).get(token)

    def check_signature(self, token: str, answer: str | None):
        votes = collections.Counter()
        for old_type, old_method in self.old_sites(token, "method"):
            candidates = self.method_candidates(old_type, old_method, token)
            names = {self.candidate_token(old_method["name"], token, c["name"]) for c in candidates}
            names.discard(None)
            if answer and names and answer not in names:
                return "prefer", sorted(names)[0] if len(names) == 1 else None
            if len(names) == 1:
                votes[names.pop()] += 1
        if len(votes) == 1:
            found = next(iter(votes))
            return ("agree" if found == answer else "prefer"), found
        return None, None

    def check_calls(self, token: str, answer: str | None):
        if not self.ensure_code():
            return None, None
        (old_out, old_in), (new_out, new_in) = self.graphs
        votes = collections.Counter()
        for old_type, old_method in self.old_sites(token, "method"):
            rva = old_method["code_rva"]
            if not rva:
                continue
            callers = {self.anchor[c] for c in old_in.get(rva, ()) if c in self.anchor}
            callees = {self.anchor[c] for c in old_out.get(rva, ()) if c in self.anchor}
            old_body = self.old.code.body(rva)
            scored = []
            for candidate in self.method_candidates(old_type, old_method, token):
                n_rva = candidate["code_rva"]
                if not n_rva:
                    continue
                shared = len(callers & new_in.get(n_rva, set())) + len(callees & new_out.get(n_rva, set()))
                new_body = self.new.code.body(n_rva)
                ratio = 0.0
                if old_body and new_body and len(old_body) < MAX_DIFF_BYTES and len(new_body) < MAX_DIFF_BYTES:
                    ratio = difflib.SequenceMatcher(None, masked(old_body), masked(new_body), autojunk=False).ratio()
                scored.append((shared + 4 * ratio, shared, candidate["name"]))
            scored.sort(reverse=True)
            if not scored:
                continue
            top, shared, name = scored[0]
            runner = scored[1][0] if len(scored) > 1 else 0.0
            if shared >= 1 and top >= 4 and top >= 1.5 * runner:
                found = self.candidate_token(old_method["name"], token, name)
                if found:
                    votes[found] += 1
        if len(votes) == 1:
            found = next(iter(votes))
            return ("agree" if found == answer else "prefer"), found
        return None, None

    def field_pair(self, old_type: dict, old_field: dict) -> tuple[dict | None, dict | None]:
        new_type = self.paired_owner(old_type["index"])
        if new_type is None:
            return None, None
        new_index = self.m.fields.forward.get(old_field["index"])
        if new_index is None:
            name = self.translate(old_field["name"])
            match = [f for f in new_type["fields"] if f["name"] == name]
            return new_type, match[0] if match else None
        return new_type, self.new.fields[new_index]

    def check_getters(self, token: str, answer: str | None):
        if not self.ensure_code():
            return None, None
        self.ensure_layouts()
        old_layout, new_layout = self.layouts
        votes = collections.Counter()
        for old_type, old_method in self.old_sites(token, "method"):
            steps = getter_chain(self.old.code.body(old_method["code_rva"]))
            new_type = self.paired_owner(old_type["index"])
            if not steps or new_type is None:
                continue
            expected, current_old, current_new = [], old_type, new_type
            for offset in steps:
                by_offset = {v: k for k, v in old_layout.offsets(current_old).items()}
                old_field = self.old.fields.get(by_offset.get(offset))
                if old_field is None or current_new is None:
                    break
                _, new_field = self.field_pair(current_old, old_field)
                if new_field is None:
                    break
                expected.append(new_layout.offsets(current_new).get(new_field["index"]))
                current_old = self.old.types.get(old_field["type"].get("definition"))
                current_new = self.new.types.get(new_field["type"].get("definition"))
            if len(expected) != len(steps) or None in expected:
                continue
            hits = [m["name"] for m in new_type["methods"]
                    if m["code_rva"] and len(m["parameters"]) == len(old_method["parameters"])
                    and getter_chain(self.new.code.body(m["code_rva"])) == expected]
            if len(hits) == 1:
                found = self.candidate_token(old_method["name"], token, hits[0])
                if found:
                    votes[found] += 1
        if len(votes) == 1:
            found = next(iter(votes))
            return ("agree" if found == answer else "prefer"), found
        return None, None

    def check_fields(self, token: str, answer: str | None):
        if not self.ensure_code():
            return None, None
        self.ensure_layouts()
        old_layout, new_layout = self.layouts
        votes = collections.Counter()
        for old_type, old_field in self.old_sites(token, "field"):
            new_type = self.paired_owner(old_type["index"])
            if new_type is None:
                continue
            offset = old_layout.offsets(old_type).get(old_field["index"])
            if offset is None:
                continue
            new_offsets = {v: k for k, v in new_layout.offsets(new_type).items()}
            counts = self.offset_votes(old_type["index"], offset)
            if not counts:
                continue
            (best, n), *rest = counts.most_common(2)
            if n >= 2 and (not rest or n >= 2 * rest[0][1]) and best in new_offsets:
                new_field = self.new.fields[new_offsets[best]]
                if self.m.ref_compatible(old_field["type"], new_field["type"]) is not False:
                    found = self.candidate_token(old_field["name"], token, new_field["name"])
                    if found:
                        votes[found] += 1
        # A field whose translated type is unique among the paired class's fields needs no code.
        if not votes:
            for old_type, old_field in self.old_sites(token, "field"):
                new_type = self.paired_owner(old_type["index"])
                if new_type is None:
                    continue
                same = [f for f in new_type["fields"] if f["flags"] == old_field["flags"]
                        and self.m.ref_compatible(old_field["type"], f["type"]) is True]
                if len(same) == 1:
                    found = self.candidate_token(old_field["name"], token, same[0]["name"])
                    if found:
                        votes[found] += 1
        if len(votes) == 1:
            found = next(iter(votes))
            return ("agree" if found == answer else "prefer"), found
        return None, None

    def offset_votes(self, old_owner: int, offset: int) -> collections.Counter:
        """New offsets found where the class's own paired methods use the old one."""
        votes = collections.Counter()
        packed = struct.pack("<i", offset)
        for method in self.old.types[old_owner]["methods"]:
            new_index = self.m.methods.forward.get(method["index"])
            if new_index is None or not method["code_rva"]:
                continue
            a = self.old.code.body(method["code_rva"])
            b = self.new.code.body(self.new.methods[new_index]["code_rva"])
            if not a or not b:
                continue
            if len(a) == len(b):
                start = a.find(packed)
                while start != -1:
                    votes[struct.unpack_from("<i", b, start)[0]] += 1
                    start = a.find(packed, start + 1)
                if offset < 0x80:
                    for i in range(1, len(a)):
                        if a[i] == offset and 0x40 <= a[i - 1] <= 0x7F and a[i - 1] & 7 != 4 and b[i - 1] == a[i - 1]:
                            votes[b[i]] += 1
            elif packed in a and len(a) < MAX_DIFF_BYTES and len(b) < MAX_DIFF_BYTES:
                for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
                    if tag == "equal":
                        votes[offset] += a[i1:i2].count(packed)
                    elif tag == "replace" and i2 - i1 == j2 - j1:
                        start = a.find(packed, max(i1 - 3, 0), i2 + 3)
                        while start != -1:
                            at = start + j1 - i1
                            if 0 < at <= len(b) - 4 and b[at - 1] == a[start - 1]:
                                votes[struct.unpack_from("<i", b, at)[0]] += 1
                            start = a.find(packed, start + 1, i2 + 3)
        return votes

    # The verdict.

    def run_check(self, check, token: str, answer: str | None):
        """A check that cannot decide, for example on a layout it does not model, reports no evidence."""
        try:
            return check(token, answer)
        except (ValueError, KeyError, IndexError, struct.error) as error:
            self.log(f"{token}: {check.__name__} skipped ({type(error).__name__}: {error})")
            return None, None

    def verdict(self, token: str, base: str, answer: str | None, deep: bool) -> dict:
        checks = {"owners": self.run_check(self.check_owners, token, answer)}
        if deep:
            kinds = {kind for kind in ("method", "field") if self.old_sites(token, kind)}
            if "method" in kinds:
                for check in (self.check_signature, self.check_calls, self.check_getters):
                    checks[check.__name__.removeprefix("check_")] = self.run_check(check, token, answer)
            if "field" in kinds:
                checks["fields"] = self.run_check(self.check_fields, token, answer)
        said = {name: result for name, result in checks.items() if result[0]}
        preferred = [found for verdict, found in said.values() if verdict == "prefer"]
        agreeing = [name for name, (verdict, _) in said.items() if verdict == "agree"]
        proposals = collections.Counter(found for _, found in said.values() if found)
        if answer:
            if preferred:
                confidence, new = "conflict", answer
            elif agreeing and (base != "low" or len(agreeing) >= 2):
                confidence, new = "high", answer
            else:
                confidence, new = base, answer
        elif len(proposals) == 1:
            new, count = proposals.most_common(1)[0]
            owner = self.claimed.get(new)
            if owner and owner != token:
                confidence = "conflict"
            else:
                confidence = "medium" if count >= 2 else "low"
        elif proposals:
            confidence, new = "conflict", None
        else:
            confidence, new = "none", None
        return {"old": token, "new": new, "confidence": confidence, "matcher": base,
                "checks": {name: {"verdict": v, "token": t} for name, (v, t) in said.items()}}
