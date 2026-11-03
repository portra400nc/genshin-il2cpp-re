#!/usr/bin/env python3
"""Recover original names for Genshin's obfuscated identifiers from the metadata export.

The game's names were replaced in the BeeByte obfuscator's style: every
original name maps to one 11-letter token from a salted hash, so one solved
token names every place that uses it. The salt changes with each game build,
so a name table from another build does not apply. Each rule here pairs a
token with a name at one site where the original name is still visible. The
pairs are counted per token and written with the tier the count supports.
"""

import argparse
import collections
import json
import re
from pathlib import Path


TOKEN = re.compile(r"^[A-Z]{11}$")

METHOD_STATIC = 0x10
METHOD_VIRTUAL = 0x40
METHOD_SPECIAL_NAME = 0x800
TYPE_INTERFACE = 0x20

KIND_GENERIC_INSTANCE = 21
KINDS_WITH_DEFINITION = (17, 18, 28)
KINDS_WITH_ELEMENT = (15, 29)

# A rule in CERTAIN_RULES follows from how the C# compiler names things. The
# override and interface rules assume an overriding method keeps the parameter
# names of the method it overrides, which the plain-name check measures. The
# self-name and excel-config rules name a class from a literal, and one such
# site is enough.
CERTAIN_RULES = ("accessor", "delegate", "state-machine")
SINGLE_VOTE_RULES = ("self-name", "excel-config")
INFERRED_MIN_VOTES = 2
INFERRED_MIN_SHARE = 0.9
STATE_MACHINE_MIN_SHARE = 0.5
SELF_NAME_MIN_CLASSES = 5
CLASS_NAME = re.compile(r"^[A-Z][A-Za-z0-9]*$")
STRING_USAGE = 5
EXCEL_PATH = re.compile(r"^Data/_ExcelBinOutput/(\w+ExcelConfig)Data$")
COLLECTION_TYPES = ("Dictionary`2", "List`1")


def is_token(name: str) -> bool:
    return TOKEN.match(name) is not None


def signature(type_ref: dict) -> tuple:
    kind = type_ref["kind"]
    if kind in KINDS_WITH_DEFINITION:
        return (kind, type_ref["definition"])
    if kind in KINDS_WITH_ELEMENT:
        return (kind, signature(type_ref["element_type"]))
    if kind == KIND_GENERIC_INSTANCE:
        return (kind, type_ref.get("index", type_ref.get("generic_name")))
    return (kind,)


def method_key(method: dict) -> tuple:
    name = method["name"].rsplit(".", 1)[-1] if not method["name"].startswith(".") else method["name"]
    return (name, tuple(signature(parameter["type"]) for parameter in method["parameters"]))


class Evidence:
    def __init__(self) -> None:
        self.votes: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)

    def add(self, token: str, name: str, rule: str) -> None:
        if is_token(token) and not is_token(name):
            self.votes[token][(name, rule)] += 1


def parameter_names(method: dict) -> list[str]:
    return [parameter["name"] for parameter in method["parameters"]]


def accessor_pairs(method: dict):
    name = method["name"].rsplit(".", 1)[-1]
    if method["flags"] & METHOD_SPECIAL_NAME and name.startswith(("set_", "add_", "remove_")) and method["parameters"]:
        yield method["parameters"][-1]["name"], "value"


def delegate_pairs(method: dict):
    names = parameter_names(method)
    if method["name"] == "BeginInvoke" and len(names) >= 2:
        yield names[-2], "callback"
        yield names[-1], "object"
    if method["name"] == "EndInvoke" and names:
        yield names[-1], "result"


def method_names(type_def: dict) -> set[str]:
    return {method["name"] for method in type_def["methods"]}


def most_shared(classes: list[dict], members, taken: set[str]) -> str | None:
    """The token most of the classes hold among the members the selector picks, when at least half of them hold it."""
    counts = collections.Counter()
    for type_def in classes:
        counts.update({member["name"] for member in members(type_def) if is_token(member["name"]) and member["name"] not in taken})
    if not counts or len(classes) < 3:
        return None
    token, count = counts.most_common(1)[0]
    return token if count >= len(classes) * STATE_MACHINE_MIN_SHARE else None


def private_fields(type_def: dict, kind: int | None = None) -> list[dict]:
    return [field for field in type_def["fields"] if field["flags"] & 0x7 == 1 and kind in (None, field["type"]["kind"])]


def finally_methods(type_def: dict) -> list[dict]:
    return [
        method
        for method in type_def["methods"]
        if method["flags"] & 0x7 == 1
        and not method["flags"] & (METHOD_VIRTUAL | METHOD_STATIC)
        and not method["parameters"]
        and method["return_type"]["kind"] == 1
    ]


def state_machine_pairs(types: list[dict]):
    """The C# compiler gives iterator and async classes fixed member names, so their tokens are the ones most of those classes share."""
    obfuscated = [type_def for type_def in types if any(is_token(field["name"]) for field in type_def["fields"])]
    iterators = [type_def for type_def in obfuscated if {"MoveNext", "System.Collections.IEnumerator.Reset"} <= method_names(type_def)]
    asyncs = [type_def for type_def in obfuscated if any(name.endswith("SetStateMachine") for name in method_names(type_def))]
    enumerables = [type_def for type_def in iterators if "System.Collections.IEnumerable.GetEnumerator" in method_names(type_def)]
    taken: set[str] = set()

    def claim(token: str | None, name: str):
        if token is not None:
            taken.add(token)
            yield token, name

    def constructor_parameters(type_def: dict) -> list[dict]:
        return [method["parameters"][0] for method in type_def["methods"] if method["name"] == ".ctor" and len(method["parameters"]) == 1]

    state = most_shared(iterators, constructor_parameters, taken)
    yield from claim(state, "<>1__state")
    yield from claim(most_shared(iterators, private_fields, taken), "<>2__current")
    yield from claim(most_shared(iterators, lambda type_def: [field for field in type_def["fields"] if field["flags"] & 0x7 == 6], taken), "<>4__this")
    yield from claim(most_shared(enumerables, lambda type_def: private_fields(type_def, 8), taken), "<>l__initialThreadId")
    finally_token = most_shared([type_def for type_def in iterators if finally_methods(type_def)], finally_methods, taken)
    yield from claim(finally_token, "<>m__Finally1")
    with_finally = [type_def for type_def in iterators if finally_token in method_names(type_def)]
    yield from claim(most_shared(with_finally, private_fields, taken), "<>7__wrap1")
    builder = most_shared(asyncs, lambda type_def: [field for field in type_def["fields"] if field["flags"] & 0x7 == 6 and field["type"]["kind"] == 17], taken)
    yield from claim(builder, "<>t__builder")
    yield from claim(most_shared(asyncs, private_fields, taken), "<>u__1")


def build_base_lookup(types_by_index: dict[int, dict]):
    methods_by_type = {
        index: {method_key(method): method for method in type_def["methods"]} for index, type_def in types_by_index.items()
    }

    def base_method(type_def: dict, key: tuple):
        seen = set()
        parent = type_def["parent"]
        while parent and parent.get("definition") is not None and parent["definition"] not in seen:
            seen.add(parent["definition"])
            base = types_by_index.get(parent["definition"])
            if base is None:
                return None
            found = methods_by_type[parent["definition"]].get(key)
            if found is not None and found["flags"] & METHOD_VIRTUAL:
                return found
            parent = base["parent"]
        return None

    return base_method


def build_interface_table(types: list[dict]) -> dict[tuple, list[str]]:
    """Maps a method shape to its parameter names when every plain-named interface that declares the shape agrees."""
    seen: dict[tuple, set] = collections.defaultdict(set)
    for type_def in types:
        if not type_def["flags"] & TYPE_INTERFACE:
            continue
        for method in type_def["methods"]:
            names = parameter_names(method)
            if names and not is_token(method["name"]) and not any(is_token(name) for name in names):
                seen[method_key(method)].add(tuple(names))
    return {key: list(next(iter(names))) for key, names in seen.items() if len(names) == 1}


def inherited_names(type_def: dict, method: dict, base_method, interface_table):
    """Yields (rule, names) for the declaration the method overrides or the plain-named interface method it implements."""
    if not method["parameters"] or not method["flags"] & METHOD_VIRTUAL or method["flags"] & METHOD_STATIC:
        return
    key = method_key(method)
    base = base_method(type_def, key)
    if base is not None:
        yield "override", parameter_names(base)
    elif not is_token(method["name"]) and key in interface_table:
        yield "interface", interface_table[key]


def collect(types: list[dict], types_by_index: dict[int, dict], families: list[dict], excel_pairs: list[tuple[str, str]]):
    evidence = Evidence()
    for token, name in excel_pairs:
        evidence.add(token, name, "excel-config")
    plain_type_names = {type_def["name"] for type_def in types if not is_token(type_def["name"])}
    for family in families:
        if family["accepted"]:
            for type_def, literal in family["classes"]:
                if literal not in plain_type_names:
                    evidence.add(type_def["name"], literal, "self-name")
    check = collections.defaultdict(lambda: [0, 0])
    base_method = build_base_lookup(types_by_index)
    interface_table = build_interface_table(types)
    for token, name in state_machine_pairs(types):
        evidence.add(token, name, "state-machine")
    for type_def in types:
        for method in type_def["methods"]:
            for token, name in accessor_pairs(method):
                evidence.add(token, name, "accessor")
            if type_def["parent"] and method["name"] in ("BeginInvoke", "EndInvoke") and is_delegate(type_def, types_by_index):
                for token, name in delegate_pairs(method):
                    evidence.add(token, name, "delegate")
            for rule, names in inherited_names(type_def, method, base_method, interface_table):
                for own, inherited in zip(parameter_names(method), names):
                    if is_token(own) != is_token(inherited):
                        evidence.add(own, inherited, rule)
                        evidence.add(inherited, own, rule)
                    elif not is_token(own):
                        check[rule][0] += own == inherited
                        check[rule][1] += 1
    return evidence, check


def self_name_families(types: list[dict], usages: dict, literals: dict[int, str]) -> list[dict]:
    """Finds methods that many classes override to return one literal, where each class returns a different class-like name.

    Such a method returns the name of the class that overrides it, as the ability configs do with their type names. A
    family is rejected if any literal is not CamelCase or is returned by a plain-named class other than that class.
    """
    owners = {method["index"]: (type_def, method["name"]) for type_def in types for method in type_def["methods"]}
    members = collections.defaultdict(list)
    for method_index, literal in literal_only_methods(usages).items():
        type_def, method_name = owners[method_index]
        members[method_name].append((type_def, literals[literal]))
    families = []
    for method_name, found in members.items():
        texts = [text for _, text in found]
        if len(found) < SELF_NAME_MIN_CLASSES or len(set(texts)) != len(texts):
            continue
        accepted = all(CLASS_NAME.match(text) for text in texts) and all(
            is_token(type_def["name"]) or text == type_def["name"] for type_def, text in found
        )
        families.append({"method": method_name, "classes": found, "accepted": accepted})
    return families


def literal_only_methods(usages: dict) -> dict[int, int]:
    """Maps each method whose only metadata usage is one string literal to that literal."""
    result = {}
    for function in usages["functions"]:
        if len(function["lists"]) == 1 and len(function["usages"]) == 1 and function["usages"][0][0] == STRING_USAGE:
            for method_index in function["methods"]:
                result[method_index] = function["usages"][0][1]
    return result


def excel_config_pairs(types: list[dict], types_by_index: dict[int, dict], usages: dict, literals: dict[int, str], generics: dict):
    """Names each Excel row class after its data file.

    A loader class returns `Data/_ExcelBinOutput/<Name>Data` from a method with no other usage and keeps its rows in
    one Dictionary or List field. The row class is `<Name>`, as the plain-named TalkExcelConfig shows.
    """
    owners = {method["index"]: type_def for type_def in types for method in type_def["methods"]}
    for method_index, literal in literal_only_methods(usages).items():
        match = EXCEL_PATH.match(literals[literal])
        if match is None:
            continue
        rows = set()
        for field in owners[method_index]["fields"]:
            generic = generics.get(str(field["type"]["index"]))
            if generic is None or types_by_index[generic["generic_definition"]]["name"] not in COLLECTION_TYPES:
                continue
            row = generic["arguments"][-1]
            if row["kind"] == 0x12:
                rows.add(row["definition"])
        if len(rows) == 1:
            yield types_by_index[rows.pop()]["name"], match.group(1)


def is_delegate(type_def: dict, types_by_index: dict[int, dict]) -> bool:
    parent = types_by_index.get(type_def["parent"].get("definition"))
    return parent is not None and parent["name"] == "MulticastDelegate"


def resolve(evidence: Evidence) -> list[dict]:
    rows = []
    for token, votes in evidence.votes.items():
        by_name = collections.Counter()
        rules = collections.defaultdict(set)
        for (name, rule), count in votes.items():
            by_name[name] += count
            rules[name].add(rule)
        total = sum(by_name.values())
        certain = [name for name in by_name if rules[name] & set(CERTAIN_RULES)]
        if len(certain) == 1:
            name, tier = certain[0], "certain"
        else:
            name, count = by_name.most_common(1)[0]
            if len(certain) > 1:
                tier = "conflict"
            elif len(by_name) == 1 and rules[name] & set(SINGLE_VOTE_RULES):
                tier = "inferred"
            elif count >= INFERRED_MIN_VOTES and count / total >= INFERRED_MIN_SHARE:
                tier = "inferred"
            else:
                tier = "guess"
        rows.append(
            {
                "token": token,
                "name": name,
                "tier": tier,
                "rules": ",".join(sorted(rules[name])),
                "votes": by_name[name],
                "total_votes": total,
                "runner_up": next((other for other, _ in by_name.most_common(2) if other != name), ""),
            }
        )
    demote_collisions(rows)
    rows.sort(key=lambda row: (-row["total_votes"], row["token"]))
    return rows


def demote_collisions(rows: list[dict]) -> None:
    """Two tokens can never stand for the same name, so when accepted pairs collide only the best-supported one stays."""
    claims = collections.defaultdict(list)
    for row in rows:
        if row["tier"] in ("certain", "inferred"):
            claims[row["name"]].append(row)
    for claimants in claims.values():
        claimants.sort(key=lambda row: (row["tier"] != "certain", -row["votes"]))
        for row in claimants[1:]:
            row["tier"] = "collision"


def count_uses(types: list[dict]) -> dict[str, collections.Counter]:
    uses = {kind: collections.Counter() for kind in ("type", "method", "field", "parameter")}
    for type_def in types:
        uses["type"][type_def["name"].split("`")[0]] += 1
        for field in type_def["fields"]:
            uses["field"][field["name"]] += 1
        for method in type_def["methods"]:
            uses["method"][method["name"]] += 1
            for parameter in method["parameters"]:
                uses["parameter"][parameter["name"]] += 1
    return {kind: collections.Counter({name: count for name, count in counter.items() if is_token(name)}) for kind, counter in uses.items()}


def report(rows: list[dict], uses: dict[str, collections.Counter], check: dict, families: list[dict]) -> str:
    lines = []
    accepted = {row["token"] for row in rows if row["tier"] in ("certain", "inferred")}
    guessed = {row["token"] for row in rows if row["tier"] == "guess"}
    lines.append("kind\ttokens\tnamed\tguessed\tuses\tuses_named")
    for kind, counter in uses.items():
        named = [token for token in counter if token in accepted]
        lines.append(
            "\t".join(
                str(value)
                for value in (
                    kind,
                    len(counter),
                    len(named),
                    sum(1 for token in counter if token in guessed),
                    sum(counter.values()),
                    sum(counter[token] for token in named),
                )
            )
        )
    lines.append("")
    lines.append("rule\tplain_sites\tsame_name\tshare")
    for rule, (same, total) in sorted(check.items()):
        lines.append(f"{rule}\t{total}\t{same}\t{same / total:.4f}")
    lines.append("")
    lines.append("self_name_method\tclasses\tobfuscated_classes\taccepted\texamples")
    for family in sorted(families, key=lambda family: (not family["accepted"], -len(family["classes"]))):
        if not family["accepted"] and not all(CLASS_NAME.match(literal) for _, literal in family["classes"]):
            continue
        examples = ", ".join(text for _, text in family["classes"][:3])
        obfuscated = sum(is_token(type_def["name"]) for type_def, _ in family["classes"])
        lines.append(f"{family['method']}\t{len(family['classes'])}\t{obfuscated}\t{family['accepted']}\t{examples}")
    lines.append("")
    tiers = collections.Counter(row["tier"] for row in rows)
    lines.append("tier\ttokens")
    for tier, count in sorted(tiers.items()):
        lines.append(f"{tier}\t{count}")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("api_json", type=Path, help="the --all-images export from export_genshin_metadata.py")
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--usages", type=Path, help="output of decode_genshin_usages.py, to name classes from literals")
    parser.add_argument("--literals", type=Path, help="gi-stringliteral's JSON output for the same build")
    parser.add_argument("--generics", type=Path, help="output of decode_genshin_generic_classes.py, to name Excel row classes")
    args = parser.parse_args()
    if (args.usages is None) != (args.literals is None):
        parser.error("--usages and --literals go together")
    if args.generics and not args.usages:
        parser.error("--generics needs --usages and --literals")

    api = json.loads(args.api_json.read_text())
    types = [type_def for image in api["images"] for type_def in image["types"]]
    types_by_index = {type_def["index"]: type_def for type_def in types}
    families = []
    excel_pairs = []
    if args.usages:
        literals = {entry["index"]: entry["value"] for entry in json.loads(args.literals.read_text())}
        usages = json.loads(args.usages.read_text())
        families = self_name_families(types, usages, literals)
        if args.generics:
            generics = json.loads(args.generics.read_text())["types"]
            excel_pairs = list(excel_config_pairs(types, types_by_index, usages, literals, generics))

    evidence, check = collect(types, types_by_index, families, excel_pairs)
    rows = resolve(evidence)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    columns = ("token", "name", "tier", "rules", "votes", "total_votes", "runner_up")
    with (args.out_dir / "names.tsv").open("w") as stream:
        stream.write("\t".join(columns) + "\n")
        for row in rows:
            stream.write("\t".join(str(row[column]) for column in columns) + "\n")
    with (args.out_dir / "nameTranslation.txt").open("w") as stream:
        for row in rows:
            if row["tier"] in ("certain", "inferred"):
                stream.write(f"{row['token']}⇨{row['name']}\n")
    summary = report(rows, count_uses(types), check, families)
    (args.out_dir / "coverage.tsv").write_text(summary)
    print(summary, end="")


if __name__ == "__main__":
    main()
