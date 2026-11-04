# genshin-il2cpp-re

Offline tools that decode Genshin Impact's IL2CPP metadata and turn it into files other tools can use. They read the game's files and memory dumps and do not depend on any mod loader. The outputs are metadata JSON, an Il2CppDumper-style `dump.cs`, Cpp2IL-style dummy assemblies, and Il2CppInterop wrappers for MelonLoader, BepInEx, or any other loader built on Il2CppInterop.

## Supported game build

The scripts check their inputs against the game 7.2 build, released on November 4, 2026, before reading them.

| File | Size (bytes) | SHA-256 |
|---|---|---|
| `GenshinImpact.exe` | 451,130,280 | `b3001fc110b63e0e0ce24a77386e71d0eefaffaae244ea0c72645a659cb5ea6e` |
| `global-metadata.dat` | 83,644,132 | `4ed10538735861ad87b027d30039e2afb92e334f1b4de4f643e17c9c79d19fd7` |
| `startup-metadata.dat` | 4,116,228 | `2a5fe7adbeb7cba81db69d7c62dee3536615e5b77efa0514c464e9c9e72d93c0` |

The `7.1` branch holds the tools for the previous build.

A new game build re-rolls every obfuscation constant, and can change formulas, header and record field offsets, and the order of record fields. The build constants live in `python/decode_genshin_strings.py`, `python/inspect_genshin_images.py`, `python/inspect_genshin_types.py`, `python/decode_genshin_usages.py`, `python/decode_genshin_generic_classes.py`, and `python/inspect_genshin_generic_insts.py`. The anchors in `python/export_genshin_metadata.py` and the code checks in `python/inspect_genshin_api.py` also name indices and addresses of one build.

## Layout

| Folder | Contents |
|---|---|
| `python/` | Metadata decoding and export, EXE and PE inspection, memory-dump reading, and mapping tokens from one build to the next. `decode_genshin_strings.py` holds the build constants the other scripts import, so run the scripts from this folder or with it on `PYTHONPATH`. |
| `ghidra/` | Headless Ghidra scripts that decompile or inspect specific native functions. |
| `dotnet/GenshinInteropBatch/` | Builds dummy assemblies from the metadata JSON and runs the pinned Il2CppInterop generator on them. |
| `dotnet/GenshinDumpWriter/` | Writes `dump.cs`, `names.json`, and a Ghidra script that labels functions, all from the dummy assemblies. |
| `docs/` | Notes on the complete metadata export. |

Put the game files in `game/`. Tools write to `out/`. Git ignores both folders, and never commit game files.

## From game files to interop wrappers

The commands need Python 3.10 or later and the .NET 9 SDK.

1. Export the metadata that Unity and the system libraries use.

   ```sh
   python3 python/export_genshin_metadata.py \
     game/GenshinImpact.exe game/global-metadata.dat game/startup-metadata.dat \
     out/GenshinUnityAPI.json --system-libraries --unity-engine
   ```

   Replace `--system-libraries --unity-engine` with `--all-images` to export all 75 images. See `docs/GenshinAllMetadata.md`.

2. Build the dummy assemblies and the interop wrappers.

   ```sh
   dotnet build dotnet/GenshinInteropBatch -c Release
   dotnet dotnet/GenshinInteropBatch/bin/Release/net9.0/GenshinInteropBatch.dll \
     out/GenshinUnityAPI.json out/GenshinInteropBatch --generate
   ```

   `out/GenshinInteropBatch/interop/` then holds the wrappers and `MethodAddressToToken.db`. `dotnet/GenshinInteropBatch/README.md` lists what the generator checks and what the metadata subset still lacks.

3. Write the dump.

   ```sh
   dotnet run --project dotnet/GenshinDumpWriter -- out/GenshinInteropBatch/dummy out/GenshinDump
   ```

## Recovering obfuscated names

Most names in `Assembly-CSharp` are 11-letter tokens. One token always stands for the same original name. The salt changes with each game build, so name tables published for other builds do not apply. `recover_genshin_names.py` pairs tokens with the original names that are still visible next to them.

From the metadata export alone, it names compiler-generated members of iterator, async and delegate classes, property setter parameters, and parameters of methods that override or implement a plain-named declaration.

String literals name about 2,200 classes. The ability configs and several other class families override a method that returns the class's own name, and each Excel row class is named after the data file its loader reads. These rules need three more inputs:

1. Recover the string literals with the third-party [gi-stringliteral](https://github.com/kuma-dayo/gi-stringliteral) at commit `1008fd7`, the version tested with this build. It needs `capstone`.

   ```sh
   git clone https://github.com/kuma-dayo/gi-stringliteral out/gi-stringliteral
   git -C out/gi-stringliteral checkout 1008fd7
   python3 -m venv out/venv && out/venv/bin/pip install capstone
   out/venv/bin/python out/gi-stringliteral/recover_string_literals.py game/global-metadata.dat game/GenshinImpact.exe \
     -o out/literals.json
   ```

2. Decode which literals, classes, methods and fields each method uses.

   ```sh
   python3 python/decode_genshin_usages.py game/GenshinImpact.exe game/global-metadata.dat \
     out/GenshinAllImagesAPI.json out/GenshinUsages.json
   ```

3. Decode the arguments of every generic-instance type.

   ```sh
   python3 python/inspect_genshin_generic_insts.py game/GenshinImpact.exe --output out/GenshinGenericInsts.json
   python3 python/decode_genshin_generic_classes.py game/GenshinImpact.exe game/startup-metadata.dat \
     out/GenshinGenericInsts.json out/GenshinGenericTypes.json
   ```

Then recover the names, and write a copy of `dump.cs` that shows each recovered name in a comment after its token.

```sh
python3 python/recover_genshin_names.py out/GenshinAllImagesAPI.json out/GenshinNames \
  --usages out/GenshinUsages.json --literals out/literals.json --generics out/GenshinGenericTypes.json
python3 python/annotate_genshin_dump.py out/GenshinDump/dump.cs out/GenshinNames/nameTranslation.txt out/GenshinDump/dump-named.cs
```

The output folder holds the following files:

- `names.tsv` lists every pair with its tier and vote counts.
- `nameTranslation.txt` holds the `certain` and `inferred` pairs in the `TOKEN⇨name` format that Il2CppDumper forks read.
- `coverage.tsv` shows how many tokens of each kind were named, the measured override share, and every class family the self-name rule considered.

`certain` pairs follow from compiler naming rules. `inferred` pairs come from overrides, which keep their base method's parameter names in about 94% of plain-named cases, or from the literal rules. Two tokens cannot stand for the same name, so when accepted pairs collide, only the best-supported one is kept, and the others are marked `collision`.

Each Python script prints its usage with `--help`, except `inspect_unity_pe.py`, which takes the EXE path and an optional function RVA.

## Moving code to a new game build

Each game build re-rolls every token, so code that names game classes and members by token, such as a mod, stops compiling or binds to unrelated members. Plain names such as `UnityEngine.*` and `MoleMole.*` stay. One original name still has one token per build, so a token map from the old build to the new one fixes every use of a token at once.

1. Run the name-recovery steps above for both builds, each into its own output folder, for example `out/old` and `out/new`. Keep each build's `GenshinImpact.exe`.

2. List the tokens your code uses.

   ```sh
   grep -rhoE '\b[A-Z]{11}\b' --include='*.cs' path/to/your/code | sort -u > out/my-tokens.txt
   ```

3. Map the tokens. The run takes about half an hour and 10 GB of memory.

   ```sh
   python3 python/map_genshin_tokens.py out/old out/new out/token-map.json --tokens out/my-tokens.txt \
     --old-exe game/old/GenshinImpact.exe --new-exe game/new/GenshinImpact.exe
   ```

   `map_genshin_tokens.py` pairs the classes, methods and fields of the two builds from plain names, recovered names, string literals, member order, signatures, metadata usages and method code. `genshin_token_checks.py` then checks each answer for the listed tokens independently: the classes that use the token, the method's signature, its callers and callees, the field a one-line getter reads, and the offsets that a class's own methods use for a field. Each token in `token-map.json` gets a confidence:

   | Confidence | Meaning |
   |---|---|
   | `high` | A check agrees with the matcher's answer. |
   | `medium`, `low` | Only the matcher answered, or the checks proposed an answer for a token the matcher left open. |
   | `conflict` | A check prefers another token. Review it. |
   | `none` | No answer. |

   Same-shaped members, such as two getters of one class with the same return type, are where the matcher goes wrong, and the checks catch most of those cases. Review every token that is not `high` before you rely on it, for example by comparing the candidates' code. Put each reviewed answer in an overrides file: `{"OLDTOKEN": {"new": "NEWTOKEN", "evidence": "why"}}`.

4. Rewrite the source. It applies `high` answers and your overrides, and stops without changing anything if a file uses a token that has neither.

   ```sh
   python3 python/apply_genshin_tokens.py out/token-map.tsv --overrides out/overrides.json $(grep -rlE '\b[A-Z]{11}\b' --include='*.cs' path/to/your/code)
   ```

5. Re-derive whatever the build hard-codes beyond names: code RVAs, field offsets and byte patterns. `out/token-map.methods.tsv` lists each method pair with both code RVAs. `genshin_layout.py` computes a class's field offsets from the metadata export. Check a computed offset against code or a runtime lookup before you write to it.

6. Compile against the new build's interop assemblies.

## License

MIT. See `LICENSE`.
