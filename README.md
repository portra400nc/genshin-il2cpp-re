# genshin-il2cpp-re

Offline tools that decode Genshin Impact's IL2CPP metadata and turn it into files other tools can use. They read the game's files and memory dumps and do not depend on any mod loader. The outputs are metadata JSON, an Il2CppDumper-style `dump.cs`, Cpp2IL-style dummy assemblies, and Il2CppInterop wrappers for MelonLoader, BepInEx, or any other loader built on Il2CppInterop.

## Supported game build

The scripts check their inputs against the September 2026 build before reading them.

| File | SHA-256 |
|---|---|
| `GenshinImpact.exe` | `08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d` |
| `global-metadata.dat` | `05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0` |
| `startup-metadata.dat` | `66c684950af332966887cfd6f5263a05704230999ee290c27d5b3bdb8a713923` |

A new game build needs new constants in `python/decode_genshin_strings.py` and `python/inspect_genshin_images.py`, and the offsets they pin must be derived again.

## Layout

| Folder | Contents |
|---|---|
| `python/` | Metadata decoding and export, EXE and PE inspection, and memory-dump reading. `decode_genshin_strings.py` holds the build constants the other scripts import, so run the scripts from this folder or with it on `PYTHONPATH`. |
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

## License

MIT. See `LICENSE`.
