# Genshin offline interop batch

This tool converts the verified MHY metadata subset into Cpp2IL-style dummy
assemblies, then runs the pinned Il2CppInterop generator on them. It does not
modify the game or need a Deck launch.

From the repository root, produce the input JSON from the copied, matched
game files:

```sh
python3 python/export_genshin_metadata.py \
  game/GenshinImpact.exe game/global-metadata.dat \
  game/startup-metadata.dat out/GenshinUnityAPI.json \
  --system-libraries --unity-engine
```

Build the batch tool with the .NET 9 SDK,
then run it with `--generate`:

```sh
dotnet build dotnet/GenshinInteropBatch/GenshinInteropBatch.csproj -c Release
dotnet dotnet/GenshinInteropBatch/bin/Release/net9.0/GenshinInteropBatch.dll \
  out/GenshinUnityAPI.json out/GenshinInteropBatch --generate
```

The output directory contains `dummy/`, `interop/`, and `report.json`. The
generator checks the output assembly count, verifies three known Genshin
method RVAs against generated method tokens in `MethodAddressToToken.db`, and
checks the generic signatures used by UnityExplorer. It rewrites three
CoreModule component helpers to call class-handle overloads because Genshin
lacks the reflection API used by the generated generic methods. It also
replaces 11 named `Color` getters with literal values after the first
UnityExplorer run raised a native exception in `Color.white`. Cecil changes
method tokens when it writes CoreModule, so the tool remaps its 5,143 method
addresses in `MethodAddressToToken.db` and verifies known entries afterward.

The batch tool reconstructs property metadata from exported `get_` and `set_`
methods. The generated wrappers preserve these properties; four representative
CoreModule and UI properties are checked after generation. The dummy assemblies
are still incomplete. The batch tool infers method-generic
parameter positions from the indices referenced by each signature; it does
not yet decode generic containers or unused generic parameters. The exporter
resolves 13 generic instantiations from the matched Deck type-name logs and
leaves all other instances undecoded. The MHY subset also lacks exact nested
ownership, field offsets, custom attributes, and some images. The batch tool omits
signatures it cannot represent and records counts in `report.json`. It also
reports duplicate type names and delegates whose `Invoke` signature cannot
be represented. Every literal field gets the constant the exporter decoded from
the game's field default-value table (`default_value` in the JSON), and
`report.json` counts them as `constants`. The batch tool stops if a literal
field has no value, because Roslyn fails module emission with `CS7038` on
named enum members without one. A match by type name, method name, and parameter count does
not establish binary or runtime compatibility.
