# Complete Genshin metadata export

The matched `GenshinImpact.exe`, `global-metadata.dat`, and
`startup-metadata.dat` contain 75 IL2CPP image ranges. Export every range
offline with:

```sh
python3 python/export_genshin_metadata.py \
  game/GenshinImpact.exe game/global-metadata.dat \
  game/startup-metadata.dat out/GenshinAllMetadata.json \
  --all-images
```

The current export contains 88,902 named types, 733,442 methods, 440,172
fields, and 711,021 non-null native method addresses. Two slots in the
88,904-entry type-definition table are outside the 75 image ranges. The
output is about 181 MiB and stays in ignored `out/` rather than Git.

This is a complete image metadata map for the matched build. It identifies
method names and native addresses. It does not reconstruct C# method bodies
from native code. `ghidra/` has small scripts for decompiling
specific native functions when a bridge or wrapper needs one. A full Ghidra
decompilation of all 711,021 addressed methods would create a much larger
artifact without verifying that UnityExplorer's calls work at runtime.
