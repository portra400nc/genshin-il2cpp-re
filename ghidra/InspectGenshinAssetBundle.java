// Inspect the AssetBundle and builtin-resource entry points in the matched EXE.
// @category Genshin

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class InspectGenshinAssetBundle extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] addresses = {
            0x15a26c500L, // AssetBundle.LoadFromMemoryAsync(binary, crc, format)
            0x15a26c510L, // AssetBundle.LoadFromMemoryAsync(binary)
            0x15a26c740L, // AssetBundle.LoadFromMemoryMHY
            0x15a270c00L  // Resources.GetBuiltinResource(type, path)
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            for (long offset : addresses) {
                Address address = toAddr(offset);
                disassemble(address);
                Function function = getFunctionAt(address);
                if (function == null)
                    function = createFunction(address, null);
                println("=== " + address + " ===");
                if (function == null) {
                    println("No function at address");
                    continue;
                }
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                println(result.decompileCompleted()
                    ? result.getDecompiledFunction().getC()
                    : "Decompilation failed: " + result.getErrorMessage());
            }
        } finally {
            decompiler.dispose();
        }
    }
}
