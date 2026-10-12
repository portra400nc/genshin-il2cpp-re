// Inspect method metadata accessors in the matched Genshin executable.
// @category Genshin

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class InspectGenshinMethodMetadata extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] addresses = {
            0x1404B1D40L, // return type
            0x1404B1D60L, // name
            0x1404B1DC0L, // parameter type
            0x1404B1ED0L, // parameter name
            0x1405281A0L, // metadata fallback for name
            0x1405282B0L, // metadata fallback for return type
            0x140528560L  // metadata fallback for parameter array
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
