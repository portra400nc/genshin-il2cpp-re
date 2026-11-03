// Inspect field access and GC-handle API candidates in the matched executable.
// @category Genshin

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class InspectGenshinHandles extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] addresses = {
            0x1404B1810L, 0x1404B1850L, 0x1404B1890L,
            0x1404B1950L, 0x1404B1980L, 0x1404B19A0L, 0x14051C390L,
            0x14051C4A0L,
            0x1404B19B0L, 0x14051B980L, 0x140525C70L,
            0x1404B1AE0L, 0x1404B1B40L, 0x1404B1BA0L, 0x1404B1BD0L,
            0x140557720L
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
