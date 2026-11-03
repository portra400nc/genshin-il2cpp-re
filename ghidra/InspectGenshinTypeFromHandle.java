// Inspect the two unnamed System.Type methods accepting a handle.
// @category Genshin

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class InspectGenshinTypeFromHandle extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] addresses = {0x1595471A0L, 0x159566F70L};
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
