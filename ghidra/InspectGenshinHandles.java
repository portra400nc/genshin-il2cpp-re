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
            0x1404BC4C0L, 0x1404BC4F0L, 0x1404BC530L,
            0x1404BC5F0L, 0x1404BC620L, 0x1404BC640L, 0x140526E20L,
            0x140526F40L,
            0x1404BC650L, 0x140526430L, 0x1405307A0L,
            0x1404BC780L, 0x1404BC7E0L, 0x1404BC840L, 0x1404BC870L,
            0x140562230L
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
