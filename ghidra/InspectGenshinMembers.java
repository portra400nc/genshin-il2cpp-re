// Inspect only the member API candidates in the matched Genshin executable.
// @category Genshin

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.app.script.GhidraScript;

public class InspectGenshinMembers extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] addresses = {
            0x1404B1360L, // nearby class-member API
            0x140512510L,
            0x1404B1370L,
            0x140511980L,
            0x1404B1380L,
            0x1405158B0L,
            0x1404B1390L,
            0x1405105E0L,
            0x1404B13A0L, // nested-type iterator, previously mistaken for methods
            0x140511290L,
            0x1404B1420L, // class_get_methods; class +0x20 method array, +0xC2 count
            0x140510BE0L,
            0x1404B1430L,
            0x140514A70L,
            0x1404B1440L,
            0x140510D90L,
            0x1404B1410L, // candidate class_get_field_from_name
            0x1405106D0L, // field-name lookup body
            0x1404B1850L  // candidate field_static_get_value
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
