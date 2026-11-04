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
            0x1404BC000L, // nearby class-member API
            0x14051CFB0L,
            0x1404BC010L,
            0x14051C500L,
            0x1404BC020L,
            0x1405203C0L,
            0x1404BC030L,
            0x14051B110L,
            0x1404BC040L, // nested-type iterator, previously mistaken for methods
            0x14051BE10L,
            0x1404BC0C0L, // class_get_methods; jumps into .upx0. In 7.1 it read class +0x20 method array, +0xC2 count
            0x14051B710L,
            0x1404BC0D0L,
            0x14051F580L,
            0x1404BC0E0L,
            0x14051B8E0L,
            0x1404BC0B0L, // candidate class_get_field_from_name
            0x14051B200L, // field-name lookup body
            0x1404BC4F0L  // candidate field_static_get_value
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
