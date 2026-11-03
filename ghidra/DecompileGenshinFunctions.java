// Decompile the functions containing the RVAs passed as script arguments in the matched Genshin executable.
// @category Genshin

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileGenshinFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            for (String arg : getScriptArgs()) {
                Address address = currentProgram.getImageBase().add(Long.decode(arg));
                disassemble(address);
                Function function = getFunctionContaining(address);
                if (function == null)
                    function = createFunction(address, null);
                println("=== " + arg + " -> " + (function == null ? "none" : function.getEntryPoint()) + " ===");
                if (function == null)
                    continue;
                DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
                println(result.decompileCompleted() ? result.getDecompiledFunction().getC() : "FAILED " + result.getErrorMessage());
            }
        } finally {
            decompiler.dispose();
        }
    }
}
