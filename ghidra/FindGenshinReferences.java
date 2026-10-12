// Print the instructions that reference each VA passed as a script argument through a RIP-relative operand, with their containing functions.
// @category Genshin

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;

public class FindGenshinReferences extends GhidraScript {
    @Override
    public void run() throws Exception {
        MemoryBlock text = currentProgram.getMemory().getBlock(".text");
        byte[] bytes = new byte[(int) text.getSize()];
        text.getBytes(text.getStart(), bytes);
        long base = text.getStart().getOffset();
        for (String arg : getScriptArgs()) {
            long target = Long.decode(arg);
            println("=== references to " + arg + " ===");
            for (int pos = 0; pos + 4 <= bytes.length; pos++) {
                int disp = (bytes[pos] & 0xff) | (bytes[pos + 1] & 0xff) << 8 | (bytes[pos + 2] & 0xff) << 16 | (bytes[pos + 3] & 0xff) << 24;
                for (int tail = 0; tail <= 4; tail++) {
                    if (base + pos + 4 + tail + disp != target)
                        continue;
                    for (int back = 2; back <= 7; back++) {
                        Address start = text.getStart().add(pos - back);
                        Instruction instruction = getInstructionAt(start);
                        if (instruction == null) {
                            disassemble(start);
                            instruction = getInstructionAt(start);
                        }
                        if (instruction == null || instruction.getLength() != back + 4 + tail)
                            continue;
                        boolean refers = false;
                        for (int operand = 0; operand < instruction.getNumOperands(); operand++)
                            for (Object object : instruction.getOpObjects(operand))
                                if (object instanceof Address && ((Address) object).getOffset() == target)
                                    refers = true;
                        if (!refers && instruction.toString().contains(Long.toHexString(target)))
                            refers = true;
                        if (!refers)
                            continue;
                        Function function = getFunctionContaining(start);
                        println(start + " " + instruction + " in " + (function == null ? "?" : function.getEntryPoint()));
                    }
                }
            }
        }
    }
}
