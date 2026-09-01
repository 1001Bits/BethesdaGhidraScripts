import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class CkOptHeadlessProbe extends GhidraScript {
    private static final String[] TARGETS = {
        "-OptimizeMasterFile",
        "-OptimizeDLC",
        "-TagifyMasterfile",
        "-DelocalizeMasterfile",
        "Attempting to Delocalize the live ESM, aborting...",
        "Attempting to Tagify the live ESM, aborting...",
        "Optimize Operation failed for unknown reason."
    };

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("[ERROR] currentProgram is null");
            return;
        }

        println("[CK_AUDIT] program=" + currentProgram.getName());
        println("[CK_AUDIT] path=" + currentProgram.getExecutablePath());
        println("[CK_AUDIT] entry=" + currentProgram.getMinAddress());

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        Map<String, LinkedHashSet<AddressHolder>> hits = new LinkedHashMap<>();
        for (String t : TARGETS) {
            hits.put(t, new LinkedHashSet<>());
        }

        DataIterator dataIt = listing.getDefinedData(true);
        while (dataIt.hasNext()) {
            Data d = dataIt.next();
            String val = null;
            try {
                Object obj = d.getValue();
                if (obj instanceof String) {
                    val = (String) obj;
                }
            } catch (Exception ignored) {
            }
            if (val == null) {
                continue;
            }
            for (String t : TARGETS) {
                if (val.equals(t)) {
                    hits.get(t).add(new AddressHolder(d.getMinAddress()));
                    println("[STRING_MATCH] " + t + " @ " + d.getMinAddress());
                }
            }
        }

        for (String t : TARGETS) {
            LinkedHashSet<AddressHolder> set = hits.get(t);
            if (set.isEmpty()) {
                continue;
            }
            for (AddressHolder h : set) {
                for (Reference ref : rm.getReferencesTo(h.addr)) {
                    Function f = fm.getFunctionContaining(ref.getFromAddress());
                    if (f != null) {
                        println("[XREF] " + t + " -> " + f.getName() + " " + f.getEntryPoint() + " via " + ref.getFromAddress());
                    }
                }
            }
        }

        // Candidate handler discovery by name.
        String[] namePatterns = {
            "Optimize",
            "Masterfile",
            "DLC",
            "Tagify",
            "Delocalize"
        };

        Set<Function> candidates = new LinkedHashSet<>();
        for (Function f : fm.getFunctions(true)) {
            String name = f.getName();
            for (String p : namePatterns) {
                if (name.contains(p)) {
                    candidates.add(f);
                    break;
                }
            }
        }

        println("[CANDIDATES] count=" + candidates.size());
        for (Function f : candidates) {
            println("\n[FUNC] " + f.getName() + " @ " + f.getEntryPoint());
            println("[SIG] " + f.getSignature().getPrototypeString());

            // Print direct call targets, one hop.
            InstructionIterator it = listing.getInstructions(f.getBody(), true);
            int callCount = 0;
            while (it.hasNext()) {
                Instruction ins = it.next();
                if (!ins.getFlowType().isCall()) {
                    continue;
                }
                for (Reference ref : ins.getReferencesFrom()) {
                    if (!ref.getReferenceType().isCall()) {
                        continue;
                    }
                    String calleeName = "<indirect>";
                    Function callee = fm.getFunctionAt(ref.getToAddress());
                    if (callee != null) {
                        calleeName = callee.getName();
                    }
                    println("[CALL] " + ins.getAddress() + " -> " + calleeName + " " + ref.getToAddress());
                    if (++callCount > 80) {
                        break;
                    }
                }
                if (callCount > 80) {
                    break;
                }
            }

            DecompInterface dec = new DecompInterface();
            dec.openProgram(currentProgram);
            dec.setOptions(new DecompileOptions());
            DecompileResults dr = dec.decompileFunction(f, 120, monitor);
            if (!dr.decompileCompleted()) {
                println("[DECOMP_FAIL] " + dr.getErrorMessage());
                continue;
            }

            String c = dr.getDecompiledFunction().getC();
            String[] lines = c.split("\\r?\\n");
            int lim = Math.min(lines.length, 180);
            for (int i = 0; i < lim; i++) {
                println("[C] " + lines[i]);
            }
            if (lines.length > lim) {
                println("... truncated " + (lines.length - lim) + " lines");
            }
            dec.dispose();
        }
    }

    private static class AddressHolder {
        private final ghidra.program.model.address.Address addr;
        AddressHolder(ghidra.program.model.address.Address a) { this.addr = a; }
    }
}
