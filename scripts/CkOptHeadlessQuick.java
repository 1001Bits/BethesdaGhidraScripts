import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class CkOptHeadlessQuick extends GhidraScript {
    private static final String[] TARGETS = {
        "-OptimizeMasterFile",
        "-OptimizeDLC",
        "-TagifyMasterfile",
        "-DelocalizeMasterfile"
    };

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("[ERROR] currentProgram null");
            return;
        }

        println("[CK_AUDIT] program=" + currentProgram.getName());
        println("[CK_AUDIT] path=" + currentProgram.getExecutablePath());

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        for (String t : TARGETS) {
            int count = 0;
            DataIterator di = listing.getDefinedData(true);
            while (di.hasNext()) {
                Data d = di.next();
                String v = null;
                try {
                    Object o = d.getValue();
                    if (o instanceof String) {
                        v = (String)o;
                    }
                } catch (Exception ignore) {}
                if (v == null || !v.equals(t)) {
                    continue;
                }
                count++;
                println("[STRING] " + t + " @ " + d.getMinAddress());
                Reference[] refs = rm.getReferencesTo(d.getMinAddress());
                for (Reference r : refs) {
                    if (r == null || r.isExternal()) continue;
                    Function f = fm.getFunctionContaining(r.getFromAddress());
                    if (f == null) continue;
                    println("  xref-to: " + f.getName() + "@" + f.getEntryPoint() + " via " + r.getFromAddress());
                }
            }
            if (count == 0) {
                println("[STRING] " + t + " no match");
            }
        }

        // Emit functions with optimization-related names.
        FunctionIterator fi = fm.getFunctions(true);
        while (fi.hasNext()) {
            Function f = fi.next();
            String n = f.getName();
            if (n.contains("Optimize") || n.contains("Masterfile") || n.contains("Tagify") || n.contains("Delocalize") || n.contains("DLC")) {
                println("[FUNC] " + n + "@" + f.getEntryPoint() + " args=" + f.getSignature().getPrototypeString());
            }
        }
    }
}
