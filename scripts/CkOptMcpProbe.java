import ghidra.app.script.GhidraScript;

public class CkOptMcpProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("NO_PROGRAM");
            return;
        }
        println("PROGRAM=" + currentProgram.getName());
    }
}
