"use strict";
//============================================================================
// ttd_dump_calls.js -- dump indirect / virtual call edges from a TTD trace.
//
// Time Travel Debugging records every executed instruction, so it knows the
// REAL target each indirect (vtable) call took -- exactly what static analysis
// in Ghidra cannot resolve.  This script enumerates the trace's call index and
// emits `caller_rva,target_rva,count` edges, which scripts/core/apply_vcall_xrefs.py
// then places as Ghidra COMPUTED_CALL references.
//
//----------------------------------------------------------------------------
// WORKFLOW
//
// 1. Record a trace (standalone TTD recorder -- ships with WinDbg, run elevated):
//      TTD.exe -accepteula -out C:\traces\sf.run -launch "Starfield.exe"
//    Play through the code paths you want edges for, then quit.  Coverage =
//    what you executed, so exercise broadly (and you can merge several traces).
//
// 2. (RECOMMENDED) Give WinDbg symbols for your Ghidra names so TTD can
//    enumerate calls to them -- this is the FakePDB loop:
//      python scripts/core/symbol_export.py <proj> <name> "<program>" out/ --fakepdb-json
//      fakepdb pdb_generate <Starfield.exe> out/Starfield.fakepdb.json Starfield.pdb
//      copy Starfield.pdb onto your _NT_SYMBOL_PATH
//    Without symbols, TTD.Calls("module!*") finds nothing -- the PDB is how the
//    debugger knows the function set whose calls to enumerate.
//
// 3. Replay headless and capture the edges:
//      cdb.exe -z C:\traces\sf.run -c ".scriptload <dir>\ttd_dump_calls.js; dx @$scriptContents.dumpVCalls(\"Starfield\"); q" > edges_raw.txt
//    (in interactive WinDbg: .scriptload ttd_dump_calls.js
//                            dx @$scriptContents.dumpVCalls("Starfield"))
//    Keep the `caller_rva,target_rva,count` lines -> edges.csv.
//
// 4. Apply into Ghidra:
//      python scripts/core/apply_vcall_xrefs.py <proj> <name> "<program>" edges.csv --apply
//
//----------------------------------------------------------------------------
// NOTES
// - Direct calls are emitted too; the apply driver skips them as duplicates
//   (they already have refs), so only the indirect/vtable edges add new xrefs.
// - `caller_rva` is the RETURN address (instruction after the call); the apply
//   driver resolves it back to the call instruction via the disassembly.
// - Polymorphic sites legitimately produce several (caller,target) pairs.
//
// STATUS: prototype -- authored against the WinDbg/TTD data-model API; validate
// against a real trace before production use.
//============================================================================

function initializeScript() {
    return [new host.apiVersionSupport(1, 7)];
}

function __findModule(modName) {
    var want = modName.toLowerCase().replace(/\.exe$/, "");
    for (var m of host.currentProcess.Modules) {
        var n = ("" + m.Name).toLowerCase();
        // match "...\starfield.exe" or any module whose base name matches
        if (n.indexOf("\\" + want + ".") >= 0 || n.indexOf("\\" + want + "\\") >= 0
            || n.endsWith("\\" + want) || n.indexOf(want) >= 0) {
            return m;
        }
    }
    throw new Error("module not found in trace: " + modName);
}

function dumpVCalls(modName) {
    if (!modName) {
        throw new Error("usage: dx @$scriptContents.dumpVCalls(\"<modulename>\")");
    }
    var session = host.currentSession;
    if (session.TTD === undefined) {
        throw new Error("not a TTD session -- open a .run trace (cdb -z trace.run)");
    }

    var mod = __findModule(modName);
    var base = mod.BaseAddress;
    var size = mod.Size;                // bound RVAs to this module's image
    var pattern = modName.replace(/\.exe$/i, "") + "!*";
    var calls = session.TTD.Calls(pattern);

    var seen = {};                      // "rRva,tRva" -> observed count
    var total = 0, kept = 0;
    for (var c of calls) {
        total++;
        var ret = c.ReturnAddress;
        var tgt = c.FunctionAddress;
        if (ret === undefined || tgt === undefined) { continue; }
        var rRva = ret.subtract(base);
        var tRva = tgt.subtract(base);
        // keep ONLY intra-module edges: both the call site and the target must
        // lie inside this module's image.  A caller in another DLL (ret outside
        // [base, base+size)) is not a useful xref for a single-binary analysis.
        if (rRva.compareTo(0) < 0 || rRva.compareTo(size) >= 0 ||
            tRva.compareTo(0) < 0 || tRva.compareTo(size) >= 0) { continue; }
        var key = rRva.toString(16) + "," + tRva.toString(16);
        seen[key] = (seen[key] || 0) + 1;
        kept++;
    }

    host.diagnostics.debugLog("# ttd_dump_calls " + modName +
        " base=0x" + base.toString(16) + " size=0x" + size.toString(16) +
        " calls=" + total + " intra-module=" + kept +
        " unique-edges=" + Object.keys(seen).length + "\n");
    host.diagnostics.debugLog("caller_rva,target_rva,count\n");
    for (var k in seen) {
        host.diagnostics.debugLog(k + "," + seen[k] + "\n");
    }
    return "ttd_dump_calls: " + Object.keys(seen).length + " unique edges";
}
