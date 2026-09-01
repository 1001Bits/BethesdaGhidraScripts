// Verify the recovered Skyrim Creation Kit program and restore analysis policy.
// @category Bethesda.CreationKit

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import java.util.Iterator;

public class VerifyAndFinalizeCreationKit extends GhidraScript {

	private static final String PARAMETER_ID = "Decompiler Parameter ID";
	private static final String EXPECTED_SHA256 =
		"3E8F7215303A82D8991F87FBC42EB84EF2672D5D8AB038212447FAECFDF37B23";

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			throw new IllegalStateException("No current Creation Kit program");
		}

		Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
		String sha256 = info.getString("Executable SHA256", "");
		if (!EXPECTED_SHA256.equalsIgnoreCase(sha256)) {
			throw new IllegalStateException(
				"Creation Kit SHA-256 mismatch: expected " + EXPECTED_SHA256 +
				", got " + sha256);
		}

		Options analysis = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
		boolean parameterIdBefore = analysis.getBoolean(PARAMETER_ID, false);
		setAnalysisOption(currentProgram, PARAMETER_ID, "false");
		boolean parameterIdAfter = analysis.getBoolean(PARAMETER_ID, true);
		if (parameterIdAfter) {
			throw new IllegalStateException(
				"Failed to disable " + PARAMETER_ID);
		}

		long namedFunctions = 0;
		FunctionIterator functions =
			currentProgram.getFunctionManager().getFunctions(true);
		while (functions.hasNext()) {
			Function function = functions.next();
			String name = function.getName();
			if (!(name.startsWith("FUN_") || name.startsWith("sub_") ||
				name.startsWith("thunk_FUN_"))) {
				namedFunctions++;
			}
		}

		long classDataTypes = 0;
		long classStructures = 0;
		Iterator<DataType> dataTypes =
			currentProgram.getDataTypeManager().getAllDataTypes();
		while (dataTypes.hasNext()) {
			DataType dataType = dataTypes.next();
			String category = dataType.getCategoryPath().getPath();
			if (category.equals("/ClassDataTypes") ||
				category.startsWith("/ClassDataTypes/")) {
				classDataTypes++;
				if (dataType instanceof Structure) {
					classStructures++;
				}
			}
		}

		println("Creation Kit verification:");
		println("  SHA-256: " + sha256.toUpperCase());
		println("  functions: " +
			currentProgram.getFunctionManager().getFunctionCount());
		println("  named functions: " + namedFunctions);
		println("  symbols: " + currentProgram.getSymbolTable().getNumSymbols());
		println("  /ClassDataTypes entries: " + classDataTypes);
		println("  /ClassDataTypes structures: " + classStructures);
		println("  Decompiler Parameter ID before: " + parameterIdBefore);
		println("  Decompiler Parameter ID after: " + parameterIdAfter);
	}
}
