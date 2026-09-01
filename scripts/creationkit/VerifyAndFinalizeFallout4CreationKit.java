// Verify the recovered Fallout 4 Creation Kit and restore analysis policy.
// @category Bethesda.CreationKit

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.util.Iterator;

public class VerifyAndFinalizeFallout4CreationKit extends GhidraScript {

	private static final String EXPECTED_SHA256 =
		"222FD0AAD949E76721D85C922AE508ADA6816BA2F3E1FC11647C7239C24C2E13";
	private static final String EXPECTED_PATH =
		"/Creation Kit/CreationKit Fallout 4 1.11.137.0.exe";
	private static final long EXPECTED_IMAGE_BASE = 0x140000000L;
	private static final String PARAMETER_ID = "Decompiler Parameter ID";
	private static final String AGGRESSIVE = "Aggressive Instruction Finder";
	private static final String CKPE_CATEGORY = "BGS CKPE FO4 1.11.137.0";
	private static final String EXPECTED_SOURCE_PINS =
		"{\"/Fallout4/Fallout4_1_11_221.exe\": " +
		"\"488015e2010308bfa164d3720cb618deea7e1c098b1d61af530d258a6f17d27b\", " +
		"\"/Fallout4/Fallout4_OG_1_10_163.exe\": " +
		"\"5b2a58004f1856e51235132ab304b20c1434017067703e4282e8b0d5bc539623\"}";
	private static final long[] ANCHOR_RVAS = {
		0x1000L, 0xFC62A5L, 0x1F8B54AL, 0x2F51000L,
		0x2F55B50L, 0x2F5A6A0L, 0x336CF50L, 0x3779EA0L
	};
	private static final String[] ANCHOR_HEX = {
		"cccccccccce966809202e9815d7602e9",
		"4c8d0564191302bae7000000488d0d58",
		"8b56380f1f004863ca8d420141894638",
		"488bc444894018555356574154415541",
		"0000498b52204885d20f84d300000048",
		"0a4c8bc949c1e1044d03cbc1eb0881e3",
		"00000000000000001900000000000801",
		"c544c700609e770300000000010a0400"
	};

	private byte[] decodeHex(String text) {
		byte[] value = new byte[text.length() / 2];
		for (int i = 0; i < value.length; i++) {
			value[i] = (byte) Integer.parseInt(
				text.substring(i * 2, i * 2 + 2), 16);
		}
		return value;
	}

	private boolean isSha256(String text) {
		return text != null && text.matches("(?i)[0-9a-f]{64}");
	}

	private void verifyLiveAnchors() throws Exception {
		for (int i = 0; i < ANCHOR_RVAS.length; i++) {
			Address address = currentProgram.getImageBase().add(ANCHOR_RVAS[i]);
			byte[] expected = decodeHex(ANCHOR_HEX[i]);
			byte[] actual = new byte[expected.length];
			int read = currentProgram.getMemory().getBytes(address, actual);
			if (read != expected.length) {
				throw new IllegalStateException(
					"Unreadable identity anchor at " + address);
			}
			for (int index = 0; index < expected.length; index++) {
				if (actual[index] != expected[index]) {
					throw new IllegalStateException(
						"Live identity anchor mismatch at " + address);
				}
			}
		}
	}

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			throw new IllegalStateException("No current Fallout 4 Creation Kit Program");
		}

		Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
		String sha256 = info.getString("Executable SHA256", "");
		String domainPath = currentProgram.getDomainFile().getPathname();
		if (!EXPECTED_SHA256.equalsIgnoreCase(sha256)) {
			throw new IllegalStateException(
				"Fallout 4 Creation Kit SHA-256 mismatch: " + sha256);
		}
		if (!EXPECTED_PATH.equals(domainPath)) {
			throw new IllegalStateException(
				"Fallout 4 Creation Kit domain path mismatch: " + domainPath);
		}
		if (currentProgram.getDefaultPointerSize() != 8 ||
			currentProgram.getImageBase().getOffset() != EXPECTED_IMAGE_BASE) {
			throw new IllegalStateException(
				"Fallout 4 Creation Kit architecture/layout mismatch");
		}
		String manifest = info.getString("BGS Target Manifest", "");
		if (!manifest.toLowerCase().contains(EXPECTED_SHA256.toLowerCase())) {
			throw new IllegalStateException(
				"Missing or mismatched BGS target manifest");
		}
		verifyLiveAnchors();
		String stageBefore = info.getString("BGS Creation Kit Stage", "");
		if (!("policy-restored".equals(stageBefore) ||
			"verified-final".equals(stageBefore))) {
			throw new IllegalStateException(
				"Final policy checkpoint is missing: stage=" + stageBefore);
		}

		setAnalysisOption(currentProgram, PARAMETER_ID, "false");
		setAnalysisOption(currentProgram, AGGRESSIVE, "false");
		Options analysis = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
		boolean parameterId = analysis.getBoolean(PARAMETER_ID, true);
		boolean aggressive = analysis.getBoolean(AGGRESSIVE, true);
		if (parameterId || aggressive) {
			throw new IllegalStateException(
				"Failed to restore required analysis policy");
		}

		long namedFunctions = 0;
		FunctionIterator functions =
			currentProgram.getFunctionManager().getFunctions(true);
		while (functions.hasNext()) {
			Function function = functions.next();
			String name = function.getName();
			if (!(name.startsWith("FUN_") || name.startsWith("sub_") ||
				name.startsWith("thunk_FUN_") || name.startsWith("thunk_sub_"))) {
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

		long vtableSymbols = 0;
		SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
		while (symbols.hasNext()) {
			Symbol symbol = symbols.next();
			String name = symbol.getName();
			if (name.equals("vftable") || name.startsWith("vftable_") ||
				name.startsWith("VTABLE_")) {
				vtableSymbols++;
			}
		}

		long ckpeBookmarks = 0;
		Iterator<Bookmark> bookmarkIterator =
			currentProgram.getBookmarkManager().getBookmarksIterator("Analysis");
		while (bookmarkIterator.hasNext()) {
			Bookmark bookmark = bookmarkIterator.next();
			if (CKPE_CATEGORY.equals(bookmark.getCategory())) {
				ckpeBookmarks++;
			}
		}

		String bytesigTarget = info.getString(
			"BGS Reciprocal Bytesig Target SHA256", "");
		long bytesigAccepted = info.getLong(
			"BGS Reciprocal Bytesig Accepted Count", -1);
		long bytesigSatisfied = info.getLong(
			"BGS Reciprocal Bytesig Satisfied Count", -1);
		String bytesigEvidence = info.getString(
			"BGS Reciprocal Bytesig Evidence SHA256", "");
		String bytesigSourcePins = info.getString(
			"BGS Reciprocal Bytesig Source Pins", "");
		if (!EXPECTED_SHA256.equalsIgnoreCase(bytesigTarget) ||
			bytesigAccepted < 1 || bytesigSatisfied < 1 ||
			!isSha256(bytesigEvidence) ||
			!EXPECTED_SOURCE_PINS.equals(bytesigSourcePins)) {
			throw new IllegalStateException(
				"Reciprocal byte-signature pass is missing or unbound");
		}

		long functionCount =
			currentProgram.getFunctionManager().getFunctionCount();
		if (functionCount < 180000) {
			throw new IllegalStateException(
				"PE unwind/function analysis is incomplete: " + functionCount);
		}
		if (classStructures < 1000 || vtableSymbols < 1000) {
			throw new IllegalStateException(
				"MSVC class recovery is incomplete: structures=" +
				classStructures + ", vtables=" + vtableSymbols);
		}
		if (ckpeBookmarks < 392) {
			throw new IllegalStateException(
				"Exact CKPE evidence is incomplete: bookmarks=" + ckpeBookmarks);
		}

		info.setString("BGS Creation Kit Stage", "verified-final");

		println("Fallout 4 Creation Kit verification:");
		println("  project path: " + domainPath);
		println("  SHA-256: " + sha256.toUpperCase());
		println("  functions: " + functionCount);
		println("  named functions: " + namedFunctions);
		println("  symbols: " +
			currentProgram.getSymbolTable().getNumSymbols());
		println("  /ClassDataTypes entries: " + classDataTypes);
		println("  /ClassDataTypes structures: " + classStructures);
		println("  vtable symbols: " + vtableSymbols);
		println("  CKPE bookmarks: " + ckpeBookmarks);
		println("  reciprocal bytesig accepted: " + bytesigAccepted);
		println("  reciprocal bytesig satisfied: " + bytesigSatisfied);
		println("  prior stage: " + stageBefore);
		println("  final stage: verified-final");
		println("  Decompiler Parameter ID: " + parameterId);
		println("  Aggressive Instruction Finder: " + aggressive);
	}
}
