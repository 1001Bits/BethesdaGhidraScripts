# Fallout 4 IDA-name archive

`ida-import-fallout4.zip` is an external, user-provided set of generated
IDA-Python name maps. Its author, origin, and redistribution license are not
known. The raw ZIP, extracted scripts, and generated symbol evidence therefore
remain local inputs and must not be copied into a release.

The repository stores only a reviewable metadata lock at
`refs/ida_import_fallout4.lock.json`. It pins the archive and every member by
SHA-256, records the expected grammar/counts, and lists target executable
hashes that were independently established elsewhere in the repository. A
map with no approved target hash can be audited but cannot be normalized.

Use `ida_name_archive.py`; never run the input scripts:

```powershell
python scripts/commonlibf4/ida_name_archive.py audit C:\path\ida-import-fallout4.zip

python scripts/commonlibf4/ida_name_archive.py normalize `
  C:\path\ida-import-fallout4.zip `
  --version 1.11.221.0 `
  --target C:\path\Fallout4.exe `
  --output extras\normalized\f4_ida_names_1.11.221.0.<full-target-sha256>.json
```

Normalization does all of the following before a record becomes consumable:

- verifies the exact archive/member hashes and an allowlisted Python AST;
- verifies the target PE SHA-256, version, architecture, image layout, and
  approved-target list;
- converts full VAs and suffix-consistent bare RVAs into one RVA coordinate;
- preserves non-executable names as data labels;
- requires executable names to match validated AMD64 `.pdata` starts; and
- quarantines aliases, repeated cleaned names, invalid coordinates, unmapped
  addresses, and non-boundary code labels.

The JSON output receives a standard `.identity.json` content/PE binding.
`parse_commonlib_types.py` and `run_bytesig_port.py` validate both files before
use. If a normalized file exists but is stale or invalid, consumers fail
closed; they do not fall back to the supplied raw archive. Merge priority is
CommonLib/exact PDB, then exact-version normalized IDA evidence, then
cross-version ports. Conflicting lower-priority names never overwrite an
existing claim.

Use a full target-SHA-qualified filename for new output. Consumers select that
path first from the exact loaded PE hash, allowing packed and Steamless images
to coexist. The older unqualified filename remains readable only when its
identity sidecar matches the requested target; it is never borrowed for the
packed/unpacked sibling.
