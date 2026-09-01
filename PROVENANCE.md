# BGS provenance and canaries

Generated importers carry a transparent `BGS_PROVENANCE` manifest with the
release ID, generator SHA-256, toolchain-lock SHA-256, exact target SHA-256,
schema version, and a deterministic provenance ID. Applying an importer stores
the same canonical JSON in Ghidra Program Info under `BGS_PROVENANCE` and adds
its documented canary comment to three real named functions without changing
their names, addresses, signatures, or behavior.

Symbol JSON and bundle/PDB identity metadata retain the manifest. Synthetic
PDBs additionally carry a `__BGS_PROVENANCE_<id>` public alias at an existing
real symbol RVA. No fabricated address is introduced.

## Offline Ed25519 signing

Generate a key pair outside the repository:

```powershell
python scripts/core/provenance_sign.py keygen `
  --private D:\offline\release.bgs-ed25519-private.pem `
  --public provenance-v1-public.pem
```

Set `BGS_PROVENANCE_SIGNING_KEY` to the private-key path only in the offline
release environment before generating or stamping importers. Never commit the
private key. Verify artifacts against the separately distributed public key:

```powershell
python scripts/core/provenance_scan.py artifact.zip `
  --public-key provenance-v1-public.pem
```

An unsigned marker or copied canary is evidence of tool lineage, not proof of
authorship. A valid signature proves that the manifest was issued by the holder
of the trusted offline key; it still does not prove who wrote downstream code.
