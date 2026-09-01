# Latest runtime assets

The supported runtime matrix remains unchanged except for the explicit latest
targets Fallout 4 `1.11.240.0` and Skyrim AE `1.7.104.0`.

Fallout `1.11.240` uses three independently bound inputs:

- The exact PE and official address library listed in
  `scripts/core/latest_target_assets.json`.
- An exact GUID/age/section/machine-matched community public-symbol PDB,
  normalized into `refs/f4_240_pdb_publics.txt` with its identity sidecar.
- Existing CommonLib, exact IDA, address-ID, and byte-signature evidence, in
  that priority order after direct PDB names.

The larger IDA-derived `version-1-11-240-0.bin` found beside the diff output is
not an official replacement. It conflicts with 81 official IDs and is retained
only as quarantined provenance in the latest-target manifest.

Skyrim `1.7.104` already has an exact PE, an embedded-version address library,
and an identity-bound generated importer path. Its address library uses meh321
V5, so the Skyrim loader accepts V1/V2 for existing targets and the bounded,
flat-indexed V5 layout for `1.7.104`. No intermediate Skyrim versions are added
by this integration.

The local release source archive omitted CommonLibF4's declared
`lib/commonlib-shared` submodule. The generator dependency and downloaded
archive identity are recorded in `scripts/core/latest_target_assets.json`.
