# Model Provenance

## Evidence Collected

- Source type and local path or Hugging Face repository.
- Requested and resolved immutable revision.
- File names, sizes, and available content digests.
- Weight serialization formats.
- Base-model and adapter lineage claims from JSON metadata.
- Presence of repository code, native libraries, scripts, or pickle weights.

## Interpretation

`safetensors` and GGUF avoid Python pickle execution but may still contain a
behavioral backdoor. A reputable publisher and immutable revision improve
traceability but do not prove model intent. Findings are therefore reported by
severity without a synthetic "safe" score.

## Local Lockfiles

`model lock` hashes every regular file beneath the selected directory with
SHA-256. Verification fails when a file changes, disappears, or is added. The
lockfile should be stored outside the model directory or excluded from the
directory before locking.

## Hugging Face Inspection

Remote inspection uses the public model API and resolves the supplied revision.
It does not download weight data. LFS object IDs are reported when available.
Use a full 40-character commit SHA for reproducible deployment.
