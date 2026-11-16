# Vera Anchor Verifier CLI

The `vera-anchor` executable is installed with `vera-anchor-verifier`.

After installing the package:

```sh
python -m pip install vera-anchor-verifier
```

run commands directly with:

```sh
vera-anchor
```

Contributors working from a source checkout may install the project in editable mode:

```sh
python -m pip install -e .
```

Dataset verification defaults to **offline**. Public verification is always explicit. Ingest and SAGE execution support both offline and public workflows, while independent SAGE HCS standards verification is a separate networked workflow.

Authenticated Dataset and Ingest verification is exposed through the library API, not the CLI. The CLI does not accept Vera Anchor private-evidence credentials.

## Commands

```text
vera-anchor verify dataset --bundle BUNDLE.json --sources SOURCES.json --source-root DIRECTORY --intent INTENT.json --policy POLICY.json [--receipt RECEIPT.json] [--mode offline] [--report-out REPORT.json]

vera-anchor verify dataset --mode public --explorer-url https://explorer.veraanchor.com --bundle BUNDLE.json --sources SOURCES.json --source-root DIRECTORY --intent INTENT.json --policy PUBLIC_POLICY.json [--receipt RECEIPT.json] [--mirror-url https://mainnet-public.mirrornode.hedera.com/api/v1] [--report-out REPORT.json]

vera-anchor verify ingest --bundle BUNDLE.json --material MATERIAL.json --intent INTENT.json --policy POLICY.json [--receipt RECEIPT.json] [--source-root DIRECTORY] [--mode offline] [--report-out REPORT.json]

vera-anchor verify ingest --mode public --explorer-url https://explorer.veraanchor.com --anchor-request-id CORE_ANCHOR_UUID --bundle BUNDLE.json --material MATERIAL.json --intent INTENT.json --policy PUBLIC_POLICY.json [--receipt RECEIPT.json] [--source-root DIRECTORY] [--mirror-url https://mainnet-public.mirrornode.hedera.com/api/v1] [--report-out REPORT.json]

vera-anchor verify execution --evidence EVIDENCE.json --intent INTENT.json --policy POLICY.json [--verification-material MATERIAL.json] [--mode offline] [--report-out REPORT.json]

vera-anchor verify execution --mode public --explorer-url https://explorer.veraanchor.com --evidence EVIDENCE.json --intent INTENT.json --policy PUBLIC_POLICY.json [--verification-material MATERIAL.json] [--mirror-url https://mainnet-public.mirrornode.hedera.com/api/v1] [--report-out REPORT.json]

vera-anchor verify standards --evidence SAGE_EVIDENCE.json --intent INTENT.json --policy STANDARDS_POLICY.json [--verification-material MATERIAL.json] [--mirror-url https://mainnet-public.mirrornode.hedera.com/api/v1] [--report-out REPORT.json]

vera-anchor report validate --report SAVED_REPORT.json

vera-anchor policy assess --report SAVED_REPORT.json --policy POLICY.json
```

## Verification intent and policy

`INTENT.json` contains caller-controlled verification intent.

Subject identifiers, Hedera network selection, expected commitments, and execution scope must come from the relying party's trusted context rather than being copied from the evidence being verified.

`POLICY.json` uses the `va.verification-policy.v1` contract.

Policy requirements determine which checks and assurance are required for an `allow`, `review`, or `deny` decision.

An untrusted receipt, bundle, execution record, publication record, or standards projection cannot define its own sufficient acceptance threshold.

## Portable reports

All four `verify` commands accept:

```text
--report-out REPORT.json
```

The output file contains only the native `va.portable-verification-report.v1` report.

The CLI still writes its normal result envelope to stdout and preserves the policy exit code.

Reports may therefore be saved when verification completes with `allow`, `review`, or `deny`, provided the produced report passes the verifier's structural validation.

The destination must be a new file in an existing writable directory.

Report export uses a temporary sibling file and exclusive final creation so an existing output is not silently overwritten.

A failed report export is an operational failure rather than a successful verification result.

Protect exported reports according to the sensitivity of their metadata.

`report validate` checks report structure and internal digests. It does **not** authenticate the report or recompute the original evidence.

`policy assess` treats a saved report as unauthenticated and therefore does not promote it into a fresh SDK-authorized `allow`.

When a relying party needs a decision over the underlying evidence, rerun the corresponding verification workflow with independently supplied intent and policy.

## Dataset verification

### Offline Dataset verification

Offline Dataset verification recomputes supported source, bundle, and receipt relationships without resolver network requests.

Example:

```sh
vera-anchor verify dataset \
  --bundle bundle.json \
  --sources sources.json \
  --source-root ./source-files \
  --intent intent.json \
  --policy policy.json
```

The Dataset source manifest supplied with `--sources` contains producer-relative paths:

```json
{
  "paths": [
    "data.csv",
    "metadata/schema.json"
  ]
}
```

Those paths must correspond to the paths committed by the Dataset bundle. They are not inferred from local filesystem names.

The CLI requires canonical relative paths and constrains source reads to the selected source root.

Absolute paths, parent traversal, non-canonical paths, duplicate paths, and symbolic-link traversal are rejected.

Example offline policy:

```json
{
  "schema_version": "va.verification-policy.v1",
  "subject": {
    "kind": "dataset",
    "id": "07be0cf7-4cab-40ca-aa70-87840df4d3e7.example.verification.demo.v1"
  },
  "report_kind": "verification",
  "required_checks": [
    "dataset.source_binding",
    "dataset.bundle_consistency"
  ],
  "on_unresolved": "review"
}
```

### Public Dataset verification

Public Dataset verification is explicit:

```sh
vera-anchor verify dataset \
  --mode public \
  --explorer-url https://explorer.veraanchor.com \
  --bundle bundle.json \
  --sources sources.json \
  --source-root ./source-files \
  --intent public-intent.json \
  --policy public-policy.json
```

Public Dataset verification requires an independently selected Hedera network in the verification intent and compatible policy.

The policy must use:

```json
"report_kind": "public_triangulation"
```

Example:

```json
{
  "schema_version": "va.verification-policy.v1",
  "subject": {
    "kind": "dataset",
    "id": "07be0cf7-4cab-40ca-aa70-87840df4d3e7.example.verification.demo.v1",
    "hedera_network": "mainnet"
  },
  "report_kind": "public_triangulation",
  "required_checks": [
    "dataset.source_binding",
    "dataset.bundle_consistency",
    "triangulation.public_record_hedera.message_sha3_512"
  ],
  "required_assurance": [
    "mirror_corroboration"
  ],
  "on_unresolved": "review"
}
```

The public workflow recomputes local evidence, resolves the selected Vera Anchor Explorer publication record, and independently queries Hedera Mirror for supported ledger observations.

A consistent digest does not establish independently authenticated decrypted plaintext, Hedera consensus signatures, publisher ownership, or factual truth.

## Ingest verification

`verify ingest` accepts one bounded `--material MATERIAL.json` descriptor.

The descriptor represents original material supplied for recomputation, not an authenticated claim about its fingerprint.

Supported forms include JSON:

```json
{
  "kind": "json",
  "value": {
    "measurement": 42
  }
}
```

Text:

```json
{
  "kind": "text",
  "text": "sample text",
  "media_type": "text/plain"
}
```

Single file:

```json
{
  "kind": "file",
  "path_rel": "measurement.csv"
}
```

File set:

```json
{
  "kind": "file_set",
  "paths": [
    "sample.csv",
    "subdir/notes.txt"
  ]
}
```

For `file` and `file_set`, provide:

```text
--source-root DIRECTORY
```

Paths must remain under the selected root and may not traverse symbolic links.

Offline example:

```sh
vera-anchor verify ingest \
  --bundle bundle.json \
  --material material.json \
  --intent intent.json \
  --policy policy.json
```

Public Ingest verification additionally requires an independently selected Core anchor request UUID:

```text
--anchor-request-id CORE_ANCHOR_UUID
```

Example:

```sh
vera-anchor verify ingest \
  --mode public \
  --explorer-url https://explorer.veraanchor.com \
  --anchor-request-id 11111111-1111-4111-8111-111111111111 \
  --bundle bundle.json \
  --material material.json \
  --intent public-intent.json \
  --policy public-policy.json
```

The anchor request identifier is distinct from:

- the Ingest object key;
- a Dataset identifier;
- tenant-side Hash Factory anchors.

Example public policy:

```json
{
  "schema_version": "va.verification-policy.v1",
  "subject": {
    "kind": "ingest",
    "id": "hf.first-ingest.demo",
    "hedera_network": "mainnet"
  },
  "report_kind": "public_triangulation",
  "required_checks": [
    "ingest.source_binding",
    "ingest.bundle_consistency",
    "triangulation.public_record_hedera.message_sha3_512"
  ],
  "required_assurance": [
    "mirror_corroboration"
  ],
  "on_unresolved": "review"
}
```

## SAGE execution verification

Offline execution verification uses `subject.kind: "execution"`, the exact job identifier, and:

```json
"report_kind": "execution"
```

Example:

```sh
vera-anchor verify execution \
  --evidence execution.json \
  --intent intent.json \
  --policy policy.json
```

The policy's `execution_scope` supplies the independently expected profile, program, and optional exact result identifier.

The verifier does not silently select a latest result.

Public execution verification is explicit:

```sh
vera-anchor verify execution \
  --mode public \
  --explorer-url https://explorer.veraanchor.com \
  --evidence execution.json \
  --intent public-intent.json \
  --policy public-policy.json
```

Example public execution policy:

```json
{
  "schema_version": "va.verification-policy.v1",
  "subject": {
    "kind": "execution",
    "id": "4e4f624d-25b6-577f-93c6-075292e722d6",
    "hedera_network": "mainnet"
  },
  "report_kind": "execution_triangulation",
  "required_checks": [
    "binding.digest_recomputed"
  ],
  "required_assurance": [
    "mirror_corroboration"
  ],
  "execution_scope": {
    "profile": "sage-standards-v1",
    "expected_program": "sage",
    "requested_result_id": null
  },
  "on_unresolved": "review"
}
```

Public execution triangulation covers its supported Explorer and Hedera relationships.

It does not implicitly complete independent HCS standards verification.

## Independent SAGE HCS standards verification

`verify standards` is a separate networked workflow.

It uses Hedera Mirror and does not use Vera Anchor Explorer.

It therefore does not accept:

```text
--mode
--explorer-url
```

Example:

```sh
vera-anchor verify standards \
  --evidence execution.json \
  --intent intent.json \
  --policy standards-policy.json
```

An explicit Mirror API root may be supplied:

```text
--mirror-url https://mainnet-public.mirrornode.hedera.com/api/v1
```

The workflow resolves supported exact historical HCS references for the independently selected network.

The current standards surface supports:

- HCS-1;
- HCS-2;
- HCS-11;
- HCS-13;
- HCS-14;
- HCS-26.

Example policy:

```json
{
  "schema_version": "va.verification-policy.v1",
  "subject": {
    "kind": "execution",
    "id": "4e4f624d-25b6-577f-93c6-075292e722d6",
    "hedera_network": "mainnet"
  },
  "report_kind": "independent_standards",
  "required_checks": [
    "binding.digest_recomputed",
    "standards.references_resolved"
  ],
  "required_assurance": [
    "mirror_corroboration"
  ],
  "execution_scope": {
    "profile": "sage-standards-v1",
    "expected_program": "sage",
    "requested_result_id": null
  },
  "on_unresolved": "review"
}
```

HCS-26 resolution verifies the selected historical discovery/version path, canonical manifest, and integrity of manifest-declared HCS-1 files within the SDK's resource bounds.

Standards resolution does not authenticate Hedera consensus signatures, DID-controller ownership, historical account ownership, or publisher-key control.

It also does not prove that referenced software executed.

### HCS-1 compressed content

The Python verifier does not introduce a required runtime decompression dependency.

Where HCS-1 verification requires Zstandard decompression, a compatible decompression implementation must be supplied through the supported verifier interface.

The verifier must not silently install or invoke an unpinned external decoder.

## Verification material

Execution and standards commands accept optional caller-supplied verification material:

```text
--verification-material MATERIAL.json
```

Verification material remains untrusted input.

Supplying additional material does not change independently configured verification intent, network selection, execution scope, or policy requirements.

## Resolver configuration

`--explorer-url` is required for public Explorer workflows.

`--mirror-url` is optional where the selected workflow supports a configured Mirror API root.

Resolver origins are caller-controlled configuration and are never taken from evidence or publication contents.

Supported CLI endpoint validation requires HTTPS except for loopback HTTP development endpoints.

Unsupported path forms, embedded credentials, query strings, and URL fragments are rejected.

The verifier does not silently probe another Hedera network when the selected network cannot be resolved.

## Local input security

CLI file inputs are treated as hostile.

The CLI applies bounded handling including:

- bounded JSON files;
- bounded source-file counts;
- bounded aggregate source bytes;
- canonical producer-relative paths;
- explicit source-root containment;
- duplicate-path rejection;
- symbolic-link rejection;
- regular-file checks.

These controls are part of the verifier's security boundary rather than convenience validation.

## Report validation

Validate a saved portable report with:

```sh
vera-anchor report validate \
  --report report.json
```

This checks supported report structure and internal digest bindings.

It does not:

- rerun the original verification;
- reacquire public evidence;
- reacquire authorized private evidence;
- authenticate the report's producer;
- establish that the underlying evidence remains current.

## Policy assessment

Assess a saved portable report with:

```sh
vera-anchor policy assess \
  --report report.json \
  --policy policy.json
```

A saved report remains unauthenticated input.

Policy assessment of an imported report therefore cannot recreate fresh SDK verification authority merely because the report's internal structure and digest are valid.

When fresh verification authority is required, rerun the corresponding `verify` workflow.

## CLI result envelope

The CLI writes one JSON object to stdout using:

```json
{
  "schema_version": "va.verifier-cli-result.v1"
}
```

A completed command emits a result envelope containing the command and result.

Input or operational failure emits an error envelope.

Raw source bytes and credentials are not included in the CLI result envelope.

Operational errors are sanitized rather than exposing arbitrary exception or upstream response contents.

## Exit codes

The CLI uses deterministic exit semantics:

- `0` — `allow`, or a valid saved report for `report validate`.
- `1` — `deny`, or an invalid saved report.
- `2` — `review`.
- `64` — malformed command or input.
- `70` — operational failure.

Exit status reflects the verifier or policy result. It must not be interpreted as a broader authentication claim than the selected workflow establishes.

## Authentication boundary

Authenticated Dataset and Ingest verification is intentionally not exposed through this CLI.

Use the Python library API for caller-authorized Vera Anchor Core acquisition.

The CLI does not accept Core API keys or private-evidence credentials.

See [Authenticated verification](authenticated-verification.md).

## Assurance boundaries

No CLI mode by itself asserts:

- factual truth;
- Hedera consensus-signature authentication;
- DID-controller ownership;
- publisher-key ownership;
- historical account ownership;
- independent proof that registered software executed;
- independent cryptographic binding of service-assisted decrypted publication plaintext to a particular ciphertext.

The current public assurance dimension `mirror_corroboration` means supported evidence was independently observed through the configured Hedera Mirror path.

It must not be interpreted as stronger ledger or identity authentication.

## Related documentation

See:

- [Authenticated verification](authenticated-verification.md)
- [Verification semantics](verification-semantics.md)
- [Threat model](threat-model.md)
- [Conformance](conformance.md)
- [Security policy](../SECURITY.md)