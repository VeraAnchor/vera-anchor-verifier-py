# Vera Anchor Verifier SDK for Python

`vera-anchor-verifier` is the open-source Python implementation of the Vera Anchor Verifier SDK: a read-only verifier for Vera Anchor evidence and supported HCS-backed execution references.

The SDK is local-first. Offline workflows recompute commitments from caller-supplied evidence and source material without Vera Anchor credentials. Explicit public workflows can resolve Vera Anchor Explorer records and independently corroborate supported Hedera observations using caller-selected network configuration.

The verifier is designed for relying parties that need deterministic verification results they can evaluate under their own acceptance policy.

Python v0.1 targets verification parity with `@veraanchor/verifier` JavaScript v0.2.0.

## Status

Python v0.1 implements the supported verification surface of Vera Anchor Verifier JavaScript v0.2.0 and is qualified through deterministic unit tests, integration workflows, cross-language golden vectors, and live Hedera mainnet conformance.

The current release remains pre-1.0. Public schemas, verification semantics, reason codes, resolver boundaries, and policy behavior should therefore be treated as versioned interfaces.

## What it verifies

The current surface includes:

- Dataset and Ingest bundle, receipt, source-binding, and commitment recomputation.
- Public Dataset and Ingest triangulation across local evidence, Vera Anchor Explorer publication records, and Hedera Mirror observations.
- Authorized Dataset and Ingest verification through caller-authorized Vera Anchor Core acquisition, local recomputation, and independent Hedera Mirror corroboration.
- SAGE execution verification with independently supplied execution scope and expected program and result constraints.
- Public execution triangulation across local execution evidence, Vera Anchor Explorer records, and supported Hedera observations.
- Independent execution standards resolution.
- Pinned HCS-1, HCS-2, HCS-11, HCS-13, HCS-14, and HCS-26 verification.
- HCS-26 historical discovery and version resolution, canonical manifest verification, and integrity verification of manifest-declared HCS-1 files.
- Canonical portable verification reports with deterministic report digests.
- Explicit relying-party policies that convert verification findings into `allow`, `review`, or `deny` decisions.

## Assurance boundaries

Verification results are intentionally scoped.

A successful integrity check does not establish factual truth, publisher ownership, authorship, or code execution. Hedera Mirror observations provide independent corroboration of supported ledger data; they are not authenticated Hedera consensus proofs.

The SDK does not claim:

- DID-controller authentication.
- Historical account ownership.
- Consensus-signature authentication.
- Publisher-key control.
- Independent proof that registered software actually executed.
- Independent cryptographic proof that service-assisted decrypted plaintext originated from a particular publication ciphertext.
- Truth or validity of the underlying source material or claims.

Caller-controlled intent is part of the trust boundary. Subject identifiers, expected commitments, Hedera network selection, execution scope, and policy requirements must come from the relying party's trusted context rather than being copied from untrusted evidence.

In particular:

```text
local consistency
!= producer authenticity
!= independent Hedera corroboration
!= policy authorization
```

These are separate verification properties and must not be collapsed into one trust claim.

## Requirements

- Python 3.12+

The package has no required runtime dependencies.

## Installation

From PyPI after publication:

```sh
python -m pip install vera-anchor-verifier
```

For local development:

```sh
python -m pip install -e .
```

## Verification model

The SDK keeps evidence findings, cross-source consistency, and application decisions separate:

```text
source and evidence recomputation
            |
            v
public record and HCS resolution when requested
            |
            v
independent Mirror corroboration where supported
            |
            v
verification findings and observations
            |
            v
portable verification report
            |
            v
caller-supplied policy
            |
            v
allow / review / deny
```

Missing evidence, unsupported operations, indeterminate observations, and external service failures do not become successful verification.

Demonstrated contradictions fail.

The verifier does not silently change Hedera networks, select an alternate resolver origin, or select a latest execution result when an exact result is required.

## Offline verification

Offline verification performs no resolver network requests.

It operates only on caller-supplied:

- Evidence.
- Source material.
- Verification intent.
- Receipts or other supplied verification material.
- Relying-party policy.

Offline verification is the default for CLI workflows that support both offline and public operation.

## Public verification

Public verification is explicit.

Public workflows can combine:

- Local evidence recomputation.
- Vera Anchor Explorer publication resolution.
- Hedera Mirror observation.
- Cross-source triangulation.
- Relying-party policy evaluation.

Resolver origins are controlled by the caller rather than by untrusted evidence.

Supported resolvers use bounded requests, reject unsupported endpoint forms, and do not silently fall back to another Hedera network.

Vera Anchor Explorer publication resolution and Hedera Mirror corroboration remain distinct observations. An original HCS anchor is not automatically interpreted as a Vera Anchor publication receipt.

## Authorized verification

Authorized Dataset and Ingest workflows support caller-authorized acquisition of permitted private evidence through Vera Anchor Core.

Authentication remains outside the deterministic verification kernel.

Core remains authoritative for:

- Access control.
- Tenant authorization.
- Service-assisted private-evidence recovery.

The verifier independently recomputes the supported Dataset or Ingest checks and, where required, separately corroborates referenced HCS observations through Hedera Mirror.

Credentials are scoped to the configured Core resolver. They are not forwarded to Mirror, Explorer, or evidence-selected URLs.

Credentials and raw decrypted payloads are excluded from portable verification reports.

## Dataset verification

Dataset verification can recompute deterministic evidence from caller-supplied source material and compare it against the supplied Dataset evidence contract.

Supported workflows include:

- Local Dataset verification.
- Receipt-aware Dataset verification.
- Public Dataset triangulation.
- Authorized Dataset triangulation.
- Policy evaluation.
- Portable report generation.

Source material remains caller-controlled and is processed through bounded source readers.

## Ingest verification

Ingest verification supports deterministic verification of supported source material forms, including:

- JSON values.
- Text.
- Single files.
- File sets.

Supported workflows include:

- Local Ingest verification.
- Receipt-aware Ingest verification.
- Public Ingest triangulation.
- Authorized Ingest triangulation.
- Policy evaluation.
- Portable report generation.

Public Ingest verification requires an independently selected Core anchor request identifier rather than deriving trust scope from untrusted evidence.

## HCS standards verification

The standards surface supports pinned verification behavior for:

- HCS-1 content integrity and bounded file reconstruction.
- HCS-2 historical registry entries.
- HCS-11 AI-agent profile integrity and supported reference relationships.
- HCS-13 schema registration and canonical schema integrity.
- HCS-14 DID-backed UAID structural binding.
- HCS-26 historical discovery and version registration, canonical skill manifests, and manifest-declared HCS-1 file integrity.

Standards registration establishes only the supported properties of the observed records.

It does not establish that associated software executed, that a publisher currently controls a key, or that the underlying claims are factually true.

HCS-1 compressed content may require a caller-supplied compatible decoder where decompression is required. The Python verifier does not silently install or invoke an unpinned external decompression dependency.

## SAGE execution verification

The execution verification surface supports deterministic verification of supported SAGE execution evidence using independently supplied intent.

Execution scope may constrain:

- Verification profile.
- Expected program.
- Exact requested result identifier.
- Hedera network.

Public execution workflows can additionally resolve the selected execution record through Vera Anchor Explorer and corroborate supported Hedera observations.

Independent standards verification remains separate from Explorer-based public execution triangulation.

Successful public execution triangulation does not implicitly complete HCS standards verification.

Successful HCS standards resolution does not independently prove that the referenced software executed.

## Portable verification reports

The SDK can produce `va.portable-verification-report.v1` reports containing deterministic, digest-bound verification results and supported context.

A portable report includes a verification core and digest-bound contextual material.

Validating a saved report checks its structure and internal digests. It does not recompute the original evidence or authenticate the origin of the saved report.

A saved report therefore cannot promote itself into fresh SDK verification authority.

Decisions requiring verification of the underlying evidence should be produced by rerunning the appropriate verification workflow with independently supplied intent and policy.

## Policy decisions

Policy evaluation keeps application acceptance separate from verification mechanics.

A policy decision may be:

- `allow`: the requirements selected by the relying party were satisfied.
- `deny`: a required condition was contradicted or the policy requires denial.
- `review`: evidence remains unresolved under a policy that delegates unresolved cases for review.

Verification intent and policy must be supplied independently by the relying party.

Untrusted evidence cannot define its own sufficient acceptance threshold.

The current public assurance dimension is `mirror_corroboration`.

`mirror_corroboration` must not be interpreted as:

- Hedera consensus-signature authentication.
- Account-control authentication.
- Publisher-key authentication.
- DID-controller authentication.

## CLI

The package installs the `vera-anchor` command.

The CLI exposes the same primary verification command families as the JavaScript verifier:

```text
vera-anchor verify dataset
vera-anchor verify ingest
vera-anchor verify execution
vera-anchor verify standards
vera-anchor report validate
vera-anchor policy assess
```

The CLI is an adapter over the verifier APIs. It does not implement a separate verification kernel.

### Dataset verification

Offline Dataset verification from local source material:

```sh
vera-anchor verify dataset \
  --bundle bundle.json \
  --sources sources.json \
  --source-root ./source-files \
  --intent intent.json \
  --policy policy.json
```

The sources manifest contains canonical relative paths:

```json
{
  "paths": [
    "data.csv",
    "metadata/schema.json"
  ]
}
```

Source paths are constrained to the explicit source root. Absolute paths, parent traversal, non-canonical paths, duplicate paths, and symbolic-link traversal are rejected.

### Public Dataset verification

Explicit public Dataset verification:

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

An explicit Mirror endpoint may also be supplied where required:

```sh
--mirror-url https://mainnet-public.mirrornode.hedera.com/api/v1
```

Public mode requires a network-scoped intent and compatible public-verification policy.

### Ingest verification

Offline Ingest verification:

```sh
vera-anchor verify ingest \
  --bundle bundle.json \
  --material material.json \
  --intent intent.json \
  --policy policy.json
```

File-backed Ingest material additionally requires `--source-root`.

Public Ingest verification additionally requires an independently selected Core anchor request identifier:

```sh
--anchor-request-id 11111111-1111-4111-8111-111111111111
```

### Execution verification

Offline SAGE execution verification:

```sh
vera-anchor verify execution \
  --evidence execution.json \
  --intent intent.json \
  --policy policy.json
```

Public execution verification uses explicit public mode and an operator-selected Explorer endpoint:

```sh
vera-anchor verify execution \
  --mode public \
  --explorer-url https://explorer.veraanchor.com \
  --evidence execution.json \
  --intent public-intent.json \
  --policy public-policy.json
```

### Independent standards verification

```sh
vera-anchor verify standards \
  --evidence execution.json \
  --intent intent.json \
  --policy standards-policy.json
```

A caller-controlled Mirror API root may be supplied with `--mirror-url`.

### Portable report validation

```sh
vera-anchor report validate \
  --report report.json
```

This validates the portable report structure and digest bindings. It does not rerun the original verification workflow.

### Policy assessment

```sh
vera-anchor policy assess \
  --report report.json \
  --policy policy.json
```

Policy assessment of an imported report does not grant that report fresh SDK verification authority.

### Report export

Verification commands support exclusive report creation with:

```sh
--report-out verification-report.json
```

The CLI will not silently overwrite an existing report.

### CLI exit codes

The CLI uses deterministic exit semantics:

```text
0   verification or policy result accepted / valid
1   verification or policy result denied / invalid
2   policy result requires review
64  invalid CLI input
70  operational failure
```

Operational failures are emitted through sanitized machine-readable error envelopes rather than raw exception or upstream response content.

## CLI input security

CLI file and network inputs are treated as untrusted.

The CLI applies bounded input handling including:

- Maximum JSON input size.
- Maximum source file count.
- Maximum aggregate source bytes.
- Canonical relative source paths.
- Explicit source-root containment.
- Symbolic-link rejection.
- Duplicate-path rejection.
- Explicit resolver endpoint validation.
- HTTPS requirements except loopback development endpoints.
- Rejection of embedded resolver credentials, query strings, and fragments.
- Exclusive report creation.
- Sanitized failure output.

Resolver endpoints come from operator-controlled CLI arguments, never from evidence-selected URLs.

## Determinism

The verifier is designed around deterministic verification contracts.

Where verification depends only on caller-supplied deterministic inputs, equivalent inputs should produce equivalent verification findings, commitments, report cores, and report digests.

Network-backed workflows necessarily depend on externally observed records, but the interpretation of those observations remains deterministic under the verifier's pinned contracts and selected network.

No verification workflow should silently substitute:

- A different Hedera network.
- A different subject.
- A latest record for an exact historical record.
- A producer-selected policy for a relying-party policy.
- An unavailable verification check with a successful result.

## Conformance

The Python verifier is qualified against:

- Deterministic unit fixtures.
- Dataset verification workflows.
- Ingest verification workflows.
- Public Dataset and Ingest triangulation.
- Authorized Dataset and Ingest triangulation.
- SAGE execution verification.
- Public execution triangulation.
- Independent HCS standards resolution.
- Portable report validation.
- Policy evaluation.
- JavaScript v0.2.0 cross-language golden vectors.
- Hedera network-scope failure cases.
- Live Vera Anchor Explorer observations.
- Live Hedera mainnet Dataset conformance.
- Live Hedera mainnet Ingest conformance.
- Live Hedera mainnet SAGE execution conformance.

Live conformance depends on external public services.

Service unavailability is not converted into successful verification.

The Python and JavaScript implementations share deterministic golden-vector coverage for the supported cross-language verification contracts.

## Development

Create and activate a Python 3.12 virtual environment, then install the project and development tooling as appropriate for your environment.

Run linting:

```sh
python -m ruff check .
```

Check formatting:

```sh
python -m ruff format --check .
```

Run strict type checking:

```sh
python -m mypy src
```

Run the complete test suite:

```sh
python -m pytest
```

Build both distribution artifacts:

```sh
python -m build
```

The expected v0.1 artifacts are:

```text
dist/vera_anchor_verifier-0.1.0-py3-none-any.whl
dist/vera_anchor_verifier-0.1.0.tar.gz
```

### Live conformance

Live tests are explicitly enabled:

```sh
VA_LIVE_TESTS=1 python -m pytest -m live -v
```

PowerShell:

```powershell
$env:VA_LIVE_TESTS="1"
python -m pytest -m live -v
Remove-Item Env:VA_LIVE_TESTS
```

Live tests should not be treated as hermetic CI fixtures because they depend on public network services.

## Release qualification

A release should pass:

```sh
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python -m pytest
python -m build
```

Release qualification should additionally include:

- Wheel content inspection.
- Source distribution content inspection.
- Clean external-consumer installation from the wheel.
- Clean external-consumer installation from the source distribution.
- Installed `vera-anchor` CLI smoke testing outside the source repository.
- Package metadata validation.
- Live conformance.
- Verification that no credentials, environment files, caches, virtual environments, or unintended private fixtures are included in the distribution.

## Relationship to the JavaScript verifier

This package is the Python implementation of the Vera Anchor Verifier SDK.

Python v0.1 targets the supported verification behavior of:

```text
@veraanchor/verifier v0.2.0
```

Parity is based on verification semantics and supported public behavior rather than language-specific implementation details.

The two implementations use language-appropriate module layouts while preserving the same core distinctions between:

- Evidence recomputation.
- Public resolution.
- Hedera corroboration.
- Execution verification.
- HCS standards verification.
- Portable reporting.
- Relying-party policy evaluation.

Cross-language deterministic behavior is qualified using shared golden vectors.

JavaScript repository:

https://github.com/VeraAnchor/vera-anchor-verifier

Python repository:

https://github.com/VeraAnchor/vera-anchor-verifier-py

## Security

Treat all evidence, resolver responses, source material, references, receipts, imported reports, and remote service responses as hostile input.

Do not derive trusted intent or policy from untrusted evidence.

Do not include credentials, private tenant evidence, customer data, or undisclosed vulnerabilities in public issues.

The verifier is read-only. It is not an authorization service, key-management system, transaction signer, or source of factual truth.

Applications integrating the verifier remain responsible for their own authorization, secret management, tenant isolation, and acceptance policy.

## Contributing

Changes to public schemas, commitment algorithms, canonicalization behavior, verification semantics, reason codes, resolver trust boundaries, report digests, or policy behavior can affect deterministic compatibility across implementations.

Such changes should be reviewed against:

- Existing Python fixtures.
- Existing JavaScript behavior.
- Cross-language golden vectors.
- Integration qualification.
- Public-network conformance where applicable.

Avoid changing public verification semantics incidentally during refactoring.

## License

Licensed under the MIT License.

See `LICENSE` for the full license text.