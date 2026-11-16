# Conformance

The verifier is qualified against deterministic fixtures, cross-language golden vectors, integration workflows and live public observations.

Conformance exists to demonstrate that the Python SDK reproduces supported Vera Anchor commitment contracts and preserves the same verification semantics as the JavaScript verifier across shared offline and networked workflows.

Python v0.1 targets verification parity with `@veraanchor/verifier` JavaScript v0.2.0.

## Current coverage

Release qualification includes:

- Dataset offline recomputation and mainnet public triangulation;
- Ingest offline recomputation and mainnet public triangulation;
- authorized Dataset verification through Core acquisition, local recomputation, Hedera Mirror corroboration, portable reporting, and policy evaluation;
- authorized Ingest verification through Core acquisition, receipt verification, local commitment recomputation, Hedera Mirror corroboration, portable reporting, and policy evaluation;
- credential-isolation and fail-closed authorized acquisition behavior;
- SAGE execution verification using pinned mainnet evidence;
- public execution triangulation;
- independent HCS standards resolution for supported HCS-1, HCS-2, HCS-11, HCS-13, HCS-14 and HCS-26 references;
- HCS-26 historical discovery and version resolution;
- HCS-26 manifest and declared-file integrity verification;
- explicit network-scope and no-fallback behavior;
- Vera Anchor Explorer public-record resolution;
- Hedera Mirror corroboration;
- portable report generation and validation;
- relying-party policy evaluation;
- CLI command and security-boundary behavior;
- positive and adversarial cases for supported commitment, source, resolver, report, and policy boundaries;
- JavaScript v0.2.0 to Python v0.1 cross-language golden-vector parity.

Live tests depend on external public services and therefore validate both the verifier's live acquisition and verification paths and the continued availability of the pinned public evidence.

A live service outage, unavailable observation, unresolved reference, or acquisition timeout is not treated as a successful verification result.

Authorized integration tests are hermetic and do not require production Vera Anchor credentials. External Core and Mirror transport is simulated at the HTTP boundary while the SDK's authentication, resolution, verification, triangulation, reporting, and policy code executes normally.

## Cross-language parity

The Python and JavaScript implementations use language-appropriate internal structures while preserving shared public verification behavior.

Cross-language conformance focuses on deterministic contracts including:

- canonical commitments;
- digest construction;
- Dataset and Ingest verification behavior;
- execution verification behavior;
- triangulation relationships;
- portable report construction;
- policy outcomes;
- reason and status semantics where shared.

Golden vectors are pinned against the JavaScript v0.2.0 parity target.

An unexpected golden-vector difference should be treated as a compatibility defect until the semantic cause is understood.

Golden vectors must not be updated merely to make a failing implementation pass.

Any intentional change to a shared deterministic contract requires explicit versioning and coordinated review across implementations.

## Deterministic fixtures

Conformance fixtures should identify, where applicable:

- evidence profile and version;
- source provenance;
- exact source bytes or deterministic source representation;
- Hedera network;
- independently expected subject;
- independently expected digest or commitment;
- required checks;
- expected findings;
- expected triangulation relationship;
- expected policy outcome;
- whether the test is hermetic or depends on live public services.

Fixtures must not derive their trusted expectations solely from the untrusted evidence being verified.

Expected subjects, commitments, networks, and policies must come from independently controlled fixture context.

## Fixture security

Fixtures must not contain:

- production credentials;
- private tenant evidence;
- customer data;
- production API keys;
- private keys;
- undisclosed confidential material.

Missing fixture data must never be replaced with fabricated successful observations.

Test authorization material must be explicitly non-production and must not authenticate against any externally reachable service.

Adversarial fixtures should be preferred where they materially establish fail-closed behavior around trust boundaries.

## Unit qualification

Unit coverage exercises deterministic primitives and component-level behavior including supported:

- cryptographic helpers;
- Merkle verification;
- Dataset and Ingest contracts;
- execution verification;
- HCS standards;
- resolver parsing and bounded behavior;
- triangulation;
- portable reporting;
- report validation;
- policy evaluation;
- CLI parsing, source containment, endpoint validation and failure sanitization.

Unit tests should remain deterministic and must not depend on external network availability.

Where an operating-system capability can be simulated deterministically, tests should avoid requiring elevated local privileges.

## Integration qualification

Integration tests exercise complete verifier workflows rather than isolated helpers.

Current integration coverage includes:

- authorized Dataset and Ingest workflows;
- public Dataset and Ingest workflows;
- execution workflows;
- independent standards workflows;
- cross-component report and policy behavior.

Hermetic integration tests should exercise the real verifier orchestration while replacing only external transport boundaries where necessary.

They should not replace verifier logic with test-only success paths.

## Mainnet conformance

Live mainnet conformance covers the supported public Vera Anchor evidence paths for:

- Dataset;
- Ingest;
- SAGE execution.

These tests use exact expected references and explicit Hedera network selection.

The verifier must not silently substitute:

- testnet for mainnet;
- mainnet for testnet;
- latest registry state for an exact historical record;
- another Explorer record;
- another HCS observation.

A live-conformance failure may indicate either a verifier regression or inability to acquire required public evidence and should be investigated accordingly.

External service unavailability must not be converted into successful verification.

## Network-scope conformance

Network selection is part of the verification contract.

Tests should establish both positive behavior and relevant negative cases for:

- explicit `mainnet` selection;
- explicit `testnet` selection;
- cross-network evidence mismatch;
- missing required network scope;
- no silent fallback.

Network-scope failures are security-relevant because accepting equivalent-looking evidence from the wrong network changes the subject being verified.

## Resolver conformance

Resolver tests should establish:

- caller-controlled resolver origins;
- explicit network selection;
- bounded request and response handling;
- supported endpoint forms;
- no evidence-derived resolver authority;
- no credential forwarding across resolver boundaries;
- correct handling of unavailable or malformed observations;
- exact historical lookup where required;
- separation of Vera Anchor Explorer observations from Hedera Mirror observations.

A resolver observation must retain sufficient provenance for downstream triangulation and reporting.

## Authorized verification conformance

Authorized workflows must establish that authentication controls acquisition rather than verification semantics.

Tests should cover:

- caller-provided Core authorization;
- Core origin isolation;
- credential isolation;
- permitted private-evidence acquisition;
- local deterministic recomputation after acquisition;
- independent Mirror corroboration where required;
- fail-closed authorization failure;
- fail-closed service failure;
- exclusion of credentials from reports;
- exclusion of raw decrypted payloads from portable reports;
- policy behavior over the resulting verification findings.

Server verification fields must not replace local recomputation.

## Portable-report conformance

Portable-report tests should establish:

- deterministic report construction;
- canonical report digest behavior;
- supported report kinds;
- structural validation;
- tamper detection;
- preserved verification context;
- separation between imported-report validity and fresh verification authority.

A structurally valid imported report must not acquire authority to prove its own origin or recreate the verification workflow that originally produced it.

## Policy conformance

Policy tests should establish:

- independently supplied policy requirements;
- required check evaluation;
- required assurance evaluation;
- `allow`;
- `review`;
- `deny`;
- unresolved handling;
- subject matching;
- execution-scope matching where applicable.

Policies must not silently weaken because evidence is missing or because a resolver is unavailable.

## CLI conformance

CLI qualification should establish parity with the supported JavaScript command families:

```text
vera-anchor verify dataset
vera-anchor verify ingest
vera-anchor verify execution
vera-anchor verify standards
vera-anchor report validate
vera-anchor policy assess
```

Tests should also establish:

- offline-by-default behavior where supported;
- explicit public mode;
- explicit resolver configuration;
- bounded JSON input;
- bounded local source handling;
- canonical source paths;
- source-root containment;
- symbolic-link rejection;
- duplicate-path rejection;
- resolver endpoint validation;
- exclusive report creation;
- sanitized operational failures;
- deterministic exit semantics.

CLI conformance does not create a separate verification standard. The CLI must remain an adapter over the same library workflows.

## Reproducibility

Offline fixtures are expected to produce deterministic results from the same bytes and caller-supplied intent.

Networked conformance uses exact references and explicit network selection.

It must not silently substitute:

- a different Hedera network;
- latest registry state;
- an unrelated public record;
- a different subject;
- a producer-selected policy.

The deterministic repository qualification gates are:

```sh
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python -m pytest
python -m build
```

Live public conformance is run separately because it depends on externally available Vera Anchor Explorer and Hedera Mirror observations:

```sh
VA_LIVE_TESTS=1 python -m pytest -m live -v
```

PowerShell:

```powershell
$env:VA_LIVE_TESTS="1"
python -m pytest -m live -v
Remove-Item Env:VA_LIVE_TESTS
```

The live conformance suite preserves fail-closed verification semantics.

External service unavailability, unresolved evidence, or acquisition timeouts must not be converted into successful verification results.

## Release qualification

Conformance is necessary but not sufficient for publication.

A release also requires:

- successful deterministic qualification gates;
- successful live conformance;
- successful wheel build;
- successful source distribution build;
- clean installation from the wheel outside the repository;
- clean installation from the source distribution outside the repository;
- installed-library smoke testing;
- installed `vera-anchor` CLI smoke testing;
- package-content inspection;
- package metadata validation;
- confirmation that no credentials, virtual environments, caches, private fixtures, or unintended files are included in the distribution.

The source checkout must not mask packaging or installation defects.

A Python release claiming JavaScript parity should not be published while a known shared deterministic or public-behavior mismatch remains unresolved.