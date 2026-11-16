# Security Policy

Security is a core property of the Vera Anchor Verifier SDK.

The verifier processes untrusted evidence, source material, resolver responses, receipts, references, imported reports, and network observations. Security issues that could weaken verification semantics, trust boundaries, deterministic behavior, or input isolation should be reported privately.

## Reporting a vulnerability

Do not open a public GitHub issue for a vulnerability that could expose users, credentials, private data, verification bypasses, or exploitable implementation details.

Use GitHub's private vulnerability reporting or Security Advisory functionality for this repository when available.

A useful report should include:

- A concise description of the issue.
- The affected version or commit.
- The affected component or verification workflow.
- Reproduction steps or a minimal proof of concept.
- The expected behavior.
- The observed behavior.
- The security impact.
- Any known prerequisites or environmental constraints.

Do not include real customer credentials, private tenant data, production secrets, or unnecessary sensitive information in a report.

If private vulnerability reporting is unavailable, contact the Vera Anchor maintainers through a private Vera Anchor communication channel rather than publishing exploit details.

## Security scope

Security-relevant issues include, but are not limited to:

- Verification bypasses.
- Incorrect successful verification of contradictory evidence.
- Fail-open behavior where verification should remain unresolved or fail.
- Cross-network or cross-subject confusion.
- Incorrect Hedera network selection.
- Resolver-origin confusion or unsafe redirects.
- Credential leakage or forwarding to unintended origins.
- Source-root escape or path traversal.
- Symbolic-link or filesystem containment bypasses.
- Unbounded input processing or denial-of-service conditions.
- Malformed input causing unsafe interpretation.
- Canonicalization or digest inconsistencies.
- Report digest or integrity bypasses.
- Imported reports acquiring authority they should not possess.
- Policy evaluation that incorrectly produces `allow`.
- Trust-boundary confusion between local verification, public resolution, Hedera corroboration, and authorization.
- Cross-language inconsistencies that materially change verification semantics.
- Exposure of decrypted material or sensitive resolver responses.

General bugs without a security impact may be reported through the normal issue tracker.

## Verification trust boundaries

The SDK intentionally separates several different properties:

```text
local consistency
!= producer authenticity
!= independent Hedera corroboration
!= policy authorization
```

A successful verification result establishes only the properties explicitly checked by the selected workflow.

The verifier does not inherently establish:

- Factual truth of source material.
- Authorship.
- Publisher ownership.
- DID-controller authentication.
- Historical account ownership.
- Publisher-key control.
- Hedera consensus-signature authentication.
- Independent proof that registered software executed.
- Independent cryptographic proof that service-assisted decrypted plaintext originated from a particular publication ciphertext.

Applications must not promote a narrower verification result into a stronger trust claim.

## Caller-controlled trust inputs

Verification intent and policy are part of the relying party's trust boundary.

Trusted values such as these must come from caller-controlled context:

- Subject identifiers.
- Expected commitments.
- Hedera network selection.
- Execution scope.
- Expected program.
- Exact result identifiers.
- Required checks.
- Required assurance.
- Acceptance policy.

Untrusted evidence must not be allowed to define the conditions under which that same evidence is accepted.

## Network and resolver security

Public verification uses explicit resolver configuration.

The verifier must not silently:

- Change Hedera networks.
- Substitute another resolver origin.
- Select an evidence-controlled endpoint.
- Forward credentials to unrelated services.
- Convert resolver failure into successful verification.
- Replace an exact historical lookup with a latest record.

Credentials supplied for authorized Vera Anchor Core access are scoped to Core and must not be forwarded to Vera Anchor Explorer, Hedera Mirror, or evidence-selected URLs.

Public network observations remain observations from the configured resolver. Hedera Mirror corroboration is not equivalent to consensus-signature authentication.

## Filesystem and local input security

CLI and library consumers should treat all local input paths as untrusted.

The CLI applies controls including:

- Canonical relative source paths.
- Explicit source-root containment.
- Parent-traversal rejection.
- Absolute-path rejection.
- Symbolic-link rejection.
- Duplicate-path rejection.
- Bounded JSON input.
- Bounded source file counts.
- Bounded aggregate source bytes.
- Exclusive report creation.

Changes that weaken these controls should be treated as security-sensitive.

## Portable reports

Portable verification reports are digest-bound records of verification results and context.

Validation of an imported report establishes report structure and internal digest consistency. It does not rerun the original evidence verification or authenticate the origin of the saved report.

An imported report must not acquire fresh SDK verification authority merely because it is internally valid.

Applications requiring fresh verification should rerun the appropriate verifier workflow using independently supplied intent and policy.

## Deterministic verification

Verification behavior is intended to remain deterministic for equivalent deterministic inputs.

Security-sensitive changes include modifications to:

- Commitment algorithms.
- Canonicalization.
- Digest construction.
- Comparison behavior.
- Reason codes.
- Verification status mapping.
- Policy decisions.
- Report construction.
- Historical record selection.
- Network selection.
- Cross-source triangulation.

Such changes require careful compatibility review and corresponding tests.

## Dependency policy

The verifier intentionally keeps its required runtime dependency surface minimal.

New runtime dependencies should be introduced only when necessary and must be evaluated for:

- Security posture.
- Maintenance status.
- Determinism.
- Supply-chain exposure.
- Transitive dependency cost.
- Cross-platform behavior.

Do not introduce optional network or decoding behavior that silently changes verification semantics.

## Secrets and sensitive data

Never commit:

- API keys.
- Access tokens.
- Private keys.
- Wallet credentials.
- `.env` files containing secrets.
- Production database credentials.
- Customer or tenant data.
- Private decrypted evidence.
- Internal service credentials.

Verification reports and error output should not expose credentials or raw sensitive upstream responses.

## Supported versions

Security fixes are expected to target the current supported release line.

While the project remains pre-1.0, users should prefer the latest published version and review release notes for changes to verification semantics or security behavior.

## Disclosure

Please allow maintainers reasonable time to investigate and address a reported vulnerability before public disclosure.

Coordinated disclosure helps protect downstream users while a fix and release are prepared.