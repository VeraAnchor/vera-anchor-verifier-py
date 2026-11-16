# Contributing

Contributions to the Vera Anchor Verifier SDK for Python are welcome.

The verifier is a security-sensitive, deterministic verification library. Changes should preserve the existing trust model, public contracts, cross-language parity, and fail-closed behavior.

Python v0.1 targets verification parity with `@veraanchor/verifier` JavaScript v0.2.0.

## Development requirements

- Python 3.12+

Create and activate a virtual environment, then install the project and required development tooling.

The repository uses:

- Ruff for linting and formatting.
- mypy in strict mode.
- pytest for unit, integration, and conformance tests.
- Hatchling for package builds.

## Development principles

Changes should preserve the following properties:

- Deterministic verification for equivalent deterministic inputs.
- Explicit trust boundaries.
- Fail-closed behavior.
- Read-only verification.
- Independently supplied verification intent.
- Independently supplied relying-party policy.
- Explicit Hedera network selection.
- Explicit resolver selection.
- Bounded processing of untrusted inputs.
- Stable canonicalization and digest behavior.
- JavaScript/Python parity where the behavior is shared.

Do not silently broaden what a successful verification result claims.

In particular:

```text
local consistency
!= producer authenticity
!= independent Hedera corroboration
!= policy authorization
```

These properties must remain distinct.

## JavaScript parity

The JavaScript verifier is the reference implementation for the Python parity target where behavior is shared.

Changes to shared verification behavior should be reviewed against the corresponding JavaScript implementation and existing cross-language golden vectors.

Language-specific implementation details do not need to be identical.

Public verification semantics should remain aligned unless a deliberate versioned divergence is explicitly approved.

Do not introduce Python-only behavior that changes:

- Verification meaning.
- Commitment construction.
- Canonicalization.
- Reason codes.
- Policy decisions.
- Report semantics.
- Resolver trust boundaries.
- Historical record selection.
- Network handling.

## Public contract changes

Treat changes to the following as compatibility-sensitive:

- Public schemas.
- Public dataclasses and TypedDicts.
- Public function signatures.
- Canonicalization.
- Commitment algorithms.
- Digest construction.
- Verification findings.
- Reason codes.
- Report schemas.
- Report digest behavior.
- Policy schemas.
- Policy evaluation.
- Resolver configuration.
- CLI commands and exit semantics.

If a change affects deterministic output or public verification meaning, it must not be treated as an incidental refactor.

## Security-sensitive changes

Extra review is required for changes involving:

- Filesystem paths.
- Source-root containment.
- Symbolic links.
- Network endpoints.
- Redirects.
- Authentication.
- Credential handling.
- Resolver behavior.
- Input bounds.
- Parsing.
- Canonicalization.
- Digest verification.
- Report validation.
- Policy authorization.
- Cross-network behavior.
- Error sanitization.
- Decrypted evidence.

Security-sensitive code should remain explicit and easy to audit.

Avoid clever abstractions that make trust boundaries harder to understand.

## Dependencies

The verifier intentionally minimizes required runtime dependencies.

Before adding a runtime dependency, consider whether the same behavior can be implemented safely using the Python standard library or existing verifier primitives.

A new dependency should have a clear justification and should be evaluated for:

- Security.
- Maintenance.
- Determinism.
- Transitive dependencies.
- Platform support.
- Supply-chain risk.

Do not add dependencies solely for convenience.

## Code style

Keep code compact, explicit, and professional.

Prefer:

- Small deterministic helpers.
- Clear type boundaries.
- Explicit validation.
- Immutable data where practical.
- Narrow public interfaces.
- Existing shared verifier primitives.
- Standard-library functionality where appropriate.

Avoid:

- Unnecessary abstraction layers.
- Large formatting-only rewrites.
- Duplicated verifier logic.
- Broad exception swallowing.
- Hidden network fallback.
- Implicit trust decisions.
- Unnecessary runtime dependencies.
- Large line-count increases without corresponding functionality.

Refactors should preserve behavior unless behavioral change is the explicit purpose of the contribution.

## Type safety

The project uses strict mypy checking.

New code should pass without suppressing legitimate typing problems.

Avoid `# type: ignore` unless there is a specific, documented reason that cannot reasonably be represented in the type system.

Do not use casts merely to hide an invalid state. Prefer validating and narrowing untrusted input before construction of typed verifier objects.

## Testing

Changes should include the smallest set of tests necessary to establish the intended behavior.

Depending on the component, this may include:

- Unit tests.
- Integration tests.
- Negative or fail-closed cases.
- Cross-language golden-vector coverage.
- Resolver boundary tests.
- Live conformance coverage.

Tests should verify behavior rather than implementation details where practical.

Security-sensitive changes should include relevant negative cases.

A successful test must not depend on elevated local privileges when equivalent behavior can be tested deterministically.

## Cross-language golden vectors

Golden vectors protect deterministic parity between the Python and JavaScript implementations.

Do not update a golden vector merely to make a failing implementation pass.

A golden-vector change requires understanding why the deterministic result changed and whether the corresponding public contract is intentionally changing.

Unexpected golden-vector drift should be treated as a compatibility defect until proven otherwise.

## Live conformance

Live tests validate selected workflows against public services and Hedera network observations.

They are not hermetic tests and should not replace deterministic unit or integration coverage.

Run live conformance explicitly:

```sh
VA_LIVE_TESTS=1 python -m pytest -m live -v
```

PowerShell:

```powershell
$env:VA_LIVE_TESTS="1"
python -m pytest -m live -v
Remove-Item Env:VA_LIVE_TESTS
```

External service failure must not be converted into successful verification.

## Required checks

Before submitting a change, run:

```sh
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python -m pytest
python -m build
```

All checks should pass.

Changes affecting live resolver or public-network behavior should also run the relevant live conformance tests when practical.

## Packaging changes

Changes to packaging, entry points, or build metadata should be tested from built artifacts rather than only from the repository source tree.

For release-affecting changes, verify:

- Wheel installation.
- Source distribution installation.
- Package metadata.
- Installed CLI behavior.
- Distribution contents.
- Absence of secrets or unintended files.

The source tree must not mask packaging defects during consumer smoke testing.

## CLI changes

The CLI is an adapter over the verifier APIs, not a separate verification implementation.

CLI changes should reuse the existing verifier workflows.

Preserve:

- Offline-by-default operation.
- Explicit public mode.
- Explicit resolver configuration.
- Source-root containment.
- Bounded file handling.
- Sanitized error output.
- Deterministic exit semantics.
- Exclusive report creation.

Do not duplicate verifier algorithms inside the CLI.

## Documentation

Documentation must describe behavior that actually exists in the current release.

Do not document speculative APIs, commands, files, or guarantees.

Documentation changes affecting verification semantics should be checked against both the Python implementation and the corresponding JavaScript behavior where parity applies.

Markdown files should remain readable as plain source and should not rely on repository-specific rendering tricks.

## Commit scope

Prefer focused changes.

A contribution should not combine unrelated:

- Feature work.
- Refactoring.
- Formatting changes.
- Dependency changes.
- Documentation restructuring.

Keeping changes narrow makes deterministic and security review substantially easier.

## Reporting security issues

Do not report exploitable vulnerabilities through a public issue.

See `SECURITY.md` for responsible disclosure guidance.

## License

By contributing to this repository, you agree that your contributions will be licensed under the project's MIT License.