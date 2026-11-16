# Threat model

The verifier treats supplied bytes, JSON documents, source paths, evidence references and network responses as hostile input.

Its purpose is to establish bounded verification claims without allowing untrusted evidence to define the relying party's trust policy.

## Security boundaries

| Threat | Current boundary |
| --- | --- |
| Replayed evidence bound to the wrong subject | Verification intent is independently supplied and subject or commitment mismatches fail. |
| Cross-network substitution | Hedera network selection is explicit and checked; resolvers do not silently fall back to another network. |
| Fabricated corroboration | Observations retain source and resolver identity, and triangulation compares independently acquired facts rather than accepting producer summaries as proof. |
| Resolver redirection or arbitrary evidence URLs | Resolver origins are caller-controlled configuration. Supported resolver paths do not obtain resolver authority from evidence. |
| Credential leakage or forwarding | Authenticated credentials are scoped to the configured Core resolver and are not forwarded to Mirror, Explorer, or evidence-selected URLs. Credentials are excluded from portable reports. |
| Service-assisted decryption overclaim | Core may authorize and decrypt private evidence, but Core authorization or a server verification flag is not verification proof. The SDK independently recomputes supported checks after acquisition. |
| Cross-tenant private evidence access | Core remains authoritative for user, organization, scope and tenant authorization. The verifier does not bypass or reproduce Core access-control decisions and does not fall back to public evidence after authorization failure. |
| Oversized or adversarial inputs | Parsers, JSON structures, source sets, proof paths, HCS chunks, decompression and network responses are bounded at implementation-specific limits. |
| Stale or substituted registry state | Standards workflows use exact historical locators where required and do not silently select a latest entry. |
| Ledger-assurance overclaim | Hedera Mirror observations are reported as corroboration, not consensus-signature authentication. |
| Saved-report overclaim | Portable report validation checks structure and digests; a saved report does not authenticate itself or independently authorize `allow`. |
| Local path traversal or symlink substitution | CLI source workflows require canonical relative paths, constrain reads to the selected source root and reject symbolic-link traversal. |
| Duplicate or ambiguous local source identity | Source paths are canonicalized under the supported contract and duplicate paths are rejected. |
| Local file replacement or unsafe file type | CLI file handling verifies expected file types and applies bounded reads rather than trusting path strings alone. |
| Report overwrite or output substitution | CLI report creation is exclusive and does not silently overwrite an existing report. |
| Leakage of private evidence | Offline workflows do not perform network requests. Authenticated workflows disclose private evidence only through the explicitly configured Core path. Raw decrypted payloads and credentials are excluded from portable reports. |
| Sensitive upstream error disclosure | CLI operational failures are emitted through sanitized error envelopes rather than exposing raw exception or upstream response content. |
| Dependency compromise | The package intentionally has no required runtime dependencies; development and release dependencies are separately qualified. |

## Trust assumptions

The relying party is responsible for independently selecting:

- verification intent;
- expected subject identifiers;
- expected commitments;
- Hedera network;
- resolver origins;
- execution scope;
- required checks;
- required assurance;
- acceptance policy.

Values copied from untrusted evidence do not become trustworthy merely because they are supplied to the verifier as expectations.

An attacker-controlled evidence object must not be able to define both the claim being checked and the conditions under which that claim is accepted.

## Evidence is hostile

The verifier assumes that evidence may be:

- malformed;
- internally inconsistent;
- replayed;
- bound to another subject;
- bound to another Hedera network;
- partially missing;
- deliberately oversized;
- constructed to trigger parser edge cases;
- designed to exploit ambiguity in historical resolution;
- designed to induce unsupported or indeterminate behavior.

Verification code must therefore fail closed around malformed or contradictory input and preserve unresolved states where evidence cannot be established.

## Source material and filesystem inputs

CLI source roots and paths are attacker-controlled input.

The supported boundary includes:

- canonical relative-path validation;
- rejection of absolute paths;
- rejection of parent traversal;
- rejection of non-canonical path forms;
- explicit source-root containment;
- symbolic-link rejection;
- duplicate-path rejection;
- bounded source-file counts;
- bounded aggregate source bytes;
- regular-file checks.

Filesystem behavior must not allow a source manifest to escape the selected root or substitute an external file through symbolic-link traversal.

Tests for these controls should not require elevated host privileges where equivalent behavior can be exercised deterministically.

## Network and resolver inputs

Network-backed workflows assume remote services and responses may be unavailable, malformed, stale, inconsistent, or hostile.

Resolver authority belongs to the caller.

Evidence must not be able to redirect verification to an arbitrary service or silently select another Hedera network.

Supported network paths apply bounded request and response handling.

A resolver failure, timeout, missing observation, or malformed response must not become successful verification.

Vera Anchor Explorer and Hedera Mirror are distinct observation sources. A successful Explorer or Mirror lookup establishes only the claim represented by that resolver's documented result.

Mirror REST data is not an authenticated Hedera consensus proof.

## Authentication and credentials

Authenticated workflows use caller-authorized Vera Anchor Core access to acquire permitted private evidence.

Core remains authoritative for:

- authentication;
- organization and tenant authorization;
- authorization scope;
- permitted private-evidence retrieval;
- service-assisted recovery where applicable.

The verifier does not reproduce or bypass Core authorization.

Credentials are scoped to the configured Core resolver.

Authorization material must not be forwarded to:

- Hedera Mirror;
- Vera Anchor Explorer;
- evidence-selected URLs;
- unrelated services.

Credentials must not appear in portable verification reports.

Production credentials must not be included in fixtures, tests, logs, examples, or public issue reports.

## Service-assisted decryption

Core may perform service-assisted private-evidence recovery.

The returned plaintext is still untrusted evidence.

The verifier independently recomputes supported Dataset or Ingest commitments and relationships rather than accepting Core fields such as `verified`, hash-match indicators, or similar server assertions as proof.

The verifier does not currently claim independent cryptographic proof that service-assisted plaintext decryption corresponds to a particular ciphertext.

That assurance must not be inferred from successful authorization or verification of the resulting plaintext.

## Cross-source triangulation

Multiple observations do not automatically provide independent assurance.

Triangulation must preserve the provenance and role of each observation and compare independently acquired supported facts.

Producer summaries must not be treated as independent corroboration of themselves.

A `consistent` relationship means the compared supported facts agree. It does not mean the underlying claim is factually true.

## Historical resolution

Historical standards and registry verification must remain bound to exact selected references where the contract requires them.

An implementation must not silently:

- select the latest registry entry;
- substitute another version;
- move to another network;
- accept an unrelated record because it is structurally valid.

Historical ambiguity should remain unresolved or fail according to the applicable verification contract.

## Portable reports

Portable reports are hostile input when imported.

A report with valid internal digests is internally consistent under the report contract. That does not authenticate its origin or recreate the evidence acquisition and verification that originally produced it.

Imported reports must not acquire fresh verification authority merely because their structure and digest are valid.

Policy evaluation over an imported report must preserve that distinction.

## Policy attacks

Policy is part of the relying party's trust boundary.

Untrusted evidence must not be able to:

- lower required assurance;
- remove required checks;
- select a permissive unresolved policy;
- change the expected subject;
- change the expected network;
- change execution scope;
- choose its own sufficient acceptance criteria.

`allow`, `review`, and `deny` remain relying-party decisions over verifier findings, not intrinsic properties declared by the producer.

## Resource exhaustion

The verifier processes hostile structured and binary data and therefore applies bounded processing where supported.

Relevant resource boundaries include:

- JSON input size;
- source file count;
- aggregate source bytes;
- proof path size;
- HCS chunk count;
- HCS reconstructed content size;
- decompression output;
- registry traversal;
- network response size;
- recursion and collection bounds where applicable.

New parsers or resolvers should introduce explicit bounds rather than relying on benign input.

## Error handling

Errors must not disclose unnecessary sensitive material.

CLI operational failures are sanitized.

Library consumers remain responsible for ensuring that their own logging does not expose:

- credentials;
- decrypted private evidence;
- tenant data;
- private source material;
- raw sensitive upstream responses.

Unsupported or unavailable assurance should remain explicit rather than being transformed into a successful result.

## Out of scope

The verifier does not establish:

- factual truth or quality of the underlying content;
- DID-controller ownership or publisher control solely from a DID or UAID declaration;
- authenticated Hedera consensus signatures from Mirror REST responses;
- historical account ownership beyond the exact evidence the supported standards expose;
- independent proof that registered software actually executed;
- independent cryptographic binding of Explorer-assisted decrypted plaintext to publication ciphertext;
- independent cryptographic proof that Core's service-assisted plaintext decryption corresponds to a particular ciphertext.

These boundaries are intentional.

Unsupported or unavailable assurance must remain explicit rather than being inferred from successful authorization, decryption, integrity checks, public resolution, or Mirror corroboration.