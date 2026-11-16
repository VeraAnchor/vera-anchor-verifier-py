# Verification semantics

The verifier separates evidence findings, cross-source consistency and relying-party decisions. These layers are related but are not interchangeable.

## Finding outcomes

Every supported verification check has one of five normalized outcomes:

- `pass` — the available evidence satisfies the exact check.
- `fail` — the verifier demonstrated a contradiction or violation of an explicit requirement.
- `indeterminate` — the check could not be established because required evidence or an external observation was unavailable.
- `unsupported` — the requested material or operation is outside the verifier's supported contract or bounded implementation.
- `skipped` — the check was intentionally not applicable or not requested in the selected workflow.

Missing evidence and service outages are not contradictions and therefore must not be converted into `fail` unless an explicit requirement itself is violated.

## Triangulation

Cross-source relationship states are:

- `consistent` — the compared independently acquired facts agree for all required comparisons;
- `conflict` — at least one required comparison demonstrates a contradiction;
- `incomplete` — the relationship cannot be fully established because required observations are missing, indeterminate or unsupported.

Consistency is not factual truth. It means the compared evidence sources agree on the supported facts that were actually checked.

## Policy decisions

Policy decisions are separate from verification findings:

- `allow` — all requirements selected by the relying party are satisfied under the policy.
- `deny` — a required condition is contradicted or the policy otherwise requires denial.
- `review` — the evidence is unresolved under a policy that delegates unresolved cases for review.

Verification intent and policy must be controlled by the relying party. An untrusted receipt, bundle, execution record or standards projection cannot define its own sufficient acceptance threshold.

Policies using `on_unresolved: "deny"` may require unresolved evidence to fail closed instead of producing `review`.

## Assurance

The current policy assurance dimension is `mirror_corroboration`.

It means the relevant supported fact was independently observed through the SDK's Hedera Mirror resolver path. It does not mean that the SDK authenticated Hedera consensus signatures or established control of an account, DID or publisher key.

The SDK also performs deterministic integrity and binding checks where the underlying contract supports recomputation. Those checks are represented through findings rather than being silently promoted into a broader authentication claim.

The following properties remain distinct:

```text
local consistency
!= producer authenticity
!= independent Hedera corroboration
!= policy authorization
```

A workflow satisfying one property does not implicitly satisfy another.

## Offline verification

Offline verification operates on caller-supplied evidence, source material, verification intent, receipts or other supplied verification material, and relying-party policy.

Offline workflows do not perform resolver network requests.

A successful offline result establishes only the supported properties that can be recomputed or checked from those supplied inputs.

It does not independently establish that a public record exists, that Hedera contains the claimed observation, or that the producer controls an external identity.

## Public verification

Public verification is explicit.

Supported public workflows may combine:

- local evidence recomputation;
- Vera Anchor Explorer resolution;
- Hedera Mirror observation;
- cross-source triangulation;
- portable reporting;
- relying-party policy evaluation.

Vera Anchor Explorer and Hedera Mirror are distinct observation sources.

An Explorer publication record is not automatically equivalent to an original HCS anchor, and a Mirror observation is not an authenticated Hedera consensus proof.

Public resolver origins and Hedera network selection belong to the relying party's trusted configuration. Untrusted evidence cannot select its own resolver authority or silently move verification to another network.

## Authentication boundary

Authentication determines which private evidence the verifier may acquire. It does not determine whether that evidence verifies.

Vera Anchor Core remains authoritative for authentication, tenant authorization, and permitted private-evidence retrieval. The verifier does not reproduce Core access-control logic.

When Core performs service-assisted decryption, the returned plaintext remains untrusted evidence. The SDK independently recomputes every supported Dataset or Ingest check rather than treating Core authorization, `verified` fields, hash-match fields, or other server assertions as verification proof.

Authenticated evidence retains explicit `authorized_service` provenance. That provenance is not itself an integrity or assurance result.

Where supported, the verifier separately resolves the selected Hedera message through its Mirror path and compares independently acquired message commitments with the Core-provided message binding.

Authorization failure, service unavailability, unresolved evidence, or missing Mirror corroboration does not become successful verification.

Accordingly, authenticated acquisition does not by itself establish:

- Hedera consensus-signature authentication;
- DID-controller or publisher-key authentication;
- historical ownership of an account;
- factual truth of the verified content;
- independent cryptographic proof that service-assisted plaintext decryption corresponds to a particular publication ciphertext.

These properties require separate explicit evidence or assurance. They must not be inferred from successful authorization, decryption, integrity checks, or Mirror corroboration.

## Dataset and Ingest interpretation

Dataset and Ingest workflows recompute supported commitments from caller-supplied source material and compare those commitments with the relevant evidence contract.

A matching commitment establishes the supported deterministic relationship between the supplied source material and evidence.

It does not establish:

- who originally produced the material;
- whether the material is factually correct;
- whether the producer currently controls an identity or account;
- whether a service assertion about the material should be trusted without recomputation.

Receipt verification similarly establishes only the supported deterministic receipt contract and relationships actually checked.

## Execution interpretation

Execution verification operates against independently supplied execution intent and scope.

The relying party may constrain supported properties including:

- execution profile;
- expected program;
- requested result identifier;
- Hedera network.

Execution evidence must not define the expectations under which that same evidence is accepted.

Public execution triangulation and independent standards resolution are separate assurance paths.

Successful public execution triangulation does not implicitly complete HCS standards verification.

Successful HCS standards resolution does not independently prove that the registered software executed.

## Supported standards interpretation

The standards path supports pinned verification behavior for HCS-1, HCS-2, HCS-11, HCS-13, HCS-14 and HCS-26 as exposed by the SDK.

Standards registration or profile publication is evidence of the declared record and its supported integrity relationships. It is not evidence that associated software executed, that a publisher currently controls a key, or that a claim is factually true.

HCS-26 verification resolves the selected historical discovery/version path, verifies the canonical manifest, and verifies integrity for the manifest-declared HCS-1 files within the SDK's resource bounds.

Historical resolution must remain tied to the selected historical reference. The verifier must not silently substitute a latest registry entry where an exact historical observation is required.

## Portable reports

`va.portable-verification-report.v1` is a deterministic, digest-bound representation of a verification result and its supported context.

Validating a saved portable report checks its structure and internal digests.

It does not:

- recompute the underlying evidence;
- repeat public resolver acquisition;
- repeat authenticated Core acquisition;
- authenticate the report's origin;
- establish that the report remains current;
- independently authorize `allow`.

Accordingly, a saved report cannot elevate itself into an SDK-authenticated `allow` decision.

Fresh verification with independently supplied intent and policy is required when a relying party needs an SDK-computed decision over the underlying evidence.

Raw decrypted payloads and authorization credentials are not part of the portable report authority model.

## Resolver failures

A resolver failure is not positive evidence.

Timeouts, unavailable services, missing observations, malformed responses, unsupported records, and unresolved references must remain explicit through the relevant verification, triangulation, or policy outcome.

The verifier must not silently:

- substitute a different Hedera network;
- change resolver origins;
- select an unrelated public record;
- replace an exact historical reference with latest state;
- treat unavailable evidence as verified.

## Authentication and identity nonclaims

A SHA3-512 match, HCS content checksum, Explorer resolution, Core authorization, service-assisted decryption, or Mirror observation does not by itself establish:

- Hedera consensus-signature authentication;
- DID-controller authentication;
- publisher-key authentication;
- current or historical account ownership;
- factual truth of the verified content;
- independent proof that particular software executed;
- independent cryptographic binding of service-assisted decrypted plaintext to a particular publication ciphertext.

Additional assurance must be represented explicitly rather than inferred by changing the meaning of existing verification outcomes.