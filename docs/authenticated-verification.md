# Authenticated verification

The Vera Anchor Verifier SDK for Python supports optional authenticated acquisition of private Dataset and Ingest evidence through Vera Anchor Core.

Authentication controls evidence acquisition. It does not determine whether acquired evidence verifies.

The authenticated workflow preserves the same separation used elsewhere in the verifier:

```text
caller-controlled intent and policy
            |
            v
authorized Core evidence acquisition
            |
            v
local recomputation of supported evidence
            |
            v
independent Hedera Mirror corroboration
            |
            v
triangulation and portable report
            |
            v
allow / review / deny
```

## Security model

Vera Anchor Core remains authoritative for authentication, tenant authorization, and access to private evidence.

The verifier does not reproduce Core authorization logic. A successful authenticated request establishes only that Core permitted the caller to retrieve the requested evidence.

Core may also perform service-assisted decryption. Decrypted evidence remains untrusted input. The verifier independently recomputes supported Dataset or Ingest checks rather than accepting Core fields such as `verified`, hash-match indicators, or other server assertions as verification proof.

Authenticated evidence retains `authorized_service` provenance. That provenance does not by itself satisfy an integrity, consistency, or assurance requirement.

Where supported, the verifier separately resolves the referenced Hedera message through its Mirror resolver and compares the independently acquired message commitment with the Core-provided message binding.

## Credentials

Authenticated workflows use an `AuthProviderV1`.

For the current Vera Anchor bearer-token/API-key contract, applications can use `create_static_bearer_auth_provider_v1`.

```python
import os

from vera_anchor_verifier import create_static_bearer_auth_provider_v1

api_key = os.environ.get("VERA_ANCHOR_API_KEY")

if not api_key:
    raise RuntimeError("VERA_ANCHOR_API_KEY is required")

auth_provider = create_static_bearer_auth_provider_v1(api_key)
```

Applications must obtain credentials from an appropriate secret-management mechanism.

Do not commit API keys or other production credentials to source control.

Authorization material is scoped to the configured Core request. Supported authenticated resolution does not forward credentials to Hedera Mirror, Vera Anchor Explorer, redirects, or evidence-selected URLs.

Credentials are not included in portable verification reports.

## Authenticated Dataset verification

`triangulate_authorized_dataset_with_policy_v1` combines:

- local Dataset source and commitment recomputation;
- caller-authorized retrieval of the private Dataset Registry event;
- comparison of locally recomputed Dataset identity and fingerprint with the authorized registry evidence;
- independent Hedera Mirror corroboration of the referenced HCS message;
- portable report creation;
- relying-party policy evaluation.

The caller must independently supply the Dataset subject, Hedera network, HCS reference, and policy.

The lower-level `triangulate_authorized_dataset_v1` workflow is also available when an application needs the triangulation result without policy evaluation.

See `examples/authorized_dataset_policy.py`.

## Authenticated Ingest verification

`triangulate_authorized_ingest_with_policy_v1` combines:

- local Ingest material and commitment recomputation;
- caller-authorized retrieval of the private Ingest receipt;
- verification of the receipt's supported deterministic contract;
- comparison of locally recomputed commitments with the authorized receipt;
- independent Hedera Mirror corroboration of the referenced HCS message;
- portable report creation;
- relying-party policy evaluation.

Supported comparisons include the Ingest object key, fingerprint, bundle digest, Merkle root, idempotency key, item count, and total bytes where available under the selected contract.

The lower-level `triangulate_authorized_ingest_v1` workflow is also available when an application needs the triangulation result without policy evaluation.

See `examples/authorized_ingest_policy.py`.

## Caller-controlled authority

Authenticated evidence acquisition does not move verification intent into Vera Anchor Core.

The relying party must independently control:

- subject identity;
- Hedera network;
- HCS reference;
- source material;
- expected commitments where applicable;
- verification policy;
- required checks;
- required assurance.

An authorized service response cannot define the conditions under which that same response is accepted.

## Policy behavior

Authenticated policy workflows preserve the normal verifier decisions:

- `allow` means the required verification checks, authenticated evidence relationships, and requested assurance were established.
- `deny` means a required condition was contradicted or the policy otherwise requires denial.
- `review` means required evidence remains unresolved under a policy that delegates unresolved cases for review.

Authorization failure, service unavailability, or missing Mirror evidence does not become a successful verification result.

Policies using `on_unresolved: "deny"` can require unresolved evidence to fail closed instead of returning `review`.

Authenticated verification therefore preserves the same distinction used throughout the SDK:

```text
authorized acquisition
!= evidence integrity
!= Hedera corroboration
!= policy authorization
```

Each property must be established independently where the selected workflow requires it.

## Portable reports

Authenticated workflows produce the same digest-bound portable report contract used by the rest of the SDK.

Raw decrypted payloads and authorization credentials are not included in portable reports.

A saved portable report remains unauthenticated input when loaded later. Validating its structure and digest does not recreate the authenticated acquisition step, so a saved report cannot independently promote itself into a fresh SDK-authorized `allow`.

Applications requiring a fresh decision over the underlying evidence should rerun the authenticated verification workflow with independently supplied intent and policy.

## Service-assisted decryption boundary

The current authenticated workflow uses Core for authorized private-evidence recovery where required.

The verifier independently checks supported content and commitment relationships after acquisition, but it does not claim an independent cryptographic proof that Core's returned plaintext was decrypted from a particular ciphertext.

Authenticated acquisition therefore provides authorized private-evidence access and cross-source verification without changing the meaning of existing integrity or Mirror-assurance claims.

A successful authenticated workflow does not by itself establish:

- Hedera consensus-signature authentication;
- DID-controller authentication;
- publisher-key authentication;
- historical account ownership;
- factual truth of the recovered content;
- independent cryptographic proof that the recovered plaintext corresponds to a particular ciphertext.

Future acquisition mechanisms may extend the evidence-recovery boundary without changing the deterministic verification, report, or policy contracts.

## Network and resolver boundaries

Authenticated verification requires an explicit Hedera network.

The verifier does not silently try another network if evidence cannot be resolved.

Core origin configuration belongs to the caller. Evidence cannot redirect the authenticated resolver to an arbitrary service.

Hedera Mirror remains a separate observation source and does not receive Core authorization material.

Vera Anchor Explorer is also a separate resolver boundary and does not receive Core authorization material.

Resolver failure, authorization failure, malformed responses, or unavailable observations must remain unresolved or fail according to the applicable verification and policy contracts. They must not be converted into successful verification.

## Tenant isolation

Core remains authoritative for tenant and organization access control.

The verifier does not infer tenant authority from evidence and does not bypass Core authorization to obtain private material.

A failed authorized acquisition must not trigger an implicit fallback to another tenant, another Core origin, or public evidence as a substitute for the requested private evidence.

Applications integrating authenticated verification remain responsible for securely selecting the correct Core origin and authorization material for the current tenant and request.

## CLI support

Authenticated verification is exposed through the Python library API.

The `vera-anchor` CLI supports offline, public, execution, standards, report-validation, and policy-assessment workflows without accepting private Vera Anchor credentials.

This separation keeps private authorization material out of the general-purpose CLI surface while preserving the same authenticated library capabilities as the JavaScript verifier.

## Related documentation

See:

- [Verification semantics](verification-semantics.md)
- [Threat model](threat-model.md)
- [Conformance](conformance.md)
- [CLI reference](cli.md)
- [Security policy](../SECURITY.md)