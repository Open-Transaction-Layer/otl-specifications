# OTL — Open Transaction Layer

## Identity Layer — Technical Specification

**did:webvh & DID Document Structure · Verifiable Credentials & Bitstring Status List Revocation · Trust Anchor Management**

- **Status:** Draft
- **Version:** 0.6
- **Date:** October 20, 2026
- **Layer:** 1 — Identity

---

## 1. Introduction and Scope

This specification defines the Identity layer of the Open Transaction Layer (OTL) protocol, the foundation which establishes self-governed, cryptographic and legal identity. The Identity layer answers three questions for any participant in the network:

1. **Who are you, cryptographically?** — the did:web and did:webvh methods and DID document structure (§2, §3).
2. **Who are you, legally?** — Verifiable Credentials issued by accredited third parties, and how their revocation is checked (§4, §5).
3. **Who decides whether to trust that attribution?** — the trust anchor model (§6), with the OTL LEI Credential as its first concrete instance (§4).

This document is scoped to those three areas. 

### 1.1 Normative Language

MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used per RFC 2119. Where this document reproduces a rule from a message or field table defined elsewhere in the OTL spec set, that table is treated as authoritative and this document adds only explanatory framing.

---

## 2. Digital Identity, provided by DID

Every OTL network participant is identified by a did:webvh or did:web Decentralized Identifier. Both methods resolve to an HTTPS endpoint hosted on the participant's own domain; there is no external registry, blockchain anchor, or consortium-operated directory in the resolution path. This directly serves design principles P3 (Self-Sufficient) and P4 (Open): any entity that controls an HTTPS domain can mint a DID and begin exchanging protocol messages, and no single operator sits in the resolution path for any other participant's identity. Participants MAY delegate some or all of their protocol participation to a trusted and contracted software provider while maintaining responsibility for counterparty due diligence.

### 2.1 Method Selection

did:webvh is RECOMMENDED. did:webvh adds an append-only, tamper-evident version history (§2.3) and a self-certifying genesis document (§2.2) on top of plain domain control. did:web has none of these: its DID document is only secured by domain ownership so a participant's entire identity history is only as trustworthy as the current state of the webserver, with no independent way to verify past states or detect an unannounced key substitution.

did:web MAY be used where a participant's infrastructure cannot yet support the did:webvh log format, or during migration. A verifier MUST NOT treat a did:web participant as offering the same rotation-integrity or historical-verifiability guarantees as a did:webvh participant, and MAY apply a stricter risk framework when interacting with counterparties using did:web (§6.1).

Both methods use the same DID document structure (§3) and the same Verifiable Credential and revocation mechanisms (§4, §5); the difference is confined to identifier resolution and update history, described below.

### 2.2 Self-Certifying Identifier (SCID) — did:webvh only

The DID includes a SCID component derived by hashing the genesis DID document (version 1 of the log). The identifier therefore encodes cryptographic proof of the document it was created from: any party can confirm that the current DID document is the legitimate continuation of the original one, without consulting a central registry. This is the mechanism that makes downstream constructs verifiable independent of who currently controls the domain, and provides a stable, globally unique identifier across key rotations.

This mechanism is specific to did:webvh. A did:web identifier has no SCID and no genesis-document commitment: its current DID document is trusted purely on the strength of present domain control, with no cryptographic tie to any earlier state.

### 2.3 Version Log and Tamper-Evident History — did:webvh only

The version log at `/.well-known/did.jsonl` is an append-only, tamper-evident history of every DID document version the participant has published. Each entry chains to the previous one. Historical states are independently verifiable offline — a verifier does not need to trust the currently-serving domain operator's account of what version 1 said; it can fetch and hash-check the log entry itself.

Each entry's authority to exist comes from a proof signed by the DID Management Key. 

did:web has no equivalent. A did:web participant's document has no append-only history; there is nothing for a verifier to fetch and hash-check to confirm what an earlier state said.

**Caching and `ttl`.** The did:webvh `ttl` parameter tells a resolver how long it may cache the DID document before refetching, and defaults to 3600 seconds. A verifier MUST NOT apply a `ttl` above 3600 seconds: it MUST treat a cached DID document or log as stale after at most 3600 seconds, whatever value the log declares. A verifier MAY honour a lower `ttl`, including `0`. Because whoever holds the DID Management Key (§3.2.2) controls this parameter, a participant that sets a high `ttl` cannot make verifiers hold stale state longer, for example after a compromise has been recovered. Participants SHOULD NOT set `ttl` above 3600.

### 2.4 Recommended: did:webvh Watchers

A participant SHOULD list one or more watcher endpoints as per did:webvh 1.0 specification so that verifiers can independently confirm what the participant's DID document actually said at a given time, catching split-view attacks and compromised rotations.

The `watchers` parameter lives in the version log (§2.3), so whoever holds the DID Management Key (§3.2.2) controls it: after a hostile takeover the attacker can replace the watcher list with watchers it operates. A hosting provider (§4.12) can therefore also list watchers in an OtlHostingCredential (§4.14), where they are signed by a party other than the DID controller and can be withdrawn by revoking the credential.

**Watcher set.** A verifier uses the union of the watchers in the DID's active `watchers` parameter and the watchers in a valid OtlHostingCredential for that DID (§4.16). The verifier MUST compare the log it retrieved with the log each queried watcher reports and MUST treat any divergence as a failed resolution. A watcher listed only in the DID's own `watchers` parameter MUST NOT count as independent corroboration, since the DID controller chose it; only watchers from a valid OtlHostingCredential, or from the verifier's own configuration, do.

### 2.5 Trust Model

Domain control establishes cryptographic identity within the network — nothing more.

Neither did:web nor did:webvh attests to the legal entity behind the domain. That is the responsibility of the Attribution layer (§4) — Verifiable Credentials issued by trusted third parties.

Trust evaluation of an attribution claim is a local decision made by each counterparty (P5 — Decentralized Trust & Attestation), not a network-level gatekeeping function.


---

## 3. DID Document Structure

The DID document is a JSON-LD document. For did:webvh it is the `state` of the latest valid entry in the version log at `/.well-known/did.jsonl` (§2.3); for did:web it is served directly at `/.well-known/did.json`. For an institutional participant (VASP) it declares, at minimum, the cryptographic keys and service entries this section specifies; other layers add further entries of their own using the same DID-document mechanics.

### 3.1 Required `@context` Entries

| Context URI | Key Type Enabled | Required When |
|---|---|---|
| `https://www.w3.org/ns/did/v1` | — (base DID Core vocabulary) | Always |
| `https://w3id.org/security/suites/ed25519-2020/v1` | Ed25519VerificationKey2020 | Any verificationMethod entry in the document uses Ed25519 |
| `https://w3id.org/security/suites/jws-2020/v1` | JsonWebKey2020 (P-256 only, §3.1.1) | Any verificationMethod or keyAgreement entry uses a P-256 key — for signing, or for ECDH key agreement |
| `https://w3id.org/security/suites/x25519-2020/v1` | X25519KeyAgreementKey2020 | Any keyAgreement entry uses X25519 |

#### 3.1.1 Cryptographic Agility

The Identity layer does not mandate a single signature or key-agreement algorithm. A verificationMethod entry MAY use Ed25519VerificationKey2020 (Ed25519) or JsonWebKey2020 with a P-256/secp256r1 key for signing. A keyAgreement entry MAY use X25519KeyAgreementKey2020 (X25519, ECDH-ES per RFC 8037) or JsonWebKey2020 with a P-256 curve (ECDH-ES per RFC 7518) for key agreement. Verifying and encrypting parties SHOULD support as many of these as practical; the signing or decrypting party — not the verifier — determines which supported key and algorithm is actually used for a given operation, simply by virtue of which key it publishes and signs or decrypts with.

**Algorithm allowlist.** The permitted algorithms are exactly these:

| Purpose | Permitted key types |
|---|---|
| Signing (`verificationMethod`, `assertionMethod`, `authentication`) | Ed25519 (Ed25519VerificationKey2020, or JsonWebKey2020 with an Ed25519 key); P-256 (JsonWebKey2020) |
| Key agreement (`keyAgreement`) | X25519 (X25519KeyAgreementKey2020); P-256 (JsonWebKey2020) |

A verifier MUST reject any signature made with a key of another type or curve, and an encrypting party MUST NOT use a keyAgreement key of another type or curve. Other curves that a JWK can represent are not permitted.

**Cryptosuite binding.** A proof's `cryptosuite` MUST match the type of the key its `verificationMethod` resolves to: `eddsa-jcs-2022` only with an Ed25519 key, and `ecdsa-jcs-2019` only with a P-256 key. A verifier MUST determine the key type from the DID document, never from the proof, and MUST reject a proof whose `cryptosuite` is unknown or does not match that key type.

**Public key validation.** Before using a public key, a verifier or encrypting party MUST validate it:

- A P-256 key MUST be a point on the curve, not the point at infinity, with coordinates of the correct length.
- An Ed25519 key MUST be a valid 32-byte point encoding.
- An X25519 key agreement MUST be rejected if it produces an all-zero shared secret (RFC 7748 §6.1).

A key that fails validation is treated as no key at all.

> **Note:** Post-quantum key agreement (e.g. ML-KEM) is anticipated but not specified here: no ratified JOSE/JWK or Data-Integrity representation for ML-KEM existed at the time of this draft. Once one is standardized, it will be added as a further optional keyAgreement key type under the same agility principle (see §8); participants and verifiers are not expected to implement it before then.

### 3.2 Key Inventory

This inventory covers only keys the Identity layer itself defines and governs. Other layers define and reuse additional keys — for example, a general-purpose message-signing key or encryption keys for a specific application protocol — using the same DID-document mechanics (§3.1–§3.3), and are out of scope for this table.

| Key | Type | Holder | Status | Purpose |
|---|---|---|---|---|
| Credential signing key (`assertionMethod`) | Ed25519VerificationKey2020 or JsonWebKey2020 (§3.1.1) | Credential issuer (e.g. a Local Operating Unit, or platform operator prior to LOU onboarding) | Conditional — MUST for credential issuers, §3.2.1 | Dedicated key credential issuers MUST use to sign verifiable credentials (§4.3), referenced from the DID document's `assertionMethod`; a proof signed by any key not referenced there MUST be rejected. |
| DID Management Key | Method-defined multikey (Ed25519 under did:webvh 1.0, which permits only the `eddsa-jcs-2022` cryptosuite for log entry proofs) | DID operator's DID Management System | Required | Declared via the did:webvh `updateKeys` parameter, not `verificationMethod`. Authorizes publication of new log entries — key rotation, service-entry changes, deactivation. See §3.2.2. |

#### 3.2.1 Credential Signing Key (`assertionMethod`) — Conditional (MUST for credential issuers)

A credential issuer (but not other participants) MUST declare a dedicated verification method (Ed25519VerificationKey2020 or JsonWebKey2020, §3.1.1) and reference it from the `assertionMethod` relationship of its DID document (§3.3). The key's `id` is not fixed by this specification; a verifier finds it through the `verificationMethod` of the credential's proof (§6.3).

A verifier MUST accept a credential proof (§4.3) only if the proof's `verificationMethod` resolves to a key referenced in the `assertionMethod` of the issuer's DID document. A proof signed by any other key MUST be rejected.

Every key under an issuer's `assertionMethod` can sign credentials, so the key MUST be used exclusively for signing verifiable credentials, and an issuer MUST NOT reference under `assertionMethod` any key it also uses for another purpose, such as message signing.

> **Note:** This exclusivity binds `assertionMethod` only. A participant's general-purpose signing key — the one it uses for presentations (§6.3) and for whatever other layers define — is referenced from `authentication`, and nothing here constrains it.

The rationale: a different threat model (compromise mints fraudulent legal-entity credentials — a trust-chain event — rather than a single fund loss or a redirected settlement) and a different cadence (low-frequency, high-value signing that tolerates stricter, more manual controls than high-frequency message signing) justify keeping this key separate from whatever a participant uses for other purposes.

```json
{
  "id": "did:webvh:lou.example#vc-key-1",
  "type": "Ed25519VerificationKey2020",
  "controller": "did:webvh:lou.example",
  "publicKeyMultibase": "<base58btc-Ed25519-public-key>"
}
```

and referenced from the DID document:

```json
{
  "assertionMethod": ["did:webvh:lou.example#vc-key-1"]
}
```

**Rotation and compromise.** A credential's proof is verified against the issuer's *current* DID document version (§3.3), so only keys currently referenced in `assertionMethod` are valid. There is no historical validity: a credential signed by a key that is no longer referenced is invalid.

- **Planned rotation.** The issuer adds the new key to `assertionMethod` and keeps the old key there while it migrates, that is, re-signs every outstanding credential and every BitstringStatusListCredential (§5.2) with the new key. Once migration is complete the issuer removes the old key. Until then both keys are valid. The issuer MUST NOT remove the old key before migration is complete, because every credential and status list still signed by it becomes invalid at that point.
- **Compromise.** If the credential signing key is believed to be compromised, the issuer replaces it at once: it removes the compromised key from `assertionMethod` with no overlap period and adds a new one. Every credential and status list signed by the old key then loses validity until it is re-issued under the new key. This is intended: the attacker cannot be allowed to keep a key that mints valid credentials, and the credentials it may have minted, with any `validFrom`, become invalid together with the legitimate ones.

#### 3.2.2 DID Management Key — Authorizing Document Updates

did:webvh's SCID self-certifies the genesis document (§2.2), but every version after that is only as trustworthy as whoever is authorized to sign it. Each entry in the version log (§2.3) carries a proof from the key(s) declared in the method's `updateKeys` parameter — the DID Management Key — not from any `verificationMethod` entry in the resolved DID document itself. Whoever holds this key can rotate any `verificationMethod` or `keyAgreement` entry in the document, add or remove service entries, or deactivate the DID entirely.

For did:web: there is no `updateKeys` parameter or log entry to sign. A did:web document is simply replaced at the server; "who can rotate a key" reduces entirely to "who can write to `/.well-known/did.json`." In did:webvh, the DID Management Key authorizes any document changes.

> **Note:** Because of this authority, the DID Management Key is the single highest-leverage credential in the Identity layer: its compromise is equivalent to compromising every other rotatable key in the document at once, since it can simply replace them. Implementations MUST treat the DID Management System — the component authorized to construct and sign new log entries — as at least as sensitive as any individual key it manages.

Illustrative shape of a did:webvh log entry (exact parameter encoding follows the did:webvh method specification):

```json
{
  "versionId": "2-<entryHash>",
  "versionTime": "2026-01-01T00:00:00Z",
  "parameters": {
    "updateKeys": ["<did-management-key-multibase>"]
  },
  "state": { "...": "the resolved DID document for this version" },
  "proof": [{
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "<did-management-key-reference>",
    "proofPurpose": "assertionMethod",
    "proofValue": "z<base58btc-signature>"
  }]
}
```

### 3.3 `authentication` and `assertionMethod`

A key reference is valid for the `authentication` or `assertionMethod` purpose only while it is present in the current DID document version. Removing a reference in a later version revokes that purpose for the key going forward, without deleting the underlying key material from the version-log history (§2.3).

### 3.4 `portability`

Portability of a DID document refers to an update of the domain while preserving the SCID and document version history. Portability is indicated by setting the `portable` parameter in the genesis version of the did document. Note that credentials are bound to the full DID, not just the SCID part of the DID, thus moving the domain invalidates all credentials bound to the DID, while enabling the flag introduces new attack vectors. Therefore we recommend participants SHOULD NOT set the `portable` flag in their genesis document.

---

## 4. Verifiable Credentials — General Framework & the LEI/LOU Instance

This section is in three parts. §4.1–§4.5 define a general Verifiable Credential framework that applies to any credential type a Credential Issuer might issue. §4.6–§4.11 specify LEI/LOU credentials as the first instance of that framework — a template for how a future credential type would specify itself. §4.12–§4.17 specify the hosting credential, the second instance.

### 4.1 Attribution Layer Overview

did:webvh establishes cryptographic identity — proof of control of a domain — but does not attest to the legal entity behind it. Legal entity attribution is provided by Credential Issuers: trusted third parties that digitally sign claims about network participants, conforming to the W3C Verifiable Credentials Data Model v2.0.

### 4.2 Credential Issuers

Credential issuers are entities that:

- Hold their own did:webvh.
- Issue W3C Verifiable Credentials signed with their own credential signing key, referenced from their `assertionMethod` (§3.2.1).
- Are trusted by network participants according to each participant's own local policy (§6).

### 4.3 Generic Credential Structure

Every OTL credential type, whatever it attests to, shares this outer shape. A specific credential type's own specification (e.g. §4.8 for OtlLeiCredential) fixes some of these fields to particular values and defines its own `credentialSubject` payload.

| Field | Type | Description |
|---|---|---|
| `@context` | `string[]` | MUST include `"https://www.w3.org/ns/credentials/v2"`; MAY include additional type-specific contexts. |
| `id` | `string` | Credential URI — `urn:uuid:{uuid}` |
| `type` | `string[]` | MUST include `"VerifiableCredential"` as the first element. Subsequent elements identify the specific credential type(s) (e.g. `"OtlLeiCredential"`) — this is how a parser determines what it is looking at and whether to process or skip it (§4.4). |
| `issuer` | `string` | did:webvh of the issuing Credential Issuer (§4.2). Self-issued credentials (issuer equal to `credentialSubject.id`) are invalid unless a specific credential type's own rules explicitly allow self-issuance. |
| `validFrom` | `string` | ISO 8601 issuance timestamp |
| `validUntil` | `string` | ISO 8601 timestamp after which the credential is expired. The general rule is that this MAY be present; a specific credential type's own specification MAY strengthen this to MUST — OtlLeiCredential does (§4.8). |
| `credentialSubject` | `object` | Type-specific payload. The one field every credential type shares is `credentialSubject.id`, the did:webvh of the subject. |
| `credentialStatus` | `BitstringStatusListEntry[]` | Revocation pointer. The general rule (§5) is that this MAY be present; a specific credential type's own specification MAY strengthen this to MUST — OtlLeiCredential does (§4.8). |
| `proof` | `CredentialProof` | Ed25519 or P-256 DataIntegrityProof signed by a key referenced in the issuer's `assertionMethod` (§3.2.1, §6.3). |

### 4.4 Verifiable Presentation — `whois` Endpoint (General)

Participants publish their credentials at `/.well-known/whois.vp`, located via the `#whois` service. For did:webvh this is the method's implicit `#whois` service (path `/whois`); a did:web participant MUST declare an explicit `#whois` service entry in its DID document. This serves a W3C Verifiable Presentation (VP) containing every credential the participant chooses to disclose publicly — of any type, potentially mixed.

> **Note:** Because `verifiableCredential` may hold a mix of credential types, a parser MUST inspect each entry's own `type` array (§4.3) before doing anything else with it — this is what lets it immediately tell a OtlLeiCredential apart from any other type it may encounter and decide whether that entry is relevant, without needing to attempt full parsing of a type it does not recognize. Unrecognized types MUST be skipped gracefully, not treated as an error.

| Field | Type | Description |
|---|---|---|
| `@context` | `string[]` | `["https://www.w3.org/ns/credentials/v2"]` |
| `type` | `string[]` | `["VerifiablePresentation"]` |
| `holder` | `string` | did:webvh of the participant that assembled and signed this VP |
| `verifiableCredential` | `Credential[]` | Array of W3C VCs of potentially mixed types — each carries its own proof signed by its own issuer |
| `proof` | `CredentialProof` | VP proof, signed by the holder's own signing key — separate from each VC's own proof. Which key a holder uses when it is not itself acting as a credential issuer is defined by whichever other layer specifies that key, not by this specification. |

### 4.5 Credential Lifecycle (General)

Each credential type's issuing authority defines its own renewal cadence and the consequence of letting it lapse — for example, LEI registrations must be renewed annually, and the corresponding OtlLeiCredential SHOULD be re-issued on renewal (§4.9, `registration.nextRenewalDate`). As a general rule, verifiers SHOULD treat a credential whose underlying registration has lapsed as equivalent to no credential. A verifier MUST reject a credential whose `validUntil` has passed, whether or not it has been revoked (§5.3). Independent of expiry, credentials may be revoked at any time via the issuer's Bitstring Status List (§5). Trust decisions remain at the verifier's discretion even for a valid, non-revoked credential.

---

### LEI / LOU: the first instance of the general framework

### 4.6 LOU Trust Anchors

Local Operating Units (LOUs) — the accredited entities within the global LEI system that issue Legal Entity Identifiers — are the trust anchors for OtlLeiCredential. There is no protocol-defined universal root: each participant's trust perimeter (§6.1) MUST include the specific LOU DIDs it chooses to trust, exactly as it would for any other credential issuer (§4.2). Trusting a given LOU is a local decision, not a network-wide default.

### 4.7 Supported Credential Types

| Credential Type | Issued By | Description |
|---|---|---|
| OtlLeiCredential (GLEIF Level 1) | Local Operating Units (LOUs) | Full GLEIF Level 1 dataset for the credential subject — entity name, addresses, jurisdiction, and registration data. |
| OtlHostingCredential | Hosting providers (§4.12) | Identifies the provider that hosts the credential subject's DID, names the subject by the common name the provider knows it by, and optionally lists the watchers for that DID (§4.14). |

### 4.8 OtlLeiCredential — Outer Fields

Following the generic Credential structure (§4.3), OtlLeiCredential fixes these fields:

| Field | Type | Description |
|---|---|---|
| `type` | `string[]` | Always `["VerifiableCredential", "OtlLeiCredential"]` |
| `issuer` | `string` | DID of the issuing Local Operating Unit (LOU). Self-issued LEI credentials are not valid. |
| `validUntil` | `string` | MUST be present (stricter than the general MAY in §4.3) and MUST NOT be later than `credentialSubject.registration.nextRenewalDate` (§4.9). |
| `credentialStatus` | `BitstringStatusListEntry[]` | MUST be present (stricter than the general MAY in §4.3); validators MUST check before trusting (§5). |
| `proof` | `CredentialProof` | Ed25519 or P-256 DataIntegrityProof signed by a key referenced in the issuer's `assertionMethod` (§6.3). |

### 4.9 OtlLeiCredential — `credentialSubject` Fields

| Field | Req | Description |
|---|---|---|
| `id` | ✓ | did:webvh or did:web of the credential subject |
| `lei` | ✓ | ISO 17442 20-character LEI code |
| `entity.legalName` | ✓ | Official legal name as registered |
| `entity.otherNames` | — | Other registered or transliterated names |
| `entity.legalAddress` | ✓ | Registered legal address |
| `entity.headquartersAddress` | ✓ | Principal place of business |
| `entity.registeredAt.id` | — | GLEIF business registry identifier code (e.g. RA000563) |
| `entity.registeredAs` | — | Registration number within the business registry |
| `entity.jurisdiction` | ✓ | ISO 3166-1 alpha-2 or ISO 3166-2 jurisdiction of formation |
| `entity.legalForm.id` | — | ISO 20275 Entity Legal Form (ELF) code |
| `entity.category` | — | `GENERAL` \| `SOLE_PROPRIETOR` \| `BRANCH` \| `FUND` \| `SUBFUND` \| `FUNDFAMILY` \| `INTERNATIONAL_ORGANIZATION` |
| `registration.initialRegistrationDate` | ✓ | ISO 8601 date the LEI was first issued |
| `registration.nextRenewalDate` | ✓ | ISO 8601 date the LEI registration expires — when elapsed the issuing LOU MUST revoke the credential |
| `registration.managingLou` | ✓ | LEI of the Local Operating Unit that manages this record |
| `registration.corroborationLevel` | ✓ | `FULLY_CORROBORATED` \| `PARTIALLY_CORROBORATED` \| `PENDING` |

> **Note:** Address type: `{ addressLines: string[], city: string, region?: string, country: string, postalCode?: string }` — `region` follows ISO 3166-2 (e.g. DE-HE); `country` follows ISO 3166-1 alpha-2.

### 4.10 OtlLeiCredential Example

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "urn:uuid:3d4e5f6a-7b8c-9d0e-1f2a-3b4c5d6e7f8a",
  "type": ["VerifiableCredential", "OtlLeiCredential"],
  "issuer": "did:webvh:lou.example.org",
  "validFrom": "2024-01-01T00:00:00Z",
  "validUntil": "2025-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:webvh:participant.example",
    "lei": "5493001KJTIIGC8Y1R12",
    "entity": { "legalName": "Example Participant GmbH", "jurisdiction": "DE", ... },
    "registration": {
      "initialRegistrationDate": "2012-06-06T00:00:00Z",
      "nextRenewalDate": "2025-01-01T00:00:00Z",
      "managingLou": "529900T8BM49AURSDO55",
      "corroborationLevel": "FULLY_CORROBORATED"
    }
  },
  "credentialStatus": [{
    "id": "https://lou.example.org/.well-known/status-lists/1#94567",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://lou.example.org/.well-known/status-lists/1"
  }],
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:webvh:lou.example.org#vc-key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z<base58btc-64-byte-Ed25519-signature>"
  }
}
```

### 4.11 LEI Credential Trust Chain

OtlLeiCredential's trust chain is a single hop — LOU → VASP — and this is the concrete instance of the general recursive-validation-to-a-root-of-trust pattern defined in §5.3. The LOU itself is the root: a verifier reaches it by verifying the OtlLeiCredential's proof against the issuing LOU's DID document and confirming that LOU is in its own locally configured trust perimeter (§4.6, §6.1) — there is no further chain to walk.

Because there is no protocol-defined universal root, a verifier's confidence in a given OtlLeiCredential is exactly as strong as its own decision to trust that LOU (§4.6) — onboarding a new LOU is a local trust-perimeter update, not a protocol-level event.

---

### Hosting: the second instance of the general framework

### 4.12 Hosting Providers

§2 allows a participant to delegate some or all of its protocol participation to a contracted software provider. A hosting provider is an entity that operates a participant's DID on the participant's behalf. OtlHostingCredential lets the provider state publicly that it hosts a given DID, so that a verifier can see who operates the DID and factor the provider's security into its trust decision.

**Meaning of "hosts".** By issuing an OtlHostingCredential, the provider asserts that:

1. it serves the DID document, and for did:webvh the version log, on a domain it controls;
2. it controls the DID Management Key (§3.2.2) — for did:webvh the `updateKeys` — and so is the party able to publish new DID document versions; and
3. for every other key in the DID document, it either controls the key itself or has performed due diligence that the key is controlled by the participant.

The provider MUST NOT issue the credential unless all three hold, and MUST revoke it as soon as any ceases to hold (§4.17). A provider that only serves a DID, without controlling its DID Management Key, does not host it in this sense.

A hosting provider is a Credential Issuer (§4.2): it holds its own did:webvh and signs with its own credential signing key (§3.2.1). As with LOUs (§4.6) there is no protocol-defined root: whether to trust a provider is a local decision by each verifier, and its DID MUST be in the verifier's trust perimeter (§6.1) for OtlHostingCredential specifically. Trust in a provider for OtlHostingCredential does not extend to any other credential type it may issue, and a verifier SHOULD accept an OtlHostingCredential from a provider only for subject DIDs on the hosting domains that provider is responsible for.

### 4.13 OtlHostingCredential — Outer Fields

Following the generic Credential structure (§4.3), OtlHostingCredential fixes these fields:

| Field | Type | Description |
|---|---|---|
| `type` | `string[]` | Always `["VerifiableCredential", "OtlHostingCredential"]` |
| `issuer` | `string` | DID of the hosting provider. Self-issued hosting credentials are not valid. |
| `credentialStatus` | `BitstringStatusListEntry[]` | MUST be present (stricter than the general MAY in §4.3); validators MUST check before trusting (§5). The provider revokes the credential through its status list when it no longer vouches for the subject DID (§4.17). |
| `proof` | `CredentialProof` | Ed25519 or P-256 DataIntegrityProof signed by a key referenced in the issuer's `assertionMethod` (§6.3). |

### 4.14 OtlHostingCredential — `credentialSubject` Fields

| Field | Req | Description |
|---|---|---|
| `id` | ✓ | did:webvh or did:web of the hosted participant. Bound to the full DID, not only the SCID (§3.4). |
| `commonName` | ✓ | The common name of the hosted participant — the name the provider knows it by, which is not necessarily its legal name. 1 to 128 characters after trimming leading and trailing whitespace. MUST NOT contain control characters or Unicode bidirectional overrides. |
| `watchers` | — | Array of HTTPS URLs of did:webvh watcher endpoints for the subject DID, as defined by the did:webvh 1.0 `watchers` parameter. MUST be omitted when `id` is a did:web, since there is no version log to watch. |

> **Note:** `commonName` is a display label, not an identifier and not an attestation of legal identity. It is the provider's own name for the participant, chosen so that a person recognises who the DID belongs to — a trading name, a brand, or a product name — and it is corroborated against no registry. The legal name is carried by `entity.legalName` in the participant's own OtlLeiCredential (§4.9), which is authoritative where the two differ.

> **Note:** A verifier MUST NOT use `commonName` to decide whether to trust a DID, to match a participant against an allow, deny or sanctions list, or to tell two participants apart; the DID is the identifier. Because the issuer chooses the value and it will be shown to people, a verifier that displays it MUST render it as untrusted text and SHOULD show it together with the subject DID and the issuing provider, so that a provider cannot pass a participant off as a better-known entity simply by naming it one.

> **Note:** The credential carries no provider name or LEI. The provider is the `issuer`, and its legal identity is established the usual way, by the provider's own OtlLeiCredential (§4.8) in its `whois` VP.

> **Note:** The watcher list is deliberately issued by the hosting provider and not carried only in the DID's own log (§2.4). Replacing the list requires the provider to issue a new credential and revoke the previous one.

### 4.15 OtlHostingCredential Example

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "urn:uuid:8a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d",
  "type": ["VerifiableCredential", "OtlHostingCredential"],
  "issuer": "did:webvh:hosting.example.org",
  "validFrom": "2026-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:webvh:participant.example.org",
    "commonName": "Example Participant",
    "watchers": [
      "https://watcher-a.example.net",
      "https://watcher-b.example.com"
    ]
  },
  "credentialStatus": [{
    "id": "https://hosting.example.org/.well-known/status-lists/1#41872",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "41872",
    "statusListCredential": "https://hosting.example.org/.well-known/status-lists/1"
  }],
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:webvh:hosting.example.org#vc-key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z<base58btc-64-byte-Ed25519-signature>"
  }
}
```

### 4.16 OtlHostingCredential Validation

The trust chain is a single hop — hosting provider → hosted participant — and follows the general validation chain (§5.3). A verifier MUST perform these steps in order, before any network access beyond obtaining the credential itself:

1. Check that `issuer` is in the verifier's trust perimeter for credential type OtlHostingCredential (§4.12, §6.1), and that the subject DID falls within the hosting domains the issuer is trusted for, where the verifier has configured such a scope.
2. Apply the binding checks (§5.3), including that `credentialSubject.id` equals the DID being resolved or authenticated.
3. Verify the credential's proof against the issuer's DID document.
4. Check revocation via `credentialStatus` (§5.3, step 4).
5. If the credential is valid, add `credentialSubject.watchers` to the watcher set (§2.4).

If any step fails, the verifier MUST treat the OtlHostingCredential as invalid, MUST NOT use its watchers, and MUST NOT display its `commonName`.

### 4.17 OtlHostingCredential Lifecycle

- **Watcher change.** The provider issues a new credential with the new list and revokes the previous one.
- **Hostile takeover.** If the DID is taken over (§5.4), the provider revokes the credential. A verifier that requires the attestation, or that has previously seen it (§4.16), then stops trusting the DID and stops using the credential's watchers; the attacker cannot undo this, since it controls neither the provider's status list nor its credential signing key.
- **Offboarding or domain move.** When a participant leaves the provider, or the DID is moved to another domain (§3.4), the provider MUST revoke the credential.
- **Loss of control.** If the provider loses control of the DID Management Key, for example through rotation of `updateKeys` to a key it does not hold, it MUST revoke the credential (§4.12).

---

## 5. Revocation — W3C Bitstring Status List

OTL uses the W3C Bitstring Status List v1.0 specification for credential revocation. Every issued credential MAY include a `credentialStatus` field; if present, validators MUST check it before trusting a credential. A specific credential type's own specification MAY strengthen this MAY to a MUST — OtlLeiCredential does (§4.8).

### 5.1 `credentialStatus` Entry (in Issued VCs)

| Field | Required | Description |
|---|---|---|
| `id` | Optional | URL identifying this specific entry. MUST NOT be the `statusListCredential` URL itself. Convention: `{statusListCredential}#{index}`. |
| `type` | Required | Always `"BitstringStatusListEntry"`. |
| `statusPurpose` | Required | Always `"revocation"`. |
| `statusListIndex` | Required | The credential's position in the bitstring — decimal integer ≥ 0, as a string. SHOULD be assigned randomly to prevent correlation. |
| `statusListCredential` | Required | URL where the BitstringStatusListCredential is served. |
| `statusSize` | Optional | Number of bits per entry; defaults to 1. For revocation, always 1. |

### 5.2 BitstringStatusListCredential

Credential issuers publish a signed BitstringStatusListCredential at `GET /.well-known/status-lists/{listId}`. This is itself a W3C VC, signed by a key referenced in the issuer's `assertionMethod`. The `@context` is `https://www.w3.org/ns/credentials/v2` only — no separate status context URL is needed.

| Field | Required | Description |
|---|---|---|
| `id` | Optional | Should match the `statusListCredential` URL |
| `type` | Required | `["VerifiableCredential", "BitstringStatusListCredential"]` |
| `issuer` | Required | did:webvh of the credential issuer. MUST equal the `issuer` of every credential whose `credentialStatus` refers to this list (see Issuer binding below). |
| `validFrom` | Required | ISO 8601 timestamp of the last update. Each newly published version of a list MUST carry a later `validFrom` than the version it replaces. |
| `validUntil` | Required | ISO 8601 timestamp after which this version of the list MUST NOT be relied on. The issuer publishes a new version before this time. |
| `credentialSubject.type` | Required | Always `"BitstringStatusList"` |
| `credentialSubject.statusPurpose` | Required | Always `"revocation"` |
| `credentialSubject.encodedList` | Required | Multibase base64url-encoded, GZIP-compressed bitstring (prefix `u`). Minimum 131,072 entries. |
| `credentialSubject.ttl` | Optional | Suggested cache TTL in milliseconds; issuers SHOULD align HTTP `Cache-Control` with this value |
| `proof` | Required | DataIntegrityProof signed by a key referenced in the issuer's `assertionMethod` |

**Issuer binding.** Before reading a bit from a list a verifier MUST check that:

- the list's `issuer` equals the `issuer` of the credential being checked; and
- the list's proof verifies, and its `verificationMethod` is a key referenced in the `assertionMethod` of that same issuer's DID document (§3.2.1).

A list signed by any other DID is invalid, and the credential is treated as having an unreachable status list (§5.3, §6.2).

**Freshness and rollback.** A status list is signed, so an older version in which a since-revoked credential's bit is still 0 stays validly signed. A verifier MUST therefore apply these rules to every status list before reading a bit from it:

- It MUST reject a list whose `validUntil` has passed.
- It MUST reject a list whose `validFrom` is older than the maximum age the verifier has configured. The verifier chooses this age according to the risk of the interaction.
- It MUST NOT accept a list whose `validFrom` is earlier than that of a version of the same list (same `statusListCredential` URL) it has already accepted. The verifier therefore keeps the latest accepted `validFrom` per list.
- A cache, including a proxy used to prevent issuer tracking (§5.3), is bound by the same rules: `ttl` never extends a list's validity beyond `validUntil` or the verifier's maximum age.

A list that fails any of these is treated like an unreachable list (§5.3, §6.2).

#### 5.2.1 Example

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "https://lou.example.org/.well-known/status-lists/1",
  "type": ["VerifiableCredential", "BitstringStatusListCredential"],
  "issuer": "did:webvh:lou.example.org",
  "validFrom": "2024-01-01T00:00:00Z",
  "validUntil": "2024-01-01T01:00:00Z",
  "credentialSubject": {
    "id": "https://lou.example.org/.well-known/status-lists/1#list",
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA",
    "ttl": 300000
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:webvh:lou.example.org#vc-key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z<base58btc-Ed25519-signature>"
  }
}
```

### 5.3 Counterparty Validation — General Validation Chain

Every OTL credential type's validation chain shares the same characteristic: starting from a presented credential, recursively verify proof and revocation status one link at a time, walking up the issuance chain, until a root of trust is reached — a locally configured trusted issuer (§6.1). If any link fails — an untrusted issuer, a bad proof, a revoked credential, or an unreachable status list — the whole chain is invalid; a chain that terminates successfully at a recognized root is valid.

Each credential type's own specification defines how many links its chain has and what the terminal root looks like. The worked example below is OtlLeiCredential's chain (§4.11), which has exactly one link, terminating directly at the issuing LOU as a locally trusted issuer.

**Trust perimeter first (all credential types).** The `issuer` DID, status list URLs and other links in a presented credential are chosen by whoever presents it. A validator MUST therefore check the credential's `issuer` DID and `type` against its trust perimeter (§6.1) before it makes any network request on the credential's behalf.

**Binding checks (all credential types).** Credentials are public, so a valid proof and a valid status entry do not show that the credential belongs to the participant presenting it. Before relying on any credential, a validator MUST also check that:

1. `credentialSubject.id` equals the `holder` of the presenting VP and equals the DID authenticated in the interaction. A credential copied from another participant's `whois` VP fails here.
2. The VP's proof verifies against the holder's DID document (§6.3).
3. `type` contains the credential type the validator expects for this use (§4.3).
4. `validFrom` is not in the future, and `validUntil`, where present, has not passed. A credential of a type that requires `validUntil` (§4.3) is invalid without it. This check is independent of revocation status.
5. `issuer` is a did:webvh (§4.2).
6. The issuer is not the subject. 

A credential that fails any binding check is invalid, and §6.2 applies.

**Worked example: OtlLeiCredential**

When validating a counterparty's OtlLeiCredential, validators MUST perform the following steps in order:

1. Confirm the issuing LOU's DID is present in the validator's own configured trust perimeter for credential type OtlLeiCredential.
2. Apply the binding checks above.
3. Verify the OtlLeiCredential's cryptographic proof against the issuer's (LOU's) DID document.
4. Check revocation of the OtlLeiCredential: locate `credentialStatus`, fetch the `statusListCredential` URL, verify the status list credential's own proof and its binding to the credential's issuer (§5.2), apply the freshness and rollback rules (§5.2), decode the bitstring (strip Multibase prefix `u`, base64url-decode, GZIP-decompress), and read the bit at `statusListIndex`.
5. If any step fails, or the LOU is not in the trust perimeter, or a status list cannot be fetched, treat the OtlLeiCredential as invalid.

> **Note:** Verifiers SHOULD cache status list responses (respecting `ttl`) and SHOULD use a proxy to prevent issuers from tracking individual lookups.

### 5.4 Trust Anchor and Identity Compromise Recovery

Revocation via the Bitstring Status List (§5.1–§5.3) handles the routine case: an issuer decides a specific credential should no longer be trusted. Two more severe scenarios sit outside that mechanism, because the compromise is at the anchor or identity level rather than the individual-credential level.

**Trust anchor compromise.**

If a trust anchor itself, a locally configured trusted issuer (§6.1), including an LOU trust anchor (§4.6) is believed to be compromised, revocation lists are insufficient: an attacker controlling the anchor's own signing key can simply keep issuing valid-looking, non-revoked credentials. Recovery is therefore out-of-band: the incident MUST be propagated over a second channel (not specified by this protocol) so affected participants can independently decide to remove that anchor from their local trust-perimeter configuration (§6.1). This specification defines the effect, removing an anchor from the local trust perimeter, but not the incident-notification mechanism itself.

**Individual DID compromise.**

If a participant's own DID is compromised, a domain hijack, or (for did:webvh) a leaked DID Management Key (§3.2.2), on-protocol signals are unreliable by definition: an attacker in control of the domain or DID Management Key can rotate every rotatable key in the document, and for did:webvh can make the compromise look like ordinary key rotation. For did:web the same domain hijack requires no such disguise, since there is no rotation history to imitate. Recovery again requires a second channel: the legitimate original operator, having lost control of the DID, reaches out directly to each of its credential issuers (§4.2) out of band and requests that they either revoke the credentials they issued to the compromised DID, or reissue equivalent credentials to a newly established replacement DID.

Where the DID is hosted by a provider that issued an OtlHostingCredential (§4.12), the provider SHOULD revoke it as part of this response. Revocation is the signal that verifiers can act on without any out-of-band notice: they stop using the credential's watchers and, where they rely on the hosting attestation, stop trusting the DID (§4.16, §4.17).

---

## 6. Trust Anchor Management

### 6.1 Trust Perimeter

Each participant independently defines their own trust perimeter — the set of claim types and the specific trusted issuer DIDs they choose to recognize. A trust perimeter entry is a pair of an issuer DID and a credential type: trusting an issuer for one credential type does not extend to any other type it may issue. Participants SHOULD maintain a configured list of such pairs and verify a credential's `issuer` and `type` against that list before relying on it. A participant may require counterparties to hold a specific credential type (e.g. a valid LEI credential from a GLEIF-accredited issuer) and validate further criteria (e.g. counterparty being in a certain jurisdiction) before engaging in protocol interaction.

A participant MAY also explicitly whitelist or blacklist individual DIDs as trusted/untrusted counterparties, independent of which issuer vouches for them.

When a counterparty falls outside the trust perimeter, the participant sends `otl:message/abort` to terminate the interaction and signals the reason (see reference-messages: Abort, code `risk-profile-rejected` | `trust-not-established`).

> **Note:** LOU trust anchors for OtlLeiCredential (§4.6) are configured exactly this way, like any other credential issuer — there is no protocol-defined exception to the locally configured model.

### 6.2 Trust Violation Handling

Any failure in a validation chain (§5.3) — an untrusted issuer, a failed proof, a revoked credential at any link, or an unreachable status list — MUST cause the validator to treat the credential as invalid and, where applicable to an in-progress flow, to abort per §6.1.

### 6.3 CredentialProof (DataIntegrityProof)

All credential and presentation proofs in the Identity layer use the W3C DataIntegrityProof format — an Ed25519 or P-256 signature (§3.1.1) produced by the `eddsa-jcs-2022` or `ecdsa-jcs-2019` cryptosuite.

**Signature input.** The signature is computed over the concatenation of two SHA-256 digests, as those cryptosuites define:

```
hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDocument))
```

where `unsecuredDocument` is the document with the `proof` field removed, and `proofConfig` is the proof block without `proofValue`, carrying the document's `@context`. Both are canonicalized per RFC 8785.

> **Note:** The proof block MUST be covered by the signature, which is why it is hashed as `proofConfig` rather than discarded along with `proofValue`. A construction that signs only the document body leaves `proofPurpose`, `created`, `domain` and `challenge` unauthenticated, so a signature can be lifted onto a contradictory proof block and still verify — defeating purpose separation, freshness, audience binding and replay protection.

| Field | Description |
|---|---|
| `type` | Always `"DataIntegrityProof"` |
| `cryptosuite` | `eddsa-jcs-2022` for an Ed25519 signing key, or `ecdsa-jcs-2019` for a P-256 (JsonWebKey2020) signing key — whichever the signer's key type is (§3.1.1). A verifier MUST reject a proof whose cryptosuite does not match the key type, or is neither of these. |
| `created` | ISO 8601 creation timestamp |
| `verificationMethod` | Key reference: on a VC, a key reference under the issuer's DID that is listed in the issuer's `assertionMethod` (§3.2.1) — the Identity layer mandates a dedicated key for this purpose. On a VP, the key reference is under the holder's DID (the VP `holder` field) and MUST be listed in the holder's `authentication`. Which signing key the holder uses for presentations is defined by whichever other layer specifies the holder's general-purpose signing key, not by this specification. |
| `proofPurpose` | `"assertionMethod"` on a VC; `"authentication"` on a VP. A verifier MUST reject a proof whose `proofPurpose` is not the one its document type requires, and MUST require the key to be referenced from the matching relationship in the signer's DID document. |
| `proofValue` | Multibase base58btc string (`z`-prefix) of the raw signature — 64 bytes for Ed25519. |

---

## 7. Anonymous Participants

Anonymous participants interact with the network without a DID of their own. They can fetch and verify signed public data and notify a beneficiary of payment execution, but cannot send authenticated DIDComm messages or be addressed/reached by the network.

### 7.1 Capability Matrix

| Capability | Anonymous | Network Participant (did:webvh or did:web) |
|---|---|---|
| Verify authenticated data objects | ✓ | ✓ |
| Resolve DID documents & counterparty identity | ✓ | ✓ |
| Create authenticated data objects | ✗ | ✓ |

### 7.2 Examples

**Browser dApp / light client** — a web application that reads public payment data and submits transactions via a connected wallet. The dApp itself has no identity; whatever wallet it drives may or may not hold a DID independently of the dApp.

Even without an identity of its own, such a dApp can still benefit from a verifiable payments object attached to the payment details it resolves: it can treat the proof as an opaque pass/fail signal — attested or not — surfaced by its wallet or provider, without itself implementing DID resolution.

---

## Appendix A: Reference to Existing Standards

External standards, specifications, and registries this document builds on, collected here for quick reference.

| Standard / Specification | Publisher | Used For | § |
|---|---|---|---|
| did:webvh method spec | DIF community | Core DID method: SCID, genesis doc, version log, `updateKeys` | §2, 3.2 |
| did:web method spec | W3C CCG | Alternate DID method: plain domain-hosted document, no version history | §2, 3.2 |
| DID Core v1.0 | W3C | Base DID document vocabulary and resolution | §3.1 |
| Verifiable Credentials Data Model v2.0 | W3C | Credential / Presentation JSON-LD shape | §4 |
| Bitstring Status List v1.0 | W3C | Credential revocation mechanism | §5 |
| VC Data Integrity 1.0 | W3C | DataIntegrityProof format; `eddsa-jcs-2022` / `ecdsa-jcs-2019` cryptosuites | §6.3 |
| Ed25519 Signature 2020, JWS 2020, X25519 Key Agreement 2020 (security vocab.) | W3C | Verification method types — Ed25519VerificationKey2020, JsonWebKey2020, X25519KeyAgreementKey2020 | §3.1 |
| RFC 2119 | IETF | Normative keywords (MUST / SHOULD / MAY) | §1.1 |
| RFC 7518, 8037, 8785 | IETF | JWA / CFRG algorithms and JSON Canonicalization behind the Data Integrity cryptosuites | §3.1.1 |
| ISO 17442, 20275, 3166-1/-2 | ISO | LEI code, Entity Legal Form code, country / subdivision codes | §4.9 |

> **Note:** Where this document's field tables conflict with a cited standard's own text, the standard is authoritative; this document only describes how OTL profiles or constrains it.