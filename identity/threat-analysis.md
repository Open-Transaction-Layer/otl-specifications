# OTL Identity Layer — Security and Threat Analysis

- **Status:** Draft for review
- **Scope:** OTL Identity layer (Layer 1): did:webvh / did:web identifiers, W3C Verifiable Credentials, Bitstring Status List revocation, trust anchor management
- **Based on:** OTL Identity Layer Technical Specification v0.6 and the did:webvh DID Method Specification v1.0
- **Date:** November 2026

---

## 1. Purpose and Scope

This document identifies attack vectors against the OTL Identity layer and proposes mitigations. It has two audiences:

1. **Specification partners**, for whom Sections 5.1 to 5.6 and Section 8 describe protocol-level threats and the status of the corresponding normative changes, which apply to every OTL implementation.
2. **Implementation partners**, who build, operate, or host OTL identities, credential issuers, and verifiers. Sections 5.7, 6 and 7 cover threats that arise in deployments (in particular hosted deployments, where one operator runs identities on behalf of many participants) and give recommendations for infrastructure and key management.

Out of scope are the Session, Transport, Messaging, and Application layers, except where an Identity-layer weakness propagates into them (for example, verifiable address validation). Generic web, cloud, and application security controls that are not specific to OTL are also out of scope.

Section references of the form "§x.y" refer to the OTL Identity Layer Specification unless stated otherwise.

---

## 2. System Overview

### 2.1 Components

| Component | Description |
|---|---|
| Participant DID | did:webvh (strongly recommended) or did:web identifier hosted on the participant's domain. For did:webvh, the DID document is derived from an append-only, hash-chained log (`did.jsonl`) whose genesis entry is bound to the identifier by the SCID. |
| DID Management Key | Key(s) listed in the did:webvh `updateKeys` parameter. Signs every log entry and can change any key, service, or parameter in the DID. |
| Witnesses | did:key identities whose threshold of proofs (`did-witness.json`) is required before a log entry is valid. Defined by did:webvh; not currently profiled by OTL. |
| Watchers | Services that retrieve and cache every log version, and in some profiles also sign their observations. The watcher set a verifier uses is defined in §2.4. |
| Credential Issuer | Entity holding a did:webvh and a dedicated credential signing key, referenced from its `assertionMethod`, that signs VCs and status lists (§3.2.1, §4.2). |
| OtlLeiCredential | VC binding a DID to an ISO 17442 LEI and GLEIF Level 1 data. Issued by an LOU (§4.8) or, prior to LOU onboarding, by a platform operator (§3.2). |
| OtlHostingCredential | VC issued by a hosting provider stating that it hosts a given DID, naming the participant by its common name and optionally listing the DID's watchers (§4.12 to §4.17). |
| whois VP | Verifiable Presentation published by the holder, containing the credentials it chooses to disclose (§4.4). |
| Bitstring Status List | Issuer-signed, GZIP-compressed bitstring credential used for revocation (§5). |
| Trust perimeter | Each verifier's local configuration of trusted (issuer DID, credential type) pairs and allow/deny lists (§6.1). |

### 2.2 Assets

| Asset | Why it matters |
|---|---|
| DID Management Keys (current and past) | Control of the identity; see Appendix A for what each key class enables. |
| Credential issuance keys | Control of legal-entity attribution for every subject the issuer vouches for, and of revocation. |
| Application data signing keys (for example keys signing payment addresses) | Directly attest payment-relevant data; compromise can lead to misdirected funds. |
| DID log and witness file integrity | Basis for every key lookup. |
| Hosting infrastructure (DNS, TLS certificates, web servers) | Controls what verifiers retrieve. |
| Trust perimeter configuration | Root of every trust decision a verifier makes. |
| Status list freshness | Determines whether revocations take effect. |
| Resolver and verifier infrastructure | Fetches attacker-supplied URLs and sits close to transaction systems. |
| Metadata about who resolves whom | Reveals commercial relationships and payment intent. |

---

## 3. Trust Assumptions

1. Cryptographic primitives (Ed25519, P-256, SHA-256, X25519) are secure when correctly implemented and parameter-validated.
2. TLS and the WebPKI authenticate hosts, subject to the known limits of domain-validated certificate issuance.
3. Domain control establishes cryptographic identity only; it says nothing about the legal entity (§2.5).
4. Legal-entity attribution is only as strong as the issuer's off-protocol verification process (LEI data is public; the DID-to-LEI binding is an operational decision).
5. Trust decisions are local (P5). There is no protocol-defined root; each verifier's perimeter configuration is assumed to reflect their risk decisions and is integrity-protected.
6. Compromise recovery for trust anchors and DIDs is out-of-band (§5.4) and is assumed to be timely. This document treats that assumption as a risk.

---

## 4. Attacker Model

| ID | Attacker | Capabilities |
|---|---|---|
| A1 | Network attacker | Observes and manipulates traffic; cannot break TLS. |
| A2 | Domain or host controller | Controls what a participant's domain serves (DNS hijack, mis-issued certificate, web server or CDN compromise, dangling DNS, rogue proxy or cache). Holds no keys. |
| A3 | Past-key holder | Holds a DID Management Key that was active at some earlier log entry. |
| A4 | Current-key holder | Holds a key in the active `updateKeys`. |
| A5 | Malicious counterparty | Controls its own DID, domain, and whois; crafts DIDs, credentials, and URLs presented to verifiers. |
| A6 | Compromised or malicious issuer / trust anchor | Holds an issuer's credential signing key. |
| A7 | Insider | Infrastructure administrator, operator, credential-approval officer, or developer with access to signing systems, key access policies, deployment pipelines, configuration, or approval devices. |
| A8 | Curious observer | Host, issuer, proxy, or watcher operator that learns from resolution and status-list traffic. |

Distinguishing A3 from A4 matters because they enable different attacks (Appendix A).

---

## 5. Threat Catalogue

Each threat lists the attacker classes involved, the attack, its impact, mitigations that already exist in the specification or in common designs, and the remaining gap with recommendations. Severity is a first-pass qualitative rating (H / M / L) combining impact and likelihood. It rates the threat as it applies to an implementation that does not defend against it, so a threat marked as addressed in the specification keeps its rating, and the remaining risk is that an implementation fails to follow the specification. The ratings are intended for discussion and are not a final risk score.

### 5.1 Control of the DID (Keys and Log)

#### T-DID-01 — Fork of the DID log using a past management key — **H**

- **Attacker:** A3 (optionally with A2 to serve the fork)
- **Attack:** Each log entry is signed by a key from the previous entry's `updateKeys`. Anyone holding a key that was authorised at entry *k*, even if it was rotated out later, can sign an alternative entry *k+1′* with a different `state` and attacker-chosen `updateKeys`, and then extend that branch indefinitely.
- **Impact:** An alternative, cryptographically valid history in which every key is attacker-controlled. Combined with A2, verifiers who have no prior state accept the fork. On its own, the fork supports false disputes, such as claiming that the legitimate operator signed data it never signed.
- **Existing mitigations:** did:webvh witnesses must not sign two children of one parent, and watchers can detect divergence. Neither is required by OTL.
- **Gaps and recommendations:**
  - The OTL specification mandates neither witnesses nor fork detection, so a verifier following the specification alone cannot detect a fork. A verifier SHOULD consider the requirement of witnesses and watchers for its counterparties as part of its trust perimeter configuration.
  - Verifiers SHOULD cache the highest verified `versionId` per DID and fail on any divergence.
  - For implementers, rotated-out keys remain fork-capable for as long as they exist. Treat their destruction as a control with evidence. Where the key store enforces a deletion waiting period, rotated-out keys need immediate disablement plus a policy denying their use.

#### T-DID-02 — Current management key compromise: undetectable takeover — **H**

- **Attacker:** A4 (optionally with A2 to serve the extension live)
- **Attack:** The active DID Management Key can sign the next canonical log entry. The attacker rotates every key and service, replaces `watchers`, sets `ttl` to its maximum, and sets `updateKeys` to keys only they hold, locking out the legitimate operator.
- **Impact:** Complete identity takeover that extends the real log. Witnesses co-sign it because it validly extends the log they hold, and they do not check content or the participant's consent. Verifiers see an ordinary key rotation (§5.4).
- **Existing mitigations:**
  - §3.2.2 requires the DID Management System to be treated as at least as sensitive as any key it manages.
  - **Revocation of the OtlHostingCredential (§4.17):** once the takeover is noticed, the provider revokes the credential. Verifiers that require or have seen the hosting attestation then stop trusting the DID (§4.16). The attacker cannot undo this without the provider's credential signing key and status list.
- **Gaps and recommendations:**
  - Custody of the management key is the decisive control. Require dual control or an independent approval for every log entry, with the approval bound to the exact entry content.
  - Give witnesses a content policy for high-impact changes (rotation of application data keys, service endpoint changes, `updateKeys` changes, deactivation) that requires an independent approval artefact rather than only checking log extension.
  - Notify the participant and alert operations on every published log entry, so that an unexpected rotation is noticed within minutes.

#### T-DID-03 — Abuse of DID parameters after takeover — **M**

- **Attacker:** A3 on a fork, A4 on the canonical log
- **Attack:** Beyond replacing keys and services, an attacker can:
  - Replace the `watchers` parameter (a new value replaces the active set), so the key the watchers guard against controls the watcher list.
  - Set `ttl` up to 2^31 seconds so verifiers cache poisoned state long after recovery, or `0` to force load.
  - Deactivate the DID or set `updateKeys: []`, permanently destroying or freezing it.
  - Add `PathHandler` services or override `#whois` / `#files` to redirect retrieval to attacker hosts.
- **Gaps and recommendations:** Verifiers MUST NOT accept `#whois` / `#files` overrides pointing outside the DID's own origin, and SHOULD cap `ttl` below the specification maximum for high-value flows (for example at 300 seconds).
- **Spec status:** Partly addressed. §2.3 forbids verifiers from applying a `ttl` above 3600 seconds. §2.4 and the OtlHostingCredential (§4.12 to §4.17) let a hosting provider issue the watcher list, and verifiers query the union of both sets, fail on any divergence, and do not count log-only watchers as independent. The attacker can still add rogue watchers through the log, which can cause a failed resolution but not an accepted fork. Off-origin `#whois` / `#files` overrides are not yet restricted.

#### T-DID-04 — Key reuse across purposes — **M**

- **Attacker:** A3, A4, A6
- **Attack:** did:webvh allows an `updateKeys` key to also appear as a `verificationMethod`. A key used for routine signing is then also the identity's master key.
- **Recommendation:** The DID Management Key MUST NOT appear in any verification relationship, and no key may serve more than one OTL purpose. Verifiers SHOULD reject DIDs that violate this.
- **Spec status:** Partly addressed. §3.2.1 makes the credential signing key exclusive to credentials, but nothing forbids the DID Management Key from also appearing in a verification relationship.

#### T-DID-05 — Rotation back to a previously used key — **M**

- **Attacker:** A3, A7
- **Attack:** If the signing system does not remember every key it has ever published, a rotation can reintroduce a previously rotated-out, possibly compromised key. A rotation precondition that only says "the key must not yet exist" is ambiguous about whether keys that no longer exist count.
- **Recommendation:** The signing component keeps the full key history per DID and rejects any previously published key. Define key rotation precisely: the key type must exist, the new key must never have been published, and exactly one key per type exists afterwards.

#### T-DID-06 — Witness unavailability blocks emergency rotation — **M**

- **Attacker:** A1/A2 against witness infrastructure, A7
- **Attack:** Every update requires k-of-n witness proofs. Taking down n−k+1 witnesses blocks all updates, including the emergency rotation needed during an incident. Witnesses are static did:key identities, and replacing a witness requires a threshold of the existing set.
- **Recommendation:** Size k and n for availability, place witnesses in independent failure domains (including at least one operated by an independent organisation), and document an emergency procedure.

#### T-DID-07 — Witnesses share fate with the controller — **M**

- **Attacker:** A7
- **Attack:** Witnesses that share administrators, deployment pipelines, or cloud accounts with the DID management system, or that have no independent validation logic, can be compromised together with it or tricked into signing malicious updates that they cannot independently verify. A single insider or pipeline compromise can then satisfy the threshold.
- **Recommendation:** If witnesses are used, at least one witness should be operated by an independent organisation with its own approval policy, so that the threshold cannot be met from within the controller's own organisation.

### 5.2 Resolution, Transport, and Domain

#### T-RES-01 — SSRF and network-boundary abuse through resolution — **H**

- **Attacker:** A5
- **Attack:** DIDs, issuer DIDs, `statusListCredential` URLs, JSON-LD contexts, and service endpoints are attacker-supplied URLs that the verifier fetches. did:webvh reports that all four reviewed implementations were vulnerable to at least one of: automatic redirects, IP-literal hosts, percent-encoding case handling, or traversal after decoding. A verifier running inside a private network, close to transaction-signing systems, exposes internal services.
- **Recommendation:** Run all resolution through an egress-restricted resolver service in a DMZ. Implement the did:webvh resolver hardening list in full (no automatic redirects, IP-literal rejection before and after decoding, case-insensitive percent decoding, size caps, timeouts, HTTPS only). Resolve DNS once and connect to that address to defeat rebinding.

#### T-RES-02 — Rollback to a stale or truncated log — **H**

- **Attacker:** A2
- **Attack:** The host (or a CDN or cache) serves an older valid prefix of the log, so the verifier accepts a key that was rotated out because it was compromised. The default `ttl` of 3600 seconds lets stale state persist after an incident even without an attacker.
- **Recommendation:** Verifiers MUST store the highest verified `versionId` per DID and fail on a shorter log, apply a shorter `ttl` and refetch the current document state for security-sensitive flows, and cross-check against the prescribed watchers.
- **Spec status:** Partly addressed. §2.3 caps `ttl` at 3600 seconds, but the specification does not yet require verifiers to remember the highest verified `versionId`.

#### T-RES-03 — Split view — **H**

- **Attacker:** A2 alone (serving different valid prefixes to different audiences); A2 with A3/A4 (serving forks)
- **Attack:** Targeted verifiers see a different DID state from everyone else.
- **Existing mitigations:** Watchers (SHOULD, §2.4). A verifier that queries watchers MUST compare the log it retrieved with each watcher's log and MUST treat any divergence as a failed resolution. Witnesses are available in did:webvh but are not profiled by OTL.
- **Recommendation:** For high-value interactions, verifiers SHOULD compare the retrieved log against at least one independent watcher and fail on divergence.

#### T-RES-04 — First contact has no fork detection — **M**

- **Attacker:** A2 with A3
- **Attack:** A verifier resolving a DID for the first time has no cached state, so cache-based fork and rollback detection gives no protection.
- **Recommendation:** On first contact with a counterparty in a high-value flow, require watcher corroboration, or require witnesses for the class of DID being trusted.

#### T-RES-05 — Stripping the hosting or watcher credential — **M**

- **Attacker:** A2 with A3/A4
- **Attack:** Hosted deployments may convey the authoritative watcher set, or an attestation of how the DID is operated, in a credential issued by the hosting provider. Disclosure in the whois VP is the holder's choice (§4.4), so an attacker who has taken over a DID simply omits that credential while keeping the LEI credential.
- **Recommendation:** An LEI credential says nothing about how securely a counterparty manages its DID and keys. For high-value flows, a verifier should require additional credentials that assert good practice in securing the DID infrastructure, such as the OtlHostingCredential or security audit credentials in the future, and should decide from out-of-band knowledge (for example a configured domain suffix) which DIDs are expected to carry one.
- **Spec status:** Partly addressed. §4.12 to §4.17 define the OtlHostingCredential, but the specification does not require a verifier to insist on it for DIDs that are expected to be hosted.

#### T-RES-06 — Downgrade to did:web — **M**

- **Attacker:** A2
- **Attack:** A participant publishing both did:webvh and a parallel did:web exposes an unverifiable path, and a verifier accepting the did:web form loses history and rotation guarantees.
- **Recommendation:** Verifiers MUST reject did:web for issuers and trust anchors (§4.2 already requires issuers to hold a did:webvh), SHOULD prefer the did:webvh form whenever both exist, and SHOULD reject did:web counterparties for high-value flows.

#### T-RES-07 — WebPKI and DNS weaknesses — **M**

- **Attacker:** A2
- **Attack:** Domain-validated certificate mis-issuance (for example via BGP hijack and ACME), DNS hijack, or dangling DNS records give domain control. A wildcard certificate for a shared hosting domain is a single high-value key for every hosted DID.
- **Recommendation:** DNSSEC, CAA records, Certificate Transparency monitoring, removal of dangling records, and per-DID or short-lived certificates where practical.

#### T-RES-08 — Resolver denial of service and amplification — **M**

- **Attacker:** A5
- **Attack:** Oversized or slowly streamed logs, logs with many entries, and whois presentations containing many credentials (see T-VC-06).
- **Recommendation:** Byte and entry-count caps per DID, operation timeouts, concurrency and rate limits, especially for previously unseen DIDs.

#### T-RES-09 — Untrusted time — **L**

- **Attacker:** A1, A7
- **Attack:** `versionTime` tolerance, credential `validFrom`, and verifiable-address expiry all depend on clocks. Isolated execution environments (trusted execution environments, hardware security modules) often take time from an untrusted host, so a host-controlled clock can skew expiry checks and the `versionTime` the signing component signs.
- **Recommendation:** Document the signing component's time source, bound acceptable drift, and avoid security decisions inside the signing component that depend on host-supplied time alone.

### 5.3 Credential Verification (§4, §5.3)

#### T-VC-01 — Credential replay through missing subject binding — **H**

- **Attacker:** A5
- **Attack:** VCs are public. A validation procedure that checks only proof, revocation, and trust perimeter does not establish that `credentialSubject.id` equals the VP `holder` and the DID being authenticated, so an attacker can copy another entity's LEI credential into their own whois VP.
- **Recommendation:** Verifiers MUST check that `credentialSubject.id` equals the VP `holder` and the authenticated DID, that the VP proof verifies against the holder's DID, that `type` contains the expected credential type, that `validFrom` is not in the future, that the issuer DID uses did:webvh, and that the issuer is not the subject. The issuer-versus-subject comparison should cover all `alsoKnownAs` forms, because a string comparison alone is bypassed by a did:web alias.
- **Spec status:** Addressed in §5.3 (binding checks 1 to 6). The specification compares the issuer with the subject but does not say that `alsoKnownAs` forms must be compared.

#### T-VC-02 — Credential signing key rotation — **H**

- **Attacker:** A6, or availability failure
- **Attack:** §3.3 says a key is valid only while present in the *current* DID document. Rotating the credential signing key out of `assertionMethod` invalidates every credential and status list it ever signed. If verifiers instead accepted the historical version, a holder of a compromised signing key could backdate `validFrom`.
- **Spec status:** Addressed in §3.2.1. Credentials and status lists are verified against the issuer's current DID document only. In a planned rotation the issuer keeps both keys listed until all credentials and status lists are re-signed. On compromise the key is replaced with no overlap, and everything it signed is invalid until re-issued. §3.3 is unchanged and does not mention credential signing keys.

#### T-VC-03 — Expiry not enforced by verifiers — **M**

- **Attacker:** A5 (benefiting from issuer inaction)
- **Attack:** Where a credential carries no `validUntil`, expiry lives only in the underlying registration (for an LEI, `registration.nextRenewalDate`) and is enforced only if the issuer revokes. Verifiers that are not required to check dates accept lapsed credentials.
- **Recommendation:** Issuers MUST set `validUntil` no later than the registration renewal date, and verifiers MUST reject expired credentials independently of revocation.
- **Spec status:** Addressed. §4.8 requires `validUntil` on OtlLeiCredential and forbids it from exceeding `nextRenewalDate`, and §4.5 and §5.3 (binding check 4) require verifiers to reject an expired credential whether or not it has been revoked.

#### T-VC-04 — Network fetches before the trust check — **H**

- **Attacker:** A5
- **Attack:** A verifier implementation that resolves the issuer DID and fetches the status list before checking whether the issuer is trusted lets any attacker-crafted credential trigger fetches to attacker-chosen hosts, enabling SSRF, DoS, and tracking.
- **Recommendation:** Verifier implementations must check the issuer DID and credential type against the trust perimeter before any network I/O, including in code paths that parse whois presentations, resolve contexts, or pre-fetch status lists for caching. Cover this ordering with tests that assert no outbound request is made for an untrusted issuer.
- **Spec status:** Addressed in §5.3 ("Trust perimeter first") and in step 1 of §4.16.

#### T-VC-05 — No scoping of issuers to credential types — **M**

- **Attacker:** A6
- **Attack:** A verifier implementation that stores trusted issuers as a flat list of DIDs accepts every credential type from any issuer on it. An issuer trusted for one claim (for example a hosting attestation) can then also issue LEI credentials.
- **Recommendation:** Verifier implementations must model each trust perimeter entry as an (issuer DID, credential type) pair in configuration, lookup, and logging, with no flat issuer allowlist anywhere in the code.
- **Spec status:** Addressed in §6.1, which defines a trust perimeter entry as an (issuer DID, credential type) pair. §4.12 additionally recommends accepting a hosting credential only for subject DIDs on the hosting domains the provider is responsible for.

#### T-VC-06 — whois amplification — **M**

- **Attacker:** A5
- **Attack:** A whois VP may contain many credentials, each with a distinct issuer and status URL. Combined with T-VC-04, one resolution fans out into hundreds of fetches.
- **Recommendation:** Cap the credentials processed per VP, and process only recognised types from trusted issuers. §4.4 already requires unrecognised types to be skipped, and §5.3 requires the trust perimeter check before any network request, which together bound the fan-out for untrusted issuers but not for a large number of trusted ones.

#### T-VC-07 — Stale or weak attributes — **M**

- **Attacker:** A5
- **Attack:** Credentials are snapshots. Name changes, mergers, and LEI status changes (lapsed, retired, merged, annulled) before the renewal date are not reflected. `corroborationLevel: PENDING` credentials can be issued and nothing tells verifiers to reject them. There is no LEI registration-status field.
- **Recommendation:** Add a registration-status field, require revocation on any status change and not only on lapse, and have verifiers in high-assurance flows require `FULLY_CORROBORATED`.
- **Spec status:** Open. §4.9 requires the LOU to revoke only when the registration expires.

#### T-VC-08 — Absence of negative evidence — **L**

- **Attacker:** A5
- **Attack:** Holders choose what to disclose and will omit unfavourable credentials (for example a failed audit attestation).
- **Recommendation:** Verifier policy should require positive credentials and treat absence as absence, never as a pass.

#### T-VC-09 — Delegation is invisible to verifiers — **M**

- **Attacker:** A7 (at a provider)
- **Attack:** §2 lets participants delegate protocol participation to a software provider, but without further signals verifiers cannot tell a self-operated DID from a provider-operated one, or factor the provider's security into their trust decision.
- **Recommendation:** Define a hosting or delegation credential type, issued by the provider and bound to the DID, and let verifiers apply policy based on it.
- **Spec status:** Partly addressed. OtlHostingCredential (§4.12 to §4.17) identifies the provider as its issuer and is bound to the full DID, which contains the SCID. §4.12 fixes the meaning of "hosts": the provider serves the DID, controls the DID Management Key, and controls or has performed due diligence on every other key in the DID document. It does not describe how the provider holds the key (alone, dual control, MPC), so a verifier cannot tell those apart.

#### T-VC-10 — Opaque trust signals for anonymous participants — **L**

- **Attacker:** A5, malicious wallet or provider
- **Attack:** §7.2 envisages applications consuming an opaque pass/fail signal from a wallet or provider. A malicious or compromised provider, or UI spoofing, defeats the check.
- **Recommendation:** Document this as a trust delegation in §7 and encourage local verification where feasible.

### 5.4 Revocation (Bitstring Status List)

#### T-REV-01 — Status list rollback — **H**

- **Attacker:** A2, including a privacy proxy or any cache
- **Attack:** Where `validFrom`, `ttl`, and `validUntil` are optional and there is no sequence number, an older, validly signed list in which a revoked credential's bit is still 0 can be replayed indefinitely.
- **Recommendation:** Require `validFrom` and `validUntil` on status list credentials, reject lists older than a configured maximum age, and never accept a list older than one previously seen.
- **Spec status:** Addressed in §5.2 ("Freshness and rollback"), including the rule that a cache or proxy is bound by the same checks.

#### T-REV-02 — Status list not bound to the credential issuer — **M**

- **Attacker:** A6, or an attacker who later controls the status-list host (for example an expired domain)
- **Attack:** If a verifier checks the status list's own proof without checking against whom, a list signed by a different DID could be accepted.
- **Recommendation:** The status list `issuer` MUST equal the VC `issuer`, and the proof MUST be by a key referenced in that issuer's `assertionMethod`.
- **Spec status:** Addressed in §5.2 ("Issuer binding"). A separate status-list signing key is covered by T-REV-05.

#### T-REV-03 — Decompression bomb — **M**

- **Attacker:** A5, A6
- **Attack:** The specification sets a minimum list length but no maximum, so a tiny GZIP payload can decompress to gigabytes.
- **Recommendation:** Cap both compressed and decompressed size, and stream-decompress with a hard limit.

#### T-REV-04 — Availability versus freshness — **M**

- **Attacker:** A1/A2 against the issuer's status endpoint
- **Attack:** §5.3 fails closed when a status list cannot be fetched, so a DoS against one issuer (for example a platform operator issuing for many participants) halts validation for every counterparty. Failing open instead enables T-REV-01. With a 5-minute `ttl`, there is also an inherent revocation latency window.
- **Recommendation:** Define the policy per risk tier: fail closed for high-value transfers and allow bounded stale use for informational display. Host status lists on resilient, cache-friendly infrastructure.

#### T-REV-05 — Shared key for credentials and status lists bypasses approval — **H**

- **Attacker:** A7, or compromise of the automation that publishes status lists
- **Attack:** §5.2 signs status lists with a key referenced in `assertionMethod`, the key §3.2.1 justifies as low-frequency and high-assurance. Status lists need frequent automated signing. Where credential issuance is gated by human approval but status lists are signed automatically with the same key, a payload shaped like a status list but carrying additional types (for example `["VerifiableCredential", "OtlLeiCredential", "BitstringStatusListCredential"]`) could obtain a credential signature without approval, unless the signing component enforces a strict schema. Whoever can sign status lists can also revoke every credential (DoS).
- **Recommendation:** Introduce a separate status-list signing key, or have the signing component enforce an exact schema for status lists. Verifiers SHOULD reject credentials whose `type` mixes credential and status-list types.

#### T-REV-06 — Correlation through status checks — **L**

- **Attacker:** A8
- **Attack:** Random `statusListIndex` assignment is only a SHOULD (§5.1), so small lists or per-subject lists enable correlation. A proxy used to prevent issuer tracking becomes a party that sees all lookups.
- **Recommendation:** Make random index assignment a MUST and prohibit holder-specific status list URLs, as the did:webvh privacy considerations already require.

### 5.5 Trust Anchors and Trust Perimeter

#### T-TA-01 — Tampering with trust perimeter configuration — **H**

- **Attacker:** A7
- **Attack:** Inserting one attacker-controlled issuer DID into a verifier's trust perimeter defeats all attribution. Deployments that hardcode trusted issuer DIDs (for example the authority DIDs of peer operators) make that configuration a high-value target.
- **Recommendation:** Pin full DIDs including SCID, require `portable: false` for pinned anchors (currently only SHOULD NOT in §3.4), and place configuration under dual-control change management with signed artefacts and alerting on change.

#### T-TA-02 — Unscoped cross-environment issuers — **H**

- **Attacker:** A6 (one environment's authority), A7
- **Attack:** Where several operators or environments each trust the others' authority DIDs for all claims, a compromised authority in one environment can attest hosting or LEI credentials for DIDs hosted in another, so a compromise crosses regulatory or operational segregation boundaries.
- **Recommendation:** Apply name-constraint style rules, so that an environment's authority is trusted only for DIDs under that environment's hosting domain.
- **Spec status:** Partly addressed. §6.1 scopes trust to a credential type, and §4.12 says a verifier SHOULD accept an OtlHostingCredential only for subject DIDs on the hosting domains the provider is responsible for. Scoping of LEI credential issuers by domain is not specified.

#### T-TA-03 — No on-protocol response to anchor or issuer compromise — **H**

- **Attacker:** A6
- **Attack:** An attacker holding an issuer key can issue unlimited credentials and sign status lists showing them as unrevoked. §5.4 relies on an unspecified out-of-band channel. A "distrust credentials issued after time T" cut-off fails because the attacker backdates `validFrom`.
- **Recommendation:** Define the incident channel (at minimum, contact points and response expectations). Consider a credential transparency mechanism (for example watcher-signed first-seen timestamps for issued credentials) so that cut-offs can rely on independently observed issuance times.

#### T-TA-04 — Spoofed compromise reports — **M**

- **Attacker:** A5
- **Attack:** §5.4 recovery has the legitimate operator ask issuers out-of-band to revoke or reissue. An attacker impersonates a victim and requests revocation of the victim's credentials.
- **Recommendation:** Issuers maintain authenticated revocation-request procedures with pre-registered contacts, and publish time-to-revoke commitments.

#### T-TA-05 — LEI credentials from non-LOU issuers — **M**

- **Attacker:** Confusion rather than a specific attacker, exploitable by A6/A7
- **Attack:** §4.6 and §4.8 define LOUs as the issuers of OtlLeiCredential, but §3.2 also allows a platform operator to issue it before LOU onboarding. Verifiers cannot distinguish "a GLEIF-accredited LOU attested this" from "a platform operator attested this", and `registration.managingLou` is then inconsistent with `issuer`.
- **Recommendation:** Either define a separate credential type for operator-attested LEI bindings, or define how `issuer` and `managingLou` relate and what verifiers should conclude from each.

#### T-TA-06 — Fraudulent DID-to-LEI binding — **H**

- **Attacker:** A5 (social engineering), A7 (insider)
- **Attack:** LEI data is public, so the only control is the issuer's verification of who controls the DID. Typically this is an approval by a compliance officer. Weak points are onboarding fraud, insider collusion, approval fatigue, a gap between what the approver sees and what is signed, replay of an approval for a different DID, and single-approver decisions. Multiple DIDs per LEI, or competing issuers for the same LEI, can produce conflicting claims.
- **Recommendation:** Quorum approval; approval payloads that display and bind DID, LEI, and legal name, with nonce and expiry; a signing component that rejects approvals not bound to the exact request; and monitoring for multiple DIDs per LEI.

### 5.6 Cryptography and Parsing

#### T-CRY-01 — Algorithm and key-type confusion — **H**

- **Attacker:** A5
- **Attack:** Without an allowlist and a binding between cryptosuite and key type, verifiers may accept weak curves, invalid points, or a cryptosuite inconsistent with the key. The weakest accepted option sets the security floor.
- **Recommendation:** A normative allowlist (Ed25519 and P-256 for signing; X25519 and P-256 for key agreement), binding of `eddsa-jcs-2022` to Ed25519 keys and `ecdsa-jcs-2019` to P-256 keys, and validation of public keys.
- **Spec status:** Addressed in §3.1.1 (algorithm allowlist, cryptosuite binding, public key validation) and §6.3.

#### T-CRY-02 — Key-purpose confusion and JWS header trust — **M**

- **Attacker:** A5
- **Attack:** A signature is accepted because the key appears anywhere in the DID document rather than under the intended relationship and id. For verifiable addresses, the JWS `kid` and `alg` headers are attacker-controlled.
- **Recommendation:** Verifiers MUST require the key under the expected verification relationship (`assertionMethod` for credential issuance) with the expected fragment id and key type. The `kid` DID MUST match the claimed signer, and `alg` MUST be determined by the key type, never by the header.
- **Spec status:** Partly addressed. §3.2.1 and §6.3 require credential proofs to use a key referenced from the matching relationship and reject a wrong `proofPurpose`. JWS handling for verifiable addresses is defined by the layer that specifies them.

#### T-CRY-03 — JSON-LD context handling — **M**

- **Attacker:** A5
- **Attack:** §4.3 allows additional contexts. Remote context loading creates SSRF and substitution risk, and term redefinition can change meaning for processors that interpret JSON-LD.
- **Recommendation:** A static context allowlist, no remote context loading, and processing as plain JSON against a strict schema (the JCS cryptosuites do not require JSON-LD processing).

#### T-CRY-04 — Parser differentials — **M**

- **Attacker:** A5
- **Attack:** Duplicate JSON keys, number serialisation differences under JCS, multi-typed credentials, and `credentialSubject` as an array can cause the signer, verifier, and display layer to read different values.
- **Recommendation:** Reject duplicate keys, use strict schemas per credential type, and publish conformance test vectors for the specification track.

#### T-CRY-05 — Display spoofing — **M**

- **Attacker:** A5
- **Attack:** `legalName`, `otherNames`, `commonName`, and DID domain labels displayed to operators can use homoglyphs, bidirectional override characters, or look-alike names.
- **Recommendation:** Normalise and sanitise displayed strings, and always display LEI and DID alongside names.
- **Spec status:** Partly addressed. §4.14 forbids control characters and bidirectional overrides in `commonName`, tells verifiers to render it as untrusted text, and tells them to show it together with the subject DID and the issuing provider.

### 5.7 Hosted Deployments and Signing Infrastructure

These threats apply to implementations in general, and most strongly to hosted deployments in which one operator runs DIDs, keys, and endpoints on behalf of many participants.

#### T-HOST-01 — Rollback of signing-component state — **H**

- **Attacker:** A7 (control of the host around the signing component)
- **Attack:** Signing components that keep no persistent state of their own (many isolated execution environments) learn the "latest DID document version" from the surrounding host. A malicious host presents an older version as current and the signing component signs a fork.
- **Recommendation:** Anchor the latest version outside the host's control (witness proofs, a monotonic counter, or a signed head stored independently), and use witnesses that enforce one child per parent.

#### T-HOST-02 — Governance of key access and signing code — **H**

- **Attacker:** A7
- **Attack:** Changing key access policies, adding an unreviewed build to the list of attested signing-code measurements (which is effectively the root of the signing system), tampering with the build pipeline, or granting oneself a signer role.
- **Recommendation:** Dual control on key access policy and attestation allow-list changes, reproducible builds of signing code, tamper-evident logging with alerting, and authenticated and authorised callers for every signing operation.

#### T-HOST-03 — Signing oracle within allowed rules — **M**

- **Attacker:** A7, or a compromised internal service
- **Attack:** A compromised service that is allowed to request DID document changes can push many valid-looking changes (new keys, new service entries) across many hosted DIDs, all within the signing component's validation rules.
- **Recommendation:** Content validation inside the signing infrastructure (for example requiring an authentication attestation for keys), per-DID and global rate limits, anomaly detection, strict service-type allowlists and endpoint patterns, and participant notification on document changes.

#### T-HOST-04 — Hosting namespace abuse — **M**

- **Attacker:** A5, A7
- **Attack:** Hosted deployments often assign each participant a subdomain of a shared domain. Loose pattern matching (for example a wildcard that also accepts deeper labels), participant-chosen names (squatting, reserved names, internationalised look-alikes), reuse of a subdomain after a participant leaves (misattribution), and dangling DNS records (takeover) all undermine the binding between name and identity.
- **Recommendation:** Exact label-count matching, a reserved-name list, ASCII-only labels, no subdomain reuse, and continuous DNS hygiene monitoring.

#### T-HOST-05 — Offboarding and portability — **M**

- **Attack:** With `portable: false` (recommended in §3.4), hosted DIDs are permanently tied to the provider's domain. When a participant leaves, any hosting attestation, watcher records, and DID state need defined handling, or the DID continues to signal that it is operated by the provider.
- **Recommendation:** Define an offboarding procedure: revoke hosting attestations, deactivate the DID, notify watchers, and agree with the participant how they establish a replacement identity and obtain reissued credentials.
- **Spec status:** Partly addressed. §4.17 requires the provider to revoke the OtlHostingCredential on offboarding or domain move. Deactivation, watcher notification, and replacement-identity handling remain open.

#### T-HOST-06 — Simplified verification procedures — **M**

- **Attacker:** A2, A3, A4 (exploiting under-verification)
- **Attack:** Implementations that summarise the did:webvh resolution algorithm (for example "check each version is signed by the previous version's key") tend to omit the entryHash chain, `versionTime` monotonicity, SCID consistency across every entry, `method` and cryptosuite checks, and witness verification.
- **Recommendation:** Implement the did:webvh resolution algorithm in full plus the OTL additions in the specification, and run the did:webvh interoperability test suite against every verifier.

#### T-HOST-07 — Split-horizon resolution — **M**

- **Attacker:** A7, misconfiguration
- **Attack:** An operator that serves the same DIDs on an internal network (for example over a VPN) and publicly can return different views of one DID, so that verifiers on each side reason about different state.
- **Recommendation:** Have watchers cross-check the internal and public views and alert on divergence.

### 5.8 Privacy

#### T-PRV-01 — Resolution metadata reveals relationships — **M**

- **Attacker:** A8
- **Attack:** As host of many participants' DIDs, a hosting provider sees which external parties resolve which participant, which reveals payment intent and commercial relationships. Issuers see status-list fetches.
- **Recommendation:** Caching-friendly responses (CDN), minimal access logging with retention limits, and support for watcher-based resolution.

#### T-PRV-02 — Participant enumeration — **M**

- **Attacker:** Any observer
- **Attack:** Certificate Transparency logs, public DID logs, and whois presentations enumerate a hosting provider's customers and publish each participant's DID-to-LEI link.
- **Recommendation:** Obtain participant consent for public listing, prefer certificates that do not disclose per-participant names, and consider opaque subdomain labels.

#### T-PRV-03 — Long-term correlation — **L**

- **Attacker:** A8
- **Attack:** Static DIDs and status-list access patterns allow correlation of activity over time.
- **Recommendation:** Accept this as inherent for institutional identities, and avoid putting unnecessary endpoints or personal data in DID documents.

---

## 6. Infrastructure and Key Management Recommendations for Implementers

This section collects deployment recommendations for implementation partners. It is product-neutral: the requirements can be met with hardware security modules, trusted execution environments, multi-party computation, or combinations of these. The choice should follow from the requirements below, not the other way round.

### 6.1 Key Classes and Protection Levels

| Key | Compromise impact | Recommended protection |
|---|---|---|
| DID Management Key | Undetectable takeover of the identity (T-DID-02); forks with rotated-out keys (T-DID-01). | Highest. Non-exportable, hardware-backed. Every use bound to an approval of the exact log entry, with dual control or participant co-signing. Never used for anything else. |
| Credential signing key (`assertionMethod`) | Fraudulent legal-entity attributions for any subject the issuer vouches for. | Highest. Non-exportable, hardware-backed. Issuance gated by human approval for claims that rest on human verification (such as DID-to-LEI bindings), with quorum approval. |
| Status-list signing key (recommended, T-REV-05) | Mass revocation (DoS) or suppression of revocations. | High. Automated signing permitted, but only of payloads matching the exact status-list schema. |
| Application data signing keys (for example payment addresses) | Misdirected funds for the affected participant. | High. Signing performed by, or tightly coupled to, the system that owns the data, so that it can validate what it signs. |
| Presentation and message signing keys (defined by other layers) | Impersonation in sessions and messages until rotation. | High. Non-exportable; rotation without coordination with the DID management process beyond a log entry. |
| Key agreement (decryption) keys | Disclosure of message contents, potentially including personal data. | Medium. Encrypted at rest. |

### 6.2 General Requirements for Signing Keys

1. Generated inside the key store using a cryptographically secure random number generator, and non-exportable.
2. One key per participant and purpose, with no key used across purposes or participants (T-DID-04).
3. Infrastructure administrators hold no signing capability, and no single person can both change key access policy and use the key.
4. Key access, policy changes, and every signing operation recorded in a tamper-evident log that administrators cannot alter, with alerting on policy changes and unusual signing volume.
5. Keys isolated from other workloads, and signing components accessible only to authenticated, authorised callers.
6. Algorithms restricted to the specification's allowlist (Ed25519 for did:webvh log entries; Ed25519 or P-256 for credentials and presentations; X25519 or P-256 for key agreement).
7. Rotation and destruction planned for in advance.

### 6.3 Validate What You Sign

A signing key is only as trustworthy as the checks performed before it is used. The signing component (not the calling service) should validate every payload:

- **DID log entries:** accept requests as a list of atomic changes (create, add key, rotate key, add service) rather than a complete new document, validate each change against fixed rules (key type, curve, expected fragment id, permitted service types and endpoint patterns, binding to the right participant), and apply them together or not at all.
- **Key additions:** accept a new public key only with an authenticated statement from the system that generated it, binding the key to the participant and purpose.
- **Credentials:** enforce an exact schema per credential type, and require approvals that are bound to the exact subject DID and claim values, carry a nonce and an expiry, and come from the required quorum (T-TA-06).
- **Status lists:** enforce an exact status-list schema and reject any payload with additional types (T-REV-05).
- **Application data:** confirm that the data (for example a payment address) belongs to the participant whose key signs it, and enforce limits on metadata such as expiry.

### 6.4 State, Time, and Rotation

- Keep authoritative DID state (latest version per DID, full key history) where the host around the signing component cannot roll it back (T-HOST-01, T-DID-05).
- Document the signing component's time source and bound drift (T-RES-09).
- Disable rotated-out keys immediately and destroy them as soon as the key store permits (T-DID-01). Reject reintroduction of any previously published key.
- Rehearse emergency rotation, including the witness approvals it requires (T-DID-06).

### 6.5 Hosting, Resolution, and Network

- Run DID resolution and status-list retrieval in a dedicated, egress-restricted service, separated from signing and transaction systems, implementing the did:webvh resolver hardening requirements in full (T-RES-01).
- Use DNSSEC and CAA records, monitor Certificate Transparency, remove dangling DNS records, and protect TLS private keys for hosting domains at a level appropriate to the number of identities they serve (T-RES-07).
- Serve DID logs, witness files, whois presentations, and status lists from caching-friendly, highly available infrastructure, with access logging minimised (T-REV-04, T-PRV-01).
- Configure witnesses and watchers so that at least one of each is operated independently of the DID controller (T-DID-07, T-RES-03).
- Where DIDs are served both internally and publicly, cross-check the two views (T-HOST-07).

### 6.6 Verifier Configuration

- Manage the trust perimeter as signed configuration under dual-control change management, pinning full DIDs including SCID and scoping each issuer to credential types and hosting domains (T-TA-01, T-TA-02, T-VC-05).
- Cache the highest verified version per DID, cap `ttl`, and define a maximum staleness and fail-closed policy per risk tier (T-RES-02, T-REV-04).
- Treat verified identity and credentials as one risk signal among several for high-value transfers, and re-evaluate them at the time of use rather than relying on an earlier check.

### 6.7 Incident Readiness

- Maintain authenticated channels with every issuer and trust anchor for compromise notification and revocation requests (T-TA-03, T-TA-04).
- Define and test the response to compromise of each key class in Section 6.1, including how participants and verifiers are told.

---

## 7. Architectural Risk: Concentration of Control

Concentration of control is not an attack vector in itself, but it determines the impact of several threats above.

In a hosted deployment, one operator can control the DID management keys, the hosting domain and TLS certificates, the credential issuance keys, the status lists, all witnesses, and most or all watchers for every hosted identity. A single breach of the hosting environment, or a single malicious insider with sufficient access, can therefore affect all hosted identities at once (T-DID-02, T-HOST-01, T-HOST-02, T-TA-06).

This contrasts with the aim that no single operator should sit in the resolution path for other participants, and with the alternative of holding DID management keys as participant-owned keys, for example through multi-party computation.

Recommendations:

1. State the concentration explicitly in the operator's risk acceptance, together with the compensating controls relied upon.
2. Introduce independence where it is cheapest: at least one independent witness, independent watchers, and dual control on every use of the DID management keys.
3. Keep a participant-controlled management key option available, and have the hosting credential state which custody model applies so that verifiers can price it in (T-VC-09).

---

## 8. Specification Status and Remaining Proposals

The table below tracks the protocol-level changes this analysis recommends against specification v0.6. Items marked "Addressed" are in v0.6. The "Remaining" items are proposals for the next draft.

| # | Section | Change | Threats addressed | Status in v0.6 |
|---|---|---|---|---|
| 1 | §5.3 | Check issuer DID and credential type against the trust perimeter before any network I/O. | T-VC-04, T-VC-06, T-RES-01 | Addressed (§5.3 "Trust perimeter first", §4.16). |
| 2 | §5.3 | Binding checks: subject equals holder equals authenticated DID; VP proof; `type`; `validFrom`; `validUntil`; issuer is did:webvh; issuer is not the subject. | T-VC-01, T-VC-03 | Addressed (§5.3 binding checks 1 to 6). Remaining: compare issuer and subject across `alsoKnownAs` forms. |
| 3 | §3.2.1 | Define which DID document version verifies a credential, and the credential signing key rotation procedure. | T-VC-02 | Addressed (§3.2.1). |
| 4 | §4.8 / §4.9 | Require `validUntil` no later than `nextRenewalDate`; add a registration-status field; require revocation on any LEI status change. | T-VC-03, T-VC-07 | `validUntil` addressed (§4.8). Remaining: registration-status field and revocation on any status change. |
| 5 | §6.1 | Key the trust perimeter on (issuer DID, credential type); allow domain scoping of issuers. | T-VC-05, T-TA-02 | Addressed for credential types (§6.1) and for hosting domains (§4.12, SHOULD). Remaining: domain scoping for LEI issuers. |
| 6 | §5.2 | Require status list `validFrom` / `validUntil`, maximum age, monotonic acceptance, and issuer equality; cap list size. | T-REV-01, T-REV-02, T-REV-03 | Addressed except size caps. |
| 7 | §3.2 / §5.2 | Introduce a separate status-list signing key, or require strict schema separation. | T-REV-05 | Remaining. |
| 8 | §3.1.1 / §6.3 | Algorithm allowlist; cryptosuite-to-key-type binding; point validation; key under the expected relationship. | T-CRY-01, T-CRY-02 | Addressed (§3.1.1, §6.3). |
| 9 | §2.3 / §3.2.2 | Verifiers cache the highest verified `versionId`; cap `ttl`; reject off-origin `#whois` / `#files` overrides; forbid use of the DID Management Key in verification relationships. | T-RES-02, T-DID-03, T-DID-04 | `ttl` cap addressed (§2.3). Remaining: `versionId` caching, off-origin overrides, management key separation. |
| 10 | §2.4 / new section | OTL witness and watcher profile: when required, independence requirements, verifier behaviour on divergence, first-contact policy. | T-DID-01, T-DID-07, T-RES-03, T-RES-04 | Watcher set and divergence handling addressed (§2.4). Remaining: witness profile and first-contact policy. |
| 11 | §4.12 to §4.17 | Define a hosting credential type, including the authoritative watcher set and custody model. | T-RES-05, T-VC-09 | Addressed except the custody model. |
| 12 | §4.3 | Static context allowlist, no remote context loading, strict schemas, reject duplicate keys. | T-CRY-03, T-CRY-04 | Remaining. |
| 13 | §5.4 | Define minimum incident-channel expectations and authenticated revocation-request procedures. | T-TA-03, T-TA-04 | Remaining. |
| 14 | §3.2 / §4.6 / §4.8 | Clarify LEI credentials issued by non-LOU operators. | T-TA-05 | Remaining. |
| 15 | New section | Resolver hardening requirements (reference the did:webvh security considerations as normative for OTL verifiers). | T-RES-01, T-RES-08 | Remaining. |

---

## 9. Open Questions

1. Should witnesses be mandatory for issuers and for DIDs used in payment flows, and who operates an independent one? (T-DID-01, T-DID-07)
2. Which approval policy governs each use of a DID management key, given that compromise of the current key is an undetectable takeover? (T-DID-02)
3. What is the fail-closed or fail-open policy per transfer risk tier when status lists are unreachable? (T-REV-04)
4. Should operator-attested LEI bindings use the OtlLeiCredential type or a distinct type? (T-TA-05)
5. How many approvers are required for an LEI binding, and what exactly does the approval device display? (T-TA-06)

---

## 10. Priority Summary

| Priority | Threats | Rationale |
|---|---|---|
| 1 — Verifier correctness | T-VC-01, T-VC-02, T-VC-04, T-CRY-01, T-CRY-02, T-RES-02 | Mostly specified in v0.6, so the remaining work is implementation conformance and tests. Failures here undermine every other control. |
| 2 — Revocation integrity | T-REV-01, T-REV-02, T-REV-03, T-REV-05 | Revocation is the routine compromise response; rollback or key sharing silently disables it. Rollback and issuer binding are specified, while size caps and key separation remain open. |
| 3 — Key custody and fork resistance | T-DID-01, T-DID-02, T-HOST-01, T-HOST-02 | Determines whether a key compromise is detectable and containable. |
| 4 — Trust anchor lifecycle and scoping | T-TA-01, T-TA-02, T-TA-03, T-TA-06, T-VC-05 | Largest blast radius; mostly configuration and policy work. |
| 5 — Systemic risk acceptance | Section 7 | Needs an explicit decision rather than an engineering fix. |

---

## Appendix A — What Each Management Key Class Enables

| Key held by attacker | Can extend canonical log? | Can fork? | Detectable by |
|---|---|---|---|
| Past key (authorised at entry *k*, since rotated out) | No | Yes, from entry *k+1* | Witnesses (refuse second child), watchers, verifier caches of later versions |
| Current key (in the active `updateKeys`) | Yes | Yes | Only witness content policies, participant notification, hosting credential revocation, or out-of-band review; log extension itself is valid |
| Domain control only (A2) | No | No, but can serve truncated or per-audience prefixes | Verifier caches, watchers |

Implications: protection against management key compromise rests on custody and approval of the current key, on destroying rotated-out keys, and on fork detection by witnesses or watchers. Nothing in the log itself distinguishes a legitimate rotation from one made with a stolen current key.
