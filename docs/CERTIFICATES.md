# Certificate trust and removal (3.2.3)

Sentinel separates a review finding from permission to change a Windows trust store.

## Current implementation

`RootStoreGuard` inventories Root/CA stores at startup and every 90 seconds in the SYSTEM service. It checks the live certificate context for AuthRoot CTL and Microsoft root-program properties. Missing both markers yields a review-only Tier2 observation, not proof that the certificate was planted. Property-read failures can also leave markers unconfirmed. A marker does not prove a certificate cannot be abused, and placing a certificate in a machine store does not make its origin trustworthy.

Automatic removal, insertion into Disallowed and associated file quarantine require an exact thumbprint on the explicit `CertDistrustList`, plus the existing action-specific safeguards. `CertRemediator` refuses heuristic-only requests at its entry point. Names, broad purpose, a self-signed certificate or absence of a Microsoft marker alone cannot authorize removal. This corrects the older 3.0.4 heuristic-removal design; 3.2.2 introduced the safer mutation boundary.

On net48, chain-shape enrichment that cannot prevent AIA downloads is omitted. Signature verification uses cached URL data. CurrentUser enumeration by the SYSTEM service is scoped to its own context; it does not establish inventory of every interactive user's personal store.

## Purpose and attacker usability

A non-system certificate permitting code signing or all purposes is useful review context, particularly if newly installed or linked to suspicious execution. Windows' all-purposes display can mean no EKU restriction; it does not mean an attacker possesses the corresponding private key. Assess effective chain/application-policy restrictions, CA versus leaf role, private-key presence and access, installation provenance, and observed use. The absence of a local private key does not exclude use of a key held elsewhere.

The current guard does **not** implement this combined purpose/private-key/provenance classifier. Its trust-marker observation must not be described as that stronger assessment. Legitimate enterprise/private CAs and development signers exist; broad purpose alone must not become an automatic-delete rule. Conversely, a Windows-trusted signer or OS-rooted chain is not a runtime safety exemption for a process.

See [requirements](requirements.md), [threat model](THREAT_MODEL.md) and [Windows validation](OFFLINE_VALIDATION.md) for response boundaries and remaining validation.
