# Offline hash reputation (3.2.3)

`HashReputationService` is a compatibility facade that returns `Unknown`. It makes no HTTP or DNS requests, reads no legacy online reputation cache and grants no verdict to synthetic test hashes. Cancellation is still honored.

CIRCL, Team Cymru MHR, MalwareBazaar and VirusTotal queries have been removed. There is no supported client API-key or Worker configuration that restores them. Legacy encrypted settings cannot enable reporting or reputation transports.

`FileReputationEngine` retains local static PE, signer and optional ML context. The external-hash contribution is a neutral Unknown prior, and local composite results use the `filerepo-offline-v1` cache namespace so old online results cannot supply trust. File identity/reputation alone is not behavioral kill authority.

Bundled indicators and local/cached intelligence can become stale. Missing data is missing coverage, not a clean verdict. Supply intelligence through a trusted local update; Sentinel does not download feeds.

The retained [Worker](../worker/README.md) is a separate legacy server component. Deploying it does not reconnect the endpoint. For firewall enforcement, privilege boundaries and measured coverage, see [design](design.md) and [Windows validation](OFFLINE_VALIDATION.md).
