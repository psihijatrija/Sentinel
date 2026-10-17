# Sentinel legacy standalone threat-report proxy

**Endpoint status (3.2.3):** Sentinel no longer calls this Worker. Online reputation, reporting and evidence-mirror transports and the compiled client credential are removed; client settings cannot restore them. This source is retained as a separately deployed compatibility component, not a required endpoint service. Deployment/testing below applies only to that independent server. No live deployment is implied.

Cloudflare Worker that can receive signed requests from independently maintained clients and forwards them to threat intelligence platforms (MalwareBazaar, URLhaus, AbuseIPDB, VirusTotal) using server-side API keys.

**Version: 2.2.0** - authentication + nonce replay protection are mandatory. Durable rate limit runs **after** HMAC. `/report/hash` is an honest MalwareBazaar lookup (sample ingest still requires the file).

## Auth model (v2.0.8)

| Header | Required | Purpose |
|--------|----------|---------|
| `X-Sentinel-Timestamp` | Yes | Unix seconds; must be within 60 seconds |
| `X-Sentinel-Nonce` | Yes | 16+ hex chars; unique within the window (replay rejected) |
| `X-Sentinel-Signature` | Yes | Hex HMAC-SHA256 of `{timestamp}.{nonce}.{path}.{rawBody}` |

Signing key is the **server-side** `SENTINEL_SHARED_SECRET` (known only to independently authorized legacy clients; current Sentinel endpoints do not use it).
The secret is used **only** as the HMAC key and is **never** sent in a request header.
**v1.8.1:** Agents no longer send `X-Sentinel-Auth`.
**There is no client-supplied signing key.** Missing secret -> Worker returns 503.

Historical Sentinel clients used certificate-pinned HTTPS. This is not an active connection in 3.2.3.

## Free Tier Limits

- 100,000 requests/day (Cloudflare Workers free plan)
- Unauth flood cap ~120/IP/minute (in-memory, pre-HMAC)
- Authenticated cap ~30/IP/minute (in-memory) plus `RATE_LIMITER` binding **after** HMAC (see `wrangler.toml`)

## Setup

1. Create a free Cloudflare account at https://dash.cloudflare.com/sign-up
2. Install Wrangler CLI: `npm install -g wrangler`
3. Login: `wrangler login`
4. Set your account ID in `wrangler.toml`
5. Add secrets:

```bash
wrangler secret put SENTINEL_SHARED_SECRET   # required, >=16 chars
wrangler secret put MALWAREBAZAAR_KEY
wrangler secret put URLHAUS_TOKEN
wrangler secret put ABUSEIPDB_KEY
wrangler secret put VIRUSTOTAL_KEY
```

6. Deploy: `wrangler deploy`

## Current Sentinel integration

None. Do not configure `ProxyEndpoint` or `ProxySharedSecret` on 3.2.3: those compatibility properties remain disabled/null. The former `--set-config` instructions do not restore transport. Review any independently deployed Worker and its credentials separately.

## API Endpoints

- `POST /report/hash` - MalwareBazaar **lookup** (+ comment if the hash is already known; does not upload a sample)
- `POST /report/url` - URLhaus
- `POST /report/ip` - AbuseIPDB
- `POST /lookup/vt` - VirusTotal hash lookup
- `POST /lookup/mb` - MalwareBazaar hash lookup (**v2.7.3**). abuse.ch now requires an `Auth-Key` for all API access, so independent clients cannot query keyless; the Worker uses `MALWAREBAZAAR_KEY` and returns `{ success, verdict: "malicious" | "not_found" }` (fails closed to `not_found`, never `Safe`).
- `GET /health` - unauthenticated health (no secrets)
- `POST /report/evidence` - authenticated minimal evidence/checkpoint anchor; requires `EVIDENCE_STORE` KV

## Evidence anchors

Create a Cloudflare KV namespace using your authenticated Cloudflare tooling, then add
its real namespace ID to the deployed Worker configuration:

```toml
[[kv_namespaces]]
binding = "EVIDENCE_STORE"
id = "<your-real-namespace-id>"
```

No production namespace is created or deployed by local tests. The existing HMAC,
timestamp, nonce and rate-limit checks apply to `/report/evidence`. The endpoint accepts
the Sentinel `EvidenceSummary` JSON shape, requires a valid `ManifestSha256` and
`ReportId`, and validates optional `LedgerFile`/`LedgerSequence`/`LedgerHash` fields.
It stores only a hashed report ID, manifest hash and optional ledger checkpoint under
a content-addressed key for 90 days. Host/process names, raw evidence and indicators
are not persisted by this endpoint. A successful response contains the storage receipt;
missing or failed KV storage returns 503. This authenticates possession of the shared
key, not independent truth of the reported incident or protection from a Cloudflare
account administrator. Retain receipts/checkpoints independently when required.

All report bodies are capped at 64 KiB, including requests without a trustworthy
Content-Length. Run `npm test` for authentication, replay, validation, privacy and
storage-failure regression tests; these tests do not call external intelligence APIs.
