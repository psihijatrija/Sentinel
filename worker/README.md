# Sentinel Threat Report Proxy

Cloudflare Worker that receives threat reports from Sentinel agents and forwards them to threat intelligence platforms (MalwareBazaar, URLhaus, AbuseIPDB, VirusTotal) using server-side API keys.

**Version: 2.2.0** - authentication + nonce replay protection are mandatory. Durable rate limit runs **after** HMAC. `/report/hash` is an honest MalwareBazaar lookup (sample ingest still requires the file).

## Auth model (v2.0.8)

| Header | Required | Purpose |
|--------|----------|---------|
| `X-Sentinel-Timestamp` | Yes | Unix seconds; must be within 60 seconds |
| `X-Sentinel-Nonce` | Yes | 16+ hex chars; unique within the window (replay rejected) |
| `X-Sentinel-Signature` | Yes | Hex HMAC-SHA256 of `{timestamp}.{nonce}.{path}.{rawBody}` |

Signing key is the **server-side** `SENTINEL_SHARED_SECRET` (also configured on agents as `ThreatReporting:ProxySharedSecret` via encrypted config store).  
The secret is used **only** as the HMAC key and is **never** sent in a request header.  
**v1.8.1:** Agents no longer send `X-Sentinel-Auth`.  
**There is no client-supplied signing key.** Missing secret -> Worker returns 503.

Agents use certificate-pinned HTTPS to the Worker (true SPKI + rotation-safe pin candidates).

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

## Sentinel Integration

```powershell
# Production (DPAPI store):
Sentinel.Service.exe --set-config ProxySharedSecret=your-long-unique-secret ProxyEndpoint=https://your-worker.workers.dev
```

If `ProxySharedSecret` is null/short, agents **skip** reporting and VT proxy lookups (fail closed).

## API Endpoints

- `POST /report/hash` - MalwareBazaar **lookup** (+ comment if the hash is already known; does not upload a sample)
- `POST /report/url` - URLhaus
- `POST /report/ip` - AbuseIPDB
- `POST /lookup/vt` - VirusTotal hash lookup
- `POST /lookup/mb` - MalwareBazaar hash lookup (**v2.7.3**). abuse.ch now requires an `Auth-Key` for all API access, so agents cannot query keyless; the Worker uses `MALWAREBAZAAR_KEY` and returns `{ success, verdict: "malicious" | "not_found" }` (fails closed to `not_found`, never `Safe`).
- `GET /health` - unauthenticated health (no secrets)
