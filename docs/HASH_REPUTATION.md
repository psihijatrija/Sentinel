# Hash reputation sources

`HashReputationService` resolves a file's reputation from three independent
threat-intel sources. The design goal is **no API key in the repo** while still
using all three. Each source can only push a verdict in one direction; the
service combines them conservatively and **never returns `Safe` on failure**.

## Sources and what each can say

| Source | Transport | Key required? | Can say `Safe` | Can say `Unsafe` |
|--------|-----------|---------------|:--------------:|:----------------:|
| CIRCL hashlookup | HTTPS (SPKI-pinned), SHA-256 | No (keyless) | Yes (trust > 60) | No |
| Team Cymru MHR | DNS, SHA-1 / MD5 only | No (keyless) | No | Yes (known-bad) |
| MalwareBazaar (abuse.ch) | HTTPS via proxy, SHA-256 | Auth-Key held **server-side** | No | Yes (sample present) |

## Evaluation order (in `FetchReputationFromApis`)

1. **CIRCL** — a trust score above 60 short-circuits to `Safe`.
2. **Team Cymru MHR** — only queried when a SHA-1 is supplied (MHR does not
   accept SHA-256). A resolvable `{sha1}.malware.hash.cymru.com` record →
   `Unsafe`. `NXDOMAIN` / timeout / error → no signal.
3. **MalwareBazaar** — a sample hit → `Unsafe`; not-found / error → no signal.

Anything not resolved to `Safe`/`Unsafe` is `Unknown`. Only non-`Unknown`
verdicts are cached (keyed by SHA-256).

## MalwareBazaar key handling (why the proxy)

As of the abuse.ch policy change, **every** MalwareBazaar API call requires an
`Auth-Key` header; a keyless request returns HTTP `401`. To keep the source
active without committing a key:

- **Preferred path** — when `ProxyEndpoint` + a valid `ProxySharedSecret` are
  configured, the lookup goes to the Cloudflare Worker at `POST /lookup/mb` as
  an HMAC-signed, replay-protected, TLS-pinned request (same pattern as the
  existing `/lookup/vt` VirusTotal path). The Worker holds the abuse.ch
  `Auth-Key` server-side.
- **Fallback path** — a direct call to `mb-api.abuse.ch` is attempted **only**
  when a local `MalwareBazaarApiKey` is explicitly set. A keyless direct call
  is skipped entirely because it would always `401`.
- Any 401 / error / missing config fails closed to `Unknown` — never `Safe`.

### Worker requirement

The proxy implements `POST /lookup/mb` (in `worker/src/index.js`) accepting
`{ "type": "hash", "value": "<sha256>" }` and returning the normalized
`{ "success": true, "verdict": "malicious" | "not_found" }`. The client also
tolerates a raw abuse.ch `query_status` body. The endpoint must be deployed
(`wrangler deploy`) and the Worker's `MALWAREBAZAAR_KEY` secret set for the
MalwareBazaar source to return signal; until then it fails closed to `Unknown`.

## Supplying SHA-1 for MHR

Callers that have the file on disk compute SHA-1 alongside SHA-256 and pass it
via the optional `sha1:` parameter of `GetVerdictAsync`
(e.g. `EphemeralProcessMonitor`). Callers that only have a SHA-256 keep working
unchanged — MHR is simply skipped for them.
