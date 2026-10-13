/**
 * Sentinel - Threat Report Proxy Worker (v2.1.7)
 *
 * Receives threat reports from Sentinel agents and forwards them to
 * abuse.ch (MalwareBazaar, URLhaus) using server-side API keys.
 *
 * SECURITY:
 *   - SENTINEL_SHARED_SECRET is REQUIRED (fail closed).
 *   - HMAC-SHA256 over `timestamp.nonce.path.body` using the shared secret
 *     as the key (never accept a client-provided signing key).
 *   - 60-second timestamp window (v2.0.8: was 5 minutes).
 *   - Server-side nonce replay cache (in-memory per isolate; CF Rate Limiting
 *     recommended as durable backstop).
 *   - No wildcard CORS (non-browser agents only).
 *
 * Endpoints:
 *   POST /report/hash    - Report a malicious hash to MalwareBazaar
 *   POST /report/url     - Report a malicious URL to URLhaus
 *   POST /report/ip      - Report a malicious IP to AbuseIPDB
 *   POST /lookup/vt      - Lookup a SHA-256 hash on VirusTotal (proxied)
 *   GET  /health         - Health check (unauthenticated)
 *
 * Deploy: wrangler deploy
 * Secrets: wrangler secret put SENTINEL_SHARED_SECRET
 *          wrangler secret put MALWAREBAZAAR_KEY
 *          wrangler secret put URLHAUS_TOKEN
 *          wrangler secret put ABUSEIPDB_KEY
 *          wrangler secret put VIRUSTOTAL_KEY
 */

// Per-isolate rate limit with sliding window.
// NOTE: Resets on cold start. Prefer Cloudflare Rate Limiting Rules in production.
const RATE_LIMIT_PER_MINUTE = 30;
const rateBuckets = new Map();

// v2.0.8: Nonce replay cache (timestamp.nonce -> expiry unix sec)
const MAX_NONCE_ENTRIES = 4096;
const usedNonces = new Map();
const TIMESTAMP_WINDOW_SEC = 60;

function checkRateLimit(ip, limit = RATE_LIMIT_PER_MINUTE) {
  const now = Math.floor(Date.now() / 1000);
  const window = Math.floor(now / 60);
  const key = `${ip}:${window}`;
  const count = rateBuckets.get(key) || 0;
  if (count >= limit) return false;
  rateBuckets.set(key, count + 1);
  if (rateBuckets.size > 5000) {
    for (const k of rateBuckets.keys()) {
      if (!k.endsWith(`:${window}`) && !k.endsWith(`:${window - 1}`)) {
        rateBuckets.delete(k);
      }
    }
  }
  return true;
}

function consumeNonce(nonce, ts) {
  // Format already validated by caller - just check replay and store
  const key = `${ts}:${nonce.toLowerCase()}`;
  if (usedNonces.has(key)) return false;
  usedNonces.set(key, ts + TIMESTAMP_WINDOW_SEC);

  // Prune expired
  if (usedNonces.size > 64) {
    const now = Math.floor(Date.now() / 1000);
    for (const [k, exp] of usedNonces.entries()) {
      if (exp < now) usedNonces.delete(k);
    }
  }
  // Hard cap
  if (usedNonces.size > MAX_NONCE_ENTRIES) {
    const keys = [...usedNonces.keys()].slice(0, usedNonces.size - MAX_NONCE_ENTRIES);
    for (const k of keys) usedNonces.delete(k);
  }
  return true;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // No CORS for browser abuse surface
    const corsHeaders = {
      'Access-Control-Allow-Origin': '',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Sentinel-Signature, X-Sentinel-Timestamp, X-Sentinel-Nonce',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    if (url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'ok',
        service: 'sentinel-threat-proxy',
        version: '2.1.8',
        timestamp: new Date().toISOString(),
        authRequired: true,
        nonceRequired: true,
        timestampWindowSec: TIMESTAMP_WINDOW_SEC
      }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
    }

    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'POST required' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    if (!env.SENTINEL_SHARED_SECRET || env.SENTINEL_SHARED_SECRET.length < 16) {
      return new Response(JSON.stringify({
        error: 'Service misconfigured: SENTINEL_SHARED_SECRET required'
      }), {
        status: 503,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    // Cheap unauthenticated flood guard (does not consume the authenticated budget).
    if (!checkRateLimit('unauth:' + clientIp, 120)) {
      return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
        status: 429,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const signature = request.headers.get('X-Sentinel-Signature');
    const timestamp = request.headers.get('X-Sentinel-Timestamp');
    const nonce = request.headers.get('X-Sentinel-Nonce');

    if (!signature || !timestamp || !nonce) {
      return new Response(JSON.stringify({
        error: 'Bad Request: Missing X-Sentinel-Signature, X-Sentinel-Timestamp, or X-Sentinel-Nonce'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const timestampVal = parseInt(timestamp, 10);
    const nowSec = Math.floor(Date.now() / 1000);
    if (isNaN(timestampVal) || Math.abs(nowSec - timestampVal) > TIMESTAMP_WINDOW_SEC) {
      return new Response(JSON.stringify({ error: 'Bad Request: Stale or invalid timestamp' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    // v2.1.7 RT-2026-M1 FIX: Validate nonce FORMAT only here (not consume).
    // Nonce is consumed AFTER HMAC verification to prevent DoS via pre-consumption.
    if (!nonce || typeof nonce !== 'string' || nonce.length < 16 || nonce.length > 64 || !/^[a-fA-F0-9]+$/.test(nonce)) {
      return new Response(JSON.stringify({ error: 'Bad Request: Invalid nonce format' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const rawBody = await request.text();

      // v2.0.8 payload: timestamp.nonce.path.body
      const signatureValid = await verifySignature(
        signature,
        env.SENTINEL_SHARED_SECRET,
        timestamp,
        nonce,
        url.pathname,
        rawBody
      );
      if (!signatureValid) {
        return new Response(JSON.stringify({ error: 'Unauthorized: HMAC signature verification failed' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // v2.1.7 RT-2026-M1 FIX: Consume nonce AFTER successful HMAC verification.
      // This prevents attackers from burning legitimate nonces with forged requests.
      if (!consumeNonce(nonce, timestampVal)) {
        return new Response(JSON.stringify({ error: 'Unauthorized: Replay detected' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // v2.2.0: durable CF rate limit AFTER HMAC so unauth traffic cannot burn the quota.
      try {
        if (env.RATE_LIMITER && typeof env.RATE_LIMITER.limit === 'function') {
          const rl = await env.RATE_LIMITER.limit({ key: clientIp });
          if (rl && rl.success === false) {
            return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
              status: 429,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }
        }
      } catch (_) { /* binding optional in local wrangler */ }

      if (!checkRateLimit('auth:' + clientIp, RATE_LIMIT_PER_MINUTE)) {
        return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
          status: 429,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const body = JSON.parse(rawBody);

      if (!body.type || !body.value) {
        return new Response(JSON.stringify({ error: 'Missing type or value' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // v2.1.7 RT-2026-M4: Input validation per endpoint BEFORE forwarding to upstream APIs
      const validationError = validateReportInput(url.pathname, body);
      if (validationError) {
        return new Response(JSON.stringify({ error: validationError }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      let result;
      switch (url.pathname) {
        case '/report/hash':
          result = await reportHash(body, env);
          break;
        case '/report/url':
          result = await reportUrl(body, env);
          break;
        case '/report/ip':
          result = await reportIp(body, env);
          break;
        case '/lookup/vt':
          result = await lookupVirusTotal(body, env);
          break;
        case '/lookup/mb':
          result = await lookupMalwareBazaar(body, env);
          break;
        default:
          return new Response(JSON.stringify({ error: 'Unknown endpoint' }), {
            status: 404,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
      }

      return new Response(JSON.stringify(result), {
        status: result.success ? 200 : 502,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    } catch (err) {
      // v2.1.7: Don't leak internal error details to clients
      return new Response(JSON.stringify({ error: 'Invalid request' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
};

// v2.1.7 RT-2026-M4: Input validation for report payloads before forwarding to upstream APIs.
// Prevents authenticated clients from abusing the proxy to poison upstream threat intel databases.
function validateReportInput(pathname, body) {
  switch (pathname) {
    case '/report/hash': {
      const v = body.value;
      // Must be a valid MD5 (32), SHA1 (40), or SHA-256 (64) hex hash
      if (!/^[a-fA-F0-9]{32}$/.test(v) && !/^[a-fA-F0-9]{40}$/.test(v) && !/^[a-fA-F0-9]{64}$/.test(v)) {
        return 'Invalid hash format: must be MD5 (32 hex), SHA-1 (40 hex), or SHA-256 (64 hex)';
      }
      if (body.comment && (typeof body.comment !== 'string' || body.comment.length > 512)) {
        return 'Comment must be a string of 512 characters or fewer';
      }
      if (body.tags && (!Array.isArray(body.tags) || body.tags.length > 10 || body.tags.some(t => typeof t !== 'string' || t.length > 64))) {
        return 'Tags must be an array of up to 10 strings, each 64 chars max';
      }
      return null;
    }
    case '/report/url': {
      const v = body.value;
      if (typeof v !== 'string' || v.length > 2048) {
        return 'URL must be a string of 2048 characters or fewer';
      }
      // Must start with http:// or https://
      if (!/^https?:\/\/.+/i.test(v)) {
        return 'URL must use http:// or https:// scheme';
      }
      // Block private/internal IPs in URL
      if (/^https?:\/\/(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|localhost|0\.0\.0\.0|\[::1\])/i.test(v)) {
        return 'Cannot report private/internal URLs';
      }
      return null;
    }
    case '/report/ip': {
      const v = body.value;
      // IPv4 validation
      const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
      if (ipv4) {
        const octets = [parseInt(ipv4[1]), parseInt(ipv4[2]), parseInt(ipv4[3]), parseInt(ipv4[4])];
        if (octets.some(o => o > 255)) return 'Invalid IPv4 address';
        // Block RFC1918, loopback, link-local, multicast
        if (octets[0] === 10 || octets[0] === 127 || octets[0] === 0) return 'Cannot report private/reserved IPs';
        if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return 'Cannot report private IPs';
        if (octets[0] === 192 && octets[1] === 168) return 'Cannot report private IPs';
        if (octets[0] === 169 && octets[1] === 254) return 'Cannot report link-local IPs';
        if (octets[0] >= 224) return 'Cannot report multicast/reserved IPs';
        return null;
      }
      // Basic IPv6 check (colon-separated hex groups)
      if (/^[a-fA-F0-9:]+$/.test(v) && v.includes(':') && v.length <= 45) {
        if (v === '::1' || v.startsWith('fe80:') || v.startsWith('fc') || v.startsWith('fd')) {
          return 'Cannot report private/link-local IPv6 addresses';
        }
        return null;
      }
      return 'Invalid IP address format (must be valid IPv4 or IPv6)';
    }
    case '/lookup/vt':
      // Already validated in lookupVirusTotal - no extra check needed
      return null;
    case '/lookup/mb':
      // Already validated in lookupMalwareBazaar - no extra check needed
      return null;
    default:
      return null;
  }
}

async function reportHash(body, env) {
  if (!env.MALWAREBAZAAR_KEY) {
    return { success: false, error: 'MalwareBazaar key not configured' };
  }

  // Honest: MalwareBazaar ingest requires the sample bytes. This endpoint looks up
  // the hash and, if known, adds a comment. It does not pretend to submit a new sample.
  const formData = new URLSearchParams();
  formData.append('query', 'get_info');
  formData.append('hash', body.value);

  const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: { 'Auth-Key': env.MALWAREBAZAAR_KEY },
    body: formData
  });

  const text = await response.text();
  let known = false;
  try {
    const parsed = JSON.parse(text);
    known = parsed && parsed.query_status === 'ok';
  } catch (_) { /* non-JSON upstream */ }

  if (known) {
    const comment = new URLSearchParams();
    comment.append('query', 'add_comment');
    comment.append('hash', body.value);
    comment.append('comment', body.comment || 'Reported by Sentinel');
    await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Auth-Key': env.MALWAREBAZAAR_KEY },
      body: comment
    });
    return { success: true, action: 'commented_existing_sample', upstream: text.substring(0, 500) };
  }

  return {
    success: true,
    submitted: false,
    action: 'lookup_only',
    reason: 'MalwareBazaar requires the sample file to ingest a new hash',
    upstream: text.substring(0, 500)
  };
}

async function reportUrl(body, env) {
  if (!env.URLHAUS_TOKEN) {
    return { success: false, error: 'URLhaus token not configured' };
  }

  const formData = new URLSearchParams();
  formData.append('token', env.URLHAUS_TOKEN);
  formData.append('anonymous', '0');
  formData.append('submission', JSON.stringify([{
    url: body.value,
    threat: body.threat || 'malware_download',
    tags: body.tags || ['sentinel']
  }]));

  const response = await fetch('https://urlhaus-api.abuse.ch/v1/urls/add/', {
    method: 'POST',
    body: formData
  });

  const text = await response.text();
  return { success: response.ok, upstream: text.substring(0, 500) };
}

async function reportIp(body, env) {
  if (!env.ABUSEIPDB_KEY) {
    return { success: false, error: 'AbuseIPDB key not configured' };
  }

  const response = await fetch('https://api.abuseipdb.com/api/v2/report', {
    method: 'POST',
    headers: {
      'Key': env.ABUSEIPDB_KEY,
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      ip: body.value,
      categories: (body.categories || [14]).join(','),
      comment: body.comment || 'Malicious activity detected by Sentinel',
      timestamp: new Date().toISOString()
    })
  });

  const text = await response.text();
  return { success: response.ok, upstream: text.substring(0, 500) };
}

async function lookupVirusTotal(body, env) {
  if (!env.VIRUSTOTAL_KEY) {
    return { success: false, error: 'VirusTotal API key not configured' };
  }

  const hash = body.value;
  if (!hash || hash.length !== 64 || !/^[a-fA-F0-9]+$/.test(hash)) {
    return { success: false, error: 'Invalid SHA-256 hash' };
  }

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      method: 'GET',
      headers: {
        'x-apikey': env.VIRUSTOTAL_KEY,
        'Accept': 'application/json'
      }
    });

    if (response.status === 404) {
      return { success: true, verdict: 'not_found', detections: 0, engines: 0 };
    }

    if (!response.ok) {
      return { success: false, error: `VT API returned ${response.status}` };
    }

    const data = await response.json();
    const stats = data?.data?.attributes?.last_analysis_stats;
    if (!stats) {
      return { success: true, verdict: 'not_found', detections: 0, engines: 0 };
    }

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const undetected = stats.undetected || 0;
    const harmless = stats.harmless || 0;
    const totalEngines = malicious + suspicious + undetected + harmless;
    const detectionCount = malicious + suspicious;
    const detectionRate = totalEngines > 0 ? detectionCount / totalEngines : 0;

    let verdict = 'safe';
    if (detectionRate >= 0.25) verdict = 'malicious';
    else if (detectionRate >= 0.10) verdict = 'suspicious';
    else if (detectionCount >= 3) verdict = 'suspicious';

    return {
      success: true,
      verdict,
      detections: detectionCount,
      engines: totalEngines,
      detectionRate: Math.round(detectionRate * 100) / 100
    };
  } catch (err) {
    return { success: false, error: 'VT lookup failed' };
  }
}

/**
 * v2.7.3: Proxied MalwareBazaar hash lookup. abuse.ch now requires an Auth-Key for ALL API
 * access, so the Sentinel agent cannot query keyless (it 401s). The Worker holds the key
 * (MALWAREBAZAAR_KEY, the same secret /report/hash uses) and returns a normalized verdict the
 * client parses: { success:true, verdict:"malicious"|"not_found" }. Fails closed to not_found on
 * any upstream/transport error so a failure is never treated as Safe (client maps -> Unknown).
 */
async function lookupMalwareBazaar(body, env) {
  if (!env.MALWAREBAZAAR_KEY) {
    return { success: false, error: 'MalwareBazaar key not configured' };
  }

  const hash = body.value;
  // MalwareBazaar accepts MD5/SHA-1/SHA-256; the Sentinel client sends SHA-256.
  if (!hash || hash.length !== 64 || !/^[a-fA-F0-9]+$/.test(hash)) {
    return { success: false, error: 'Invalid SHA-256 hash' };
  }

  try {
    const formData = new URLSearchParams();
    formData.append('query', 'get_info');
    formData.append('hash', hash);

    const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Auth-Key': env.MALWAREBAZAAR_KEY },
      body: formData
    });

    if (!response.ok) {
      // Includes 401 if the key is bad. Fail closed -> not_found (client maps to Unknown).
      return { success: true, verdict: 'not_found', upstream: response.status };
    }

    const text = await response.text();
    let status = null;
    try {
      const parsed = JSON.parse(text);
      status = parsed && parsed.query_status;
    } catch (_) { /* non-JSON upstream */ }

    // A present sample record = known-malicious. Anything else (hash_not_found, ...) = no signal.
    const verdict = status === 'ok' ? 'malicious' : 'not_found';
    return { success: true, verdict };
  } catch (err) {
    return { success: true, verdict: 'not_found', error: 'upstream_unreachable' };
  }
}

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Verify HMAC-SHA256(secret, `${timestamp}.${nonce}.${path}.${body}`) against hex signature.
 */
async function verifySignature(signatureHex, sharedSecret, timestamp, nonce, path, bodyJson) {
  try {
    const encoder = new TextEncoder();
    const keyBytes = encoder.encode(sharedSecret);
    const sigBytes = hexToBytes(signatureHex);
    if (sigBytes.length !== 32) return false;

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const payloadStr = `${timestamp}.${nonce}.${path}.${bodyJson}`;
    const payloadBytes = encoder.encode(payloadStr);

    return await crypto.subtle.verify('HMAC', cryptoKey, sigBytes, payloadBytes);
  } catch {
    return false;
  }
}
