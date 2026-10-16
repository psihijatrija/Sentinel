import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHmac, randomBytes } from 'node:crypto';

const source = await readFile(new URL('../src/index.js', import.meta.url), 'utf8');
const worker = (await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'))).default;
const secret = randomBytes(32).toString('hex'); // Ephemeral test fixture, never a deployment credential.
const summary = () => ({
  ReportId: 'AUTO_fixture_9001', ManifestSha256: 'a'.repeat(64),
  LedgerFile: 'audit-chain-2026-10-15.jsonl', LedgerSequence: 2, LedgerHash: 'b'.repeat(64),
  Host: 'private-host', ProcessName: 'private-process', Urls: ['https://private.invalid/user']
});
function signed(body, path = '/report/evidence') {
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString('hex');
  const signature = createHmac('sha256', secret).update(`${timestamp}.${nonce}.${path}.${raw}`).digest('hex');
  return new Request('https://worker.invalid' + path, {
    method: 'POST', body: raw, headers: {
      'X-Sentinel-Timestamp': timestamp, 'X-Sentinel-Nonce': nonce,
      'X-Sentinel-Signature': signature, 'Content-Type': 'application/json'
    }
  });
}

test('health works without credentials; report fails closed without secret', async () => {
  const health = await worker.fetch(new Request('https://worker.invalid/health'), {});
  assert.equal(health.status, 200);
  assert.equal((await health.json()).authRequired, true);
  assert.equal((await worker.fetch(signed(summary()), {})).status, 503);
});

test('evidence storage acknowledges only a successful write and strips private fields', async () => {
  const writes = [];
  const response = await worker.fetch(signed(summary()), {
    SENTINEL_SHARED_SECRET: secret,
    EVIDENCE_STORE: { put: async (...args) => writes.push(args) }
  });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.match(result.receipt, /^evidence:v1:[a-f0-9]{64}$/);
  assert.equal(writes.length, 1);
  assert.equal(writes[0][0], result.receipt);
  assert.equal(writes[0][2].expirationTtl, 90 * 24 * 60 * 60);
  assert.doesNotMatch(writes[0][1], /private|AUTO_fixture/);
  assert.equal(JSON.parse(writes[0][1]).ledger.sequence, 2);
});

test('missing and failed storage return 503 rather than a success receipt', async () => {
  const missing = await worker.fetch(signed(summary()), { SENTINEL_SHARED_SECRET: secret });
  assert.equal(missing.status, 503);
  const failed = await worker.fetch(signed(summary()), {
    SENTINEL_SHARED_SECRET: secret, EVIDENCE_STORE: { put: async () => { throw new Error('offline'); } }
  });
  assert.equal(failed.status, 503);
  assert.equal((await failed.json()).receipt, undefined);
});

test('invalid HMAC never reaches storage or consumes the authenticated rate budget', async () => {
  let writes = 0, rateCalls = 0;
  const request = signed(summary());
  request.headers.set('X-Sentinel-Signature', '0'.repeat(64));
  const response = await worker.fetch(request, {
    SENTINEL_SHARED_SECRET: secret,
    EVIDENCE_STORE: { put: async () => writes++ },
    RATE_LIMITER: { limit: async () => { rateCalls++; return { success: true }; } }
  });
  assert.equal(response.status, 401);
  assert.equal(writes, 0);
  assert.equal(rateCalls, 0);
});

test('nonce replay cannot write a second anchor', async () => {
  let writes = 0;
  const request = signed(summary());
  const duplicate = request.clone();
  const env = { SENTINEL_SHARED_SECRET: secret, EVIDENCE_STORE: { put: async () => writes++ } };
  assert.equal((await worker.fetch(request, env)).status, 200);
  assert.equal((await worker.fetch(duplicate, env)).status, 401);
  assert.equal(writes, 1);
});

test('invalid checkpoint and missing manifest hash are rejected before persistence', async () => {
  let writes = 0;
  const env = { SENTINEL_SHARED_SECRET: secret, EVIDENCE_STORE: { put: async () => writes++ } };
  for (const change of [{ LedgerSequence: -1 }, { LedgerSequence: 2 ** 54 },
    { LedgerHash: 'invalid' }, { LedgerFile: '../audit-chain-2026-10-15.jsonl' }, { ManifestSha256: '' }]) {
    assert.equal((await worker.fetch(signed({ ...summary(), ...change }), env)).status, 400);
  }
  assert.equal(writes, 0);
});

test('body size is bounded independently of Content-Length', async () => {
  const request = signed('x'.repeat(65537));
  request.headers.set('Content-Length', '1');
  const response = await worker.fetch(request, { SENTINEL_SHARED_SECRET: secret });
  assert.equal(response.status, 413);
});

test('legacy endpoint validation still rejects an invalid hash', async () => {
  const response = await worker.fetch(signed({ type: 'hash', value: 'invalid' }, '/report/hash'), {
    SENTINEL_SHARED_SECRET: secret
  });
  assert.equal(response.status, 400);
});
