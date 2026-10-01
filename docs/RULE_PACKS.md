# Sentinel Rule Packs (v2.2.0)

RSA-SHA256 signed packs. HMAC packs are rejected. External `rulepack_pubkey.xml` is ignored (embedded public key only).

Signed correlation rule packs extend multi-signal detection **without recompiling** Sentinel.

## Location

| Path | Purpose |
|------|---------|
| `%ProgramData%\Sentinel\rules\packs\*.pack.json` | Runtime packs (preferred) |
| `{installDir}\rules\packs\*.pack.json` | Bundled packs |

## Format

```json
{
  "name": "example-terminal",
  "version": "1.0",
  "rules": [
    {
      "name": "Credential + Beacon",
      "minSignals": 2,
      "requiredFragments": ["LSASS", "Beacon"],
      "confidence": 0.93,
      "evidence": "Credential access with C2-like network",
      "reasoning": "Two independent fragments on one PID within the correlation window.",
      "attackTechniques": ["T1003.001", "T1071"]
    }
  ],
  "signature": "<base64 RSA-SHA256 signature>"
}
```

Legacy `"hmac"` fields are **rejected** (v2.0.4+). Packs must be re-signed with RSA.

## Signing (RSA-SHA256, offline private key)

v2.0.4+ uses **asymmetric** signatures. Only the public key is embedded in Sentinel.
The private key never ships to endpoints.

1. Build the JSON **without** the `signature` field (canonical object property order as written).
2. Sign the UTF-8 bytes with RSA-SHA256 (PKCS#1 v1.5 padding).
3. Add `"signature": "<base64>"` to the pack file.

```powershell
# Offline signing tool (private key never on endpoints)
# Example conceptual flow - use your HSM / secure signer in production:
$payload = [IO.File]::ReadAllText("pack.unsigned.json")
# Sign with offline RSA private key -> base64 -> write pack with signature field
```

### Trust root (v2.0.8)

- Verification uses the **embedded** RSA public key only.
- `%ProgramData%\Sentinel\Secure\rulepack_pubkey.xml` is **ignored** if present
  (prevents admin-writable trust-root swap).
- Key rotation requires a product update that ships a new embedded public key.

## Semantics

- Each rule becomes an `ICorrelationRule` (`FragmentCorrelationRule`).
- All `requiredFragments` must appear (case-insensitive substring) in **distinct** rule names already buffered for the same PID.
- Match emits a chain-confirmed composite: `Rule Pack: {name}`.
- Still subject to `ObserveUntilChain` / `ResponsePolicy` / product posture.

## Security notes

- SYSTEM on the endpoint **cannot** forge packs without the offline private key.
- Packs never disable ActiveResponse or product posture.
- Fail-closed: missing/invalid signature -> pack rejected and logged.
