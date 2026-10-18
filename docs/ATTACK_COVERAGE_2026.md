# Windows attack coverage and validation: 3.3.0

Sentinel is a userland Windows EDR. No claim of protection against every 2026 attack,
commercial detection parity, or guaranteed prevention before credential theft is made.
This release strengthens specific input paths used by the existing detection pipeline.

## Added coverage

Kernel-File NameCreate/NameDelete v0 maps sensitive paths to FileKey values; Read v0/v1
resolves those values using the event header's pointer width. Browser Login Data,
Cookies, Firefox key4.db/logins.json, Local State, Discord stable/canary/PTB LevelDB
.ldb/.log stores, AWS credentials, Git credentials and selected SSH private keys are
included. Source schema: [Kernel-File manifest](https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-18990/Microsoft-Windows-Kernel-File.xml).

Only sensitive names are cached. Both maps have 4,096-entry bounds; saturation clears
the relevant map. Names expire after two minutes; matching reads are deduplicated for
20 seconds per PID/FileKey. Unknown schemas, missing names, truncated payloads and
system/unattributed PIDs are ignored. No file content or private key bytes are read.
Normal reads by browsers, backups and security tools are expected and remain Tier2
LogOnly. Process names never exempt the ETW read rule. An independent, high-confidence
Tier1 C2 signal is required for the infostealer composite; ordinary outbound activity
and low-confidence/weak network observations cannot complete that composite. There is
no upload-volume minimum on this chain, but independent C2 detection is still required.
A read event records an I/O request, not proof that data was successfully extracted.

PowerShell 4104 v1 is decoded as MessageNumber, MessageTotal, ScriptBlockText,
ScriptBlockId, Path. The old decoder treated binary counters as text and could discard
the event. Each bounded ETW fragment is now evaluated by existing process-command rules
without an additional 8,192-character cutoff. Fragment counters are checked; fragments
are not concatenated. Source schema: [PowerShell manifest](https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-18990/Microsoft-Windows-PowerShell.xml).

The fallback write/create watcher now remains active until shutdown instead of
returning a completed background-service task immediately. Its ownership filter no
longer exempts a process merely because it calls itself a browser or has any signature.
Known owner names also require signature verification. This remains a heuristic,
not proof of ownership or a general read-interception mechanism.

## Remaining limits

- Native Windows ETW delivery, PID attribution, provider availability, dropped events,
  overhead under heavy I/O and time-to-containment need live scenario measurements.
  Payload regression tests do not establish those properties.
- Reads before name discovery, after expiry, during cache saturation, via unsupported
  schemas or without an attributed PID may be missed. File mappings and memory theft
  are not guaranteed to generate these file-read events. Reads are observed after the
  I/O begins; this is not a synchronous access-control barrier.
- Script logging must be available. Disabled logging, other interpreters, obfuscation,
  split-fragment patterns and missing events can evade these script-text rules.
- Low-volume theft with no recognized C2 behavior remains a gap. Nothing here guarantees
  that containment happens before an attacker uploads credentials or deletes a payload.
- Browser phishing, QR-login abuse, OAuth consent, malicious extensions and account
  takeover require separate browser/account defenses. Sentinel cannot revoke remote
  sessions, reverse fraud, reset every compromised setting, or repair router firmware.
- OS/browser vulnerabilities require security updates. Userland telemetry is not a
  substitute for OS patching, credential isolation, MFA and independent backups.

## Validation record

Windows Framework CI and native scenario validation are distinct from Linux
cross-build/portable tests.

- Full solution Release cross-build with .NET SDK 10.0.402: passed, zero warnings/errors.
- New raw-payload and read-to-correlation regressions: 21 passed against the built
  production Core assembly in a temporary .NET 10 host. This is not Windows Framework
  or live ETW execution.
- Existing response-policy regressions: 15 passed in the same temporary host (36
  portable tests total).
- Existing dashboard tests: 16 passed. Existing standalone Worker tests: 8 passed.
- Full .NET Framework and live native Windows checks require Windows CI. No detection
  rate, latency bound or guaranteed before-theft prevention result is claimed.
