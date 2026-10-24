# Standalone protection scope — 3.4.1

Sentinel's product target is standalone Windows endpoint protection within userland.
Another antivirus is optional, not an assumed source of detection or containment.
This target is not a claim that the current release replaces every antivirus feature.
The inventory below separates shipped mechanisms from gaps; independent comparative
malware and false-positive testing is still required before claiming product parity.

| Area | Shipped mechanisms | Gaps and boundaries |
| --- | --- | --- |
| Antivirus / EPP | Local file watching, fixed/removable-volume scanning, static/ML context, file quarantine for authorized responses | File verdict scanning is observe-only. Core hash reputation returns **Unknown**; no maintained comprehensive signature engine, archive unpacking coverage, or guaranteed before-execution interception. These are standalone protection gaps, even when no other antivirus is installed. |
| NanoAV companion | Independently packaged original engine, online feeds and aggressive original responses; Sentinel coexistence changes only | Its original heuristics, cache/deletion defects and false positives remain. Presence of quarantined files does not prove accurate detection, removal or antivirus parity. See [NanoAV](NANOAV.md). |
| Behavioral execution / scripts | ETW/process telemetry, specific socket-shell rules, script analysis and multi-signal correlation | Bounded supported patterns and available telemetry; no promise to recognize every language, obfuscator, LOLBin or zero-day. Polling can miss short-lived processes. |
| Injection / fileless payloads | Module identity checks, injection candidates and bounded private executable PE inspection, including RX sections with readonly headers | PE-free shellcode, erased headers, inaccessible/protected processes and inspection budgets limit coverage. Candidate inspection is not universal memory inspection. See [loader scope](LOADER_PAYLOAD_COVERAGE.md). |
| Credentials / session theft | Kernel-File credential-store read attribution plus independent high-confidence remote-control or inspected-payload corroboration | A read alone is LogOnly. Missing/reused process identity cannot authorize the chain. No retrieval or revocation of sessions already stolen, and no remote identity-provider monitoring. |
| Process response | Authorized Tier1 process/tree termination with pinned lifetime, descendant rescan and verified exit receipts | Permissions and races can prevent containment. Injected-victim response preserves backing files and ancestors. No kernel enforcement against an administrator or malicious driver. |
| Network / C2 | DNS, socket/TCP observations, behavioral correlation; local/eligible local-GPO firewall management, owned modern port-block filters and verified response effects | TCP polling is not packet capture, TLS decryption, universal MitM prevention or relay identification. Endpoint reuse and events between polls limit attribution. No network-appliance or router cleanup. |
| Persistence | Specific startup/service/task observations; cleanup of exact HKLM Run/RunOnce direct launches of a verified quarantined payload | No blanket service/task/WMI/browser reset. Wrappers, environment-expanded targets, HKCU and alternate registry views are not covered by this cleanup. Recheck/read-back reduces races but registry compare-and-delete is not atomic. |
| Ransomware | Behavioral signals and authorized containment | No universal pre-write protection, decryption or restoration of already encrypted data. Recovery needs independent backups. |
| Credential/driver hardening | Registry configuration checks; runtime VBS, individual Credential Guard/HVCI states, query-only LSASS process protection; vulnerable-driver blocklist configuration | Windows supplies these OS controls. Configuration does not prove enforcement; provider/access failures are explicit. No userland kernel-driver exploit prevention guarantee. Credential Guard primarily concerns domain authentication, not local passwords or browser sessions. |
| Defender integration | Optional Defender runtime observations and ASR policy management when available | Defender ASR is a Defender capability, not Sentinel's own detector. Sentinel's own engines must function without it; no ASR credit on systems without an enforcing Defender provider. |
| Exploit / patch management | Separate online ExploitShield matches feed CVEs to applicable vendor fixes through WUA | Vendor fixes, provider access, applicability and reboot requirements apply. It does not execute PoCs or stop all zero-days. |
| DNS / certificate recovery | Explicit administrator-authorized DNS snapshot/repair/read-back/restore; explicit certificate distrust policy | No universal root-store reset, arbitrary proxy/browser cleanup or router repair. See [DNS repair](DNS_REPAIR.md). |
| Tamper resistance / evidence | Visible service, protected IPC, local audit and incident evidence | Userland cannot guarantee survival against SYSTEM/kernel compromise. No self-hiding or kernel self-defense. |
| Identity / social engineering | Local authentication/event observations where auditing is available | No domain-wide ticket validation, cloud token revocation, phone/SMS scam prevention or guaranteed MFA protection. These need external authority or infrastructure. |

## Standalone completion priorities

1. Build and independently validate a maintained file-detection pipeline: authenticated
   intelligence updates, explicit freshness/degradation, real sample and clean-software
   corpora, archive/script/packed-file coverage and measured false positives. Existing
   Unknown reputation must never become a clean verdict.
2. Establish a userland scanning/response contract for confirmed malicious files. The
   current observe-only file-verdict and behavioral kill policies do not supply a full
   preventive antivirus. A userland watcher cannot promise the kernel-level before-open
   enforcement offered by a filesystem minifilter.
3. Extend process/network lifetime attribution, credential-read coverage and payload
   inspection using repeatable benign/adversarial fixtures. Measure detection, verified
   response, latency, resource cost and legitimate-application compatibility separately.
4. Extend narrowly attributed persistence and browser/proxy recovery with durable
   snapshots and verified receipts. Preserve legitimate startup and enterprise settings.
5. Validate installation, upgrade, reboot, unavailable providers and normal operation
   on Windows **with Defender disabled/absent as well as enabled**. The current native
   CI fixtures are narrower than that acceptance matrix.

There is no finite “all other products” feature set. Kernel interception, hypervisor
isolation and remote domain/cloud enforcement cannot be implemented solely by a local
userland agent. Windows security features can be inspected or configured where supported,
but must not be advertised as Sentinel-owned implementations.

## Validation evidence

Portable tests cover rule boundaries, PID reuse, exact persistence attribution and runtime
status interpretation. Windows CI additionally requires seven native fixtures: readonly/RX
memory inspection, clean Qt-module policy, owned-process containment with unrelated-process
survival, temporary registry-value cleanup, runtime-provider reporting, owned modern port-rule read-back and filtered ETW process-start delivery. The process
fixture uses synthetic evidence and a harmless sleeper; it does not prove live ETW
credential attribution or protection against a real malware sample. A passing fixture is
not comparative antivirus certification. Native results must be read from CI artifacts;
Linux cross-builds cannot establish Windows execution success.


3.4.1 log-derived fixes and native acceptance limits are recorded in
[LOG_REMEDIATION_3.4.1.md](LOG_REMEDIATION_3.4.1.md). Native ETW filtering or extra
buffers cannot grant protected-provider access or guarantee loss-free collection.
