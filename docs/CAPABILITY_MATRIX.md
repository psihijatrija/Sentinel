# Detection and remediation coverage

This is an engineering scope inventory for 3.2.5, not a commercial-product parity claim. Vendor features vary and require independent comparative testing.

| Area | Current capability | Remaining work / limits |
| --- | --- | --- |
| DNS configuration | Passive IPv4/IPv6/effective resolver drift; explicit administrator profile repair, snapshots, read-back, rollback and explicit interrupted-operation recovery | New disposable Windows DNS job must pass; authenticated answers, DHCP/router diagnosis, profile overrides and enterprise policy coverage |
| Process containment | Authorized behavioral responses terminate a pinned, rescanned process tree and report refused/failed descendants | Continuous race/privilege testing; no kernel enforcement or guarantee against administrator attackers |
| Files and DLLs | Quarantine/containment outcomes distinguish verified effects, absent, deferred and failed files | Locked-module recovery and reinfection scenarios need continuing integration coverage; detection is not proof every file was removed |
| Firewall | Local/eligible local-GPO inbound reconciliation, approvals, rollback and effective-state reporting; endpoint external self-block | Domain GPO requires domain administration; see Windows validation checklist for reboot/interactive gaps |
| Certificates | Heuristics produce review findings; explicit thumbprint distrust can remediate with read-back | Trust-marker absence cannot safely authorize removal; no universal root-store reset |
| Browser, proxy, hosts, persistence | Existing monitors/hardening observe specific behaviors and settings | No unified administrator-approved recovery transaction with complete rollback for these areas |
| Ransomware | Behavioral detection and authorized process response | No general file decryption or guaranteed recovery of encrypted data; independent backups remain necessary |
| Wi-Fi/router | Local network telemetry and observations | No router firmware repair, router credential rotation, guaranteed weak-password assessment or remote device cleanup |
| Reputation and updates | Local behavioral/static/ML analysis, bundled/cached intelligence | Endpoint is offline; no live cloud reputation or automatic threat-report transport; intelligence can become stale |

## Next priorities

1. Complete native DNS validation using the new disposable Windows job. Explicit recovery now uses durable starting/target states and fresh administrator approval; legacy or unrelated states are refused. Continue SYSTEM-journal ACL, interactive UAC, real reboot/power-loss, IPv6-only and DHCP-change scenarios before claiming universal crash-safe restoration.
2. Build the same preview, administrator approval, protected snapshot, bounded action and verified receipt contract for hosts-file and proxy/PAC recovery. Preserve legitimate enterprise configuration and show unsupported policy scopes.
3. Add targeted browser and persistence recovery only where ownership and the intended restored state can be established. Avoid a blanket reset that destroys legitimate configuration.
4. Run an independent adversarial review of privileged IPC, repair snapshots, containment races and false positives, then publish a repeatable scenario-based coverage report. A passing unit suite does not establish commercial detection parity.

Encrypted DNS or active router diagnosis would require an explicit product-policy decision: current Sentinel endpoint operation intentionally makes no external probes. Installing this release does not change that policy.

In 3.2.5, the legacy RegistryMonitor proxy-change path is Tier2 LogOnly and no longer writes/deletes proxy values to restore startup observations. This does not add a manual proxy repair workflow or complete interactive-user/WinHTTP policy coverage.
