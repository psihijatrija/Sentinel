# DNS inspection and repair

Sentinel 3.2.4 introduced administrator-approved local DNS configuration repair. It does not establish that an Avast finding is correct, authenticate DNS answers, or certify a router as clean.

## Use

1. Open the dashboard's **Scan** page and select **Inspect DNS**.
2. Select a connected, unmanaged Ethernet or Wi-Fi adapter. Review its IPv4/IPv6 static settings, effective resolver addresses and eligibility details. Empty static settings mean automatic configuration.
3. Choose Quad9, Cloudflare or Google. The confirmation shows the actual IPv4 and IPv6 addresses. Choose the provider deliberately: overriding ISP/router DNS can affect local names, filtering and connectivity.
4. Approve repair and accept Windows UAC. The normal Agent remains a standard-user process. A short-lived elevated Service executable forwards the fixed operation to the running SYSTEM service.
5. Refresh inspection and read the recorded outcome. **Verified** means the selected adapter's static and effective resolver addresses matched and the local DNS cache was flushed. It does not mean a test website resolved correctly or interception is impossible.
6. If inspection shows an interrupted transaction created by 3.2.5 or later, select it under **Recover interrupted DNS operation** and review its original settings. Fresh inspection and UAC approval are required. Recovery refuses unrelated static settings, changed protocol support or a newer transaction. It restores the original snapshot; it does not certify those settings as safe.
7. To undo a verified repair, select its saved transaction and approve restoration. The previous static settings, including automatic mode, are restored and read back. Restoration does not establish that those previous settings were safe.

Profiles: Quad9 `9.9.9.9`, `149.112.112.112`, `2620:fe::fe`, `2620:fe::9`; Cloudflare `1.1.1.1`, `1.0.0.1`, `2606:4700:4700::1111`, `2606:4700:4700::1001`; Google `8.8.8.8`, `8.8.4.4`, `2001:4860:4860::8888`, `2001:4860:4860::8844`. Only enabled address families are changed. Sentinel makes no external DNS/probe requests; these settings govern subsequent OS/application resolution.

## Safeguards and outcomes

- Inspection is passive. IPv4, IPv6 and DHCP-derived effective resolver changes produce Tier2 LogOnly observations, never automatic repair authority. Startup settings are observations, not trusted recovery values. The last verified profile is compared with current configuration on inspection; drift does not automatically reapply it.
- Requests bind the adapter GUID to a configuration fingerprint. Stale previews, changed post-repair state, unavailable APIs, incomplete inspection, domain-joined machines, detected NRPT/resolver-assignment policy and known VPN/virtual adapters are refused. This conservative scope is not a complete inventory of every enterprise management system.
- HTTP authentication and CSRF checks precede UAC. The service checks the actual named-pipe client's administrator token, in addition to existing IPC authentication. Browser possession of the dashboard token alone cannot approve DNS mutation. No arbitrary command or resolver address is accepted.
- Before mutation, the service saves a durable snapshot under `%ProgramData%\Sentinel\DnsRepair` and requires acceptance of a `dns_repair_before` audit event. Snapshots are restricted to SYSTEM writes and administrator reads. Results and observed changes join the local audit chain.
- Configuration mismatch, cancellation, cache failure or journal failure triggers bounded rollback and read-back. **Failed**, **Refused**, and **PartiallyCompleted** are distinct from Verified; failed rollback remains visible. Final audit failure also prevents a fully successful receipt.
- The journal holds at most 128 records. An administrator must archive records before further changes when full. In 3.2.5, new transactions persist both the intended target and starting state before mutation. Prepared/RestorePrepared/RecoveryPrepared/RecoveryRequired/RollbackFailed transactions can be explicitly recovered when current static settings match those saved operation states. Recovery is never automatic at startup. Legacy snapshots without an intent plan, later transactions and unrelated changes require administrator review. In-memory last-result display resets on service restart; snapshots and audit records persist.
- Restoration refuses to overwrite changes made since the selected repair. DHCP changes can prevent exact restoration verification even when automatic mode was restored. Read the receipt rather than assuming success.

## Platform and coverage limits

The native configuration API requires Windows 10 build 19041 or later; unsupported systems have no registry-only fallback. Read-only API and pipe-authorization checks run in Windows CI. Portable transaction tests cover failures and rollback; the separate `dns-smoke` Windows CI job now exercises actual profile writes, original/automatic restoration, cancellation rollback and disk-backed recovery with a new service instance. It runs only on a disposable hosted runner, with a 150-second process-tree deadline and an independent Windows-cmdlet emergency restore. The regular suite skips this guarded mutation test. **The harness is implemented; a passing Windows run is required before claiming native validation.** SYSTEM journal ACL behavior, interactive UAC, IPv6-only hardware, DHCP lease changes and reboot/power-loss validation remain distinct follow-up checks.

This feature does not repair router firmware/credentials, inspect Wi-Fi passwords, authenticate DHCP, remove malicious browser extensions, reset hosts/proxy/PAC settings or defeat transparent DNS interception. It does not enable encrypted DNS. Those require separate diagnosis and recovery. See the [capability matrix](CAPABILITY_MATRIX.md).

In 3.2.5, the legacy RegistryMonitor proxy-change path is Tier2 LogOnly and no longer writes/deletes proxy values to restore startup observations. This does not add a manual proxy repair workflow or complete interactive-user/WinHTTP policy coverage.
