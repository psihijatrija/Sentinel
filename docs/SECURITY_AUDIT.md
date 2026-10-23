# Read-only security audit (3.4.0)

Run **Full Scan** in the authenticated local dashboard. The Security audit panel adds
hardening read-back and a six-hour activity report to existing process, persistence,
certificate, shortcut, staging and network findings. **Download audit JSON** saves the
collected audit locally; it includes account names, IP addresses and application paths.
Review it before sharing. It is not the redacted diagnostic export or a signed evidence pack.

This adapts investigation and baseline-checking ideas from the supplied Powershell.zip
(SecurityCheckup.ps1 and security-audit-6h.ps1) and Registry.zip. It does not run the
uploaded scripts, import registry packs, install their scheduled tasks, restore browser
cookies, delete network shortcuts or change security settings.

## Meaning of status

- **Configured**: an explicitly readable DWORD matches the baseline. This is registry
  read-back, not proof of effective enforcement. Policy refresh/reboot, enterprise policy,
  platform support and other settings can affect actual protection.
- **ObservedActive**: the local runtime provider or verified process-handle query reported an active state at collection
  time. This is a snapshot, not continuous assurance. VBS running does not establish that
  Credential Guard or every VBS feature is running.
- **NeedsReview**: an explicit setting differs or a supported runtime snapshot reports an
  inactive state. This does not prove compromise, and no automatic repair is performed.
- **ConfiguredNotRunning**: the feature appears in configured Device Guard services but
  not in the running services. A reboot or hardware/policy prerequisites may apply;
  the cause is not independently established.
- **ContextDependent**: Credential Guard is not reported active or configured. Its
  priority depends on domain credential use; this is not a universal consumer failure.
- **Unsupported**: the Device Guard WMI class/namespace is not available on this Windows
  installation. This does not establish that a security feature is enabled or disabled.
- **Unknown**: missing settings, access failures, unavailable providers or unsupported types.
  Missing values are not interpreted as disabled: current Windows defaults can be secure.

Configuration checks cover LSASS PPL, WDigest plaintext caching, PowerShell script-block
logging, required SMB client/server signing, SMB1 server configuration, Credential Guard,
Memory Integrity and the vulnerable-driver blocklist. Blocklist configuration does not
prove that any particular driver load will be prevented.

Runtime Device Guard checks inspect VBS status and individual configured/running service
IDs. VBS running does not imply CG or HVCI is running; malformed or contradictory provider
values remain Unknown. LSASS runtime protection uses a query-only handle, verifies the
system image path, and reads process protection status without reading LSASS memory.
An unavailable process handle remains Unknown; registry RunAsPPL is separate configuration.

Credential Guard chiefly protects domain authentication secrets. It does **not** protect
local-account/personal Microsoft-account sign-in passwords, browser cookies or saved
browser passwords. Inactive CG is contextual rather than a generic missing consumer
protection alert. Memory Integrity and LSASS runtime gaps remain separate observations.

Defender service/antivirus/real-time status is queried only as optional integration context.
Sentinel targets standalone operation; Defender's ASR and antivirus capabilities are not
credited to Sentinel itself. Missing providers remain explicit, including on custom Windows
installations. Runtime WMI queries have bounded enumeration timeouts. There are no remote
queries or outbound probes in this audit.

## History coverage

Security 4624/4625, System 7045 and TaskScheduler Operational 106 are read using named XML
fields in a fixed six-hour UTC window. Each source returns at most 200 records; malformed
records, errors and truncation are disclosed. Source availability does not establish that
required audit policy was enabled throughout the window, or that logs retain all activity.
Successful network/RDP logons and new services/tasks are observations, not malicious verdicts.
Raw event XML, service command lines and task bodies are not copied into the report.

Camera/microphone records use LastUsedTimeStart from ConsentStore keys in at most 64 loaded
interactive-user hives, with at most 256 collected usage records. Unloaded profiles, registry
access failures, missing stores and unsupported timestamp types limit coverage. Registry usage
timestamps do not prove current capture or reveal every capture mechanism. The report does
not enumerate current remote sessions or reconstruct processes that ended without retained
telemetry. Timestamps and histories must be reviewed alongside existing scan findings.

History sections are Available, Partial or Unknown. Zero returned records is never a clean-system
verdict. The dashboard renders at most 50 records per source; JSON contains all collected rows.
The audit never emits detection signals or authorizes containment. Existing response policy,
privileged IPC authorization and certificate/DNS repair boundaries remain in effect.

## Validation

Payload/aggregation tests exercise strict registry and runtime types, missing sources,
cancellation, named event fields, malformed timestamps and XML entity rejection. Dashboard
checks exercise escaping, partial/unknown coverage, configuration versus runtime labels,
record limits and incomplete scans. These are separate from native Windows validation.

The process-tree containment fixture now publishes PID files through a same-directory rename
after the writer closes the temporary file. Its reader uses shared reads and bounded retries
for Windows sharing/lock violations. A Windows-only regression holds an exclusive writer open
before releasing it. Parent/child/grandchild termination and unrelated-process survival assertions
are preserved. Live Windows execution must confirm the reported CI failure is resolved.

3.4.0 adds pure tests for individual feature states, strict provider types, contextual
Credential Guard scope, and matching dashboard labels. Native CI exercises the real WMI
and process-query providers without requiring them to report active protection: unavailable
or unsupported is a valid, disclosed state, not a passing protection claim. Linux cross-build
and portable test results are listed in [the changelog](CHANGELOG.md); native results require
Windows CI. The native endpoint fixture also checks real owned-process containment and
temporary Run-value cleanup independently of the read-only audit.
