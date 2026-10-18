# Read-only security audit (3.3.1)

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
- **ObservedActive**: the local runtime WMI provider reported an active state at collection
  time. This is a snapshot, not continuous assurance. VBS running does not establish that
  Credential Guard or every VBS feature is running.
- **NeedsReview**: an explicit setting differs or a supported runtime snapshot reports an
  inactive state. This does not prove compromise, and no automatic repair is performed.
- **Unknown**: missing settings, access failures, unavailable providers or unsupported types.
  Missing values are not interpreted as disabled: current Windows defaults can be secure.

Configuration checks cover LSASS PPL, WDigest plaintext caching, PowerShell script-block
logging, required SMB client/server signing and SMB1 server configuration. Local Defender
service/antivirus/real-time status and VBS runtime status are queried through optional WMI
providers with bounded enumeration timeouts. Missing providers remain Unknown, including
on custom Windows installations. There are no remote queries or outbound probes.

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

Local release checks: full .NET SDK 10.0.402 Release cross-build passed with zero
warnings/errors. A temporary .NET 10 host ran 59 production-assembly regressions,
including 23 new audit cases; all passed without skips. Dashboard checks: 22 passed.
Standalone Worker checks: 8 passed. Windows Framework execution, live WMI/Event Log/
registry collection and the new exclusive-writer/process-tree fixtures were not run
on this Linux host and require Windows CI.
