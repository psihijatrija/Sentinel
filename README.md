# Sentinel

Userland endpoint detection and response (EDR) for Windows. Sentinel runs entirely in
user mode — no kernel driver, no rootkit — yet fuses real-time telemetry from ten ETW
providers (process, image load, file, registry, DNS, network, PowerShell script-block,
firewall, task scheduler, WMI activity, and the Microsoft Threat-Intelligence provider)
with behavioral rules, weighted multi-signal correlation, and offline ML scoring for PE,
URL, and command-line artifacts. It maps detections to MITRE ATT&CK and terminates a
process tree when an authorized high-confidence Tier1 detection identifies a kill-grade
attack. Tier2 indicators remain log-only; correlation supplies additional context.

Detection coverage spans process injection and evasion (including ETW-TI call-stack
analysis of unbacked return frames), credential theft, C2 and beaconing, ransomware I/O,
living-off-the-land binaries, WMI persistence, and local-network man-in-the-middle. The
correlation engine is explainable: every composite emits the score breakdown and the
ATT&CK techniques that fired.

Sentinel Core/Service/Agent operate offline: their online reputation, live intelligence feeds, connectivity probes, and automatic outbound reporting have been removed. The service maintains firewall blocks for those executables' non-loopback traffic, mirrors them into supported local Group Policy, and monitors unapproved inbound exceptions for re-enables. Outbound connectivity and narrow DHCP/IPv6 control traffic are preserved; domain conflicts are reported. The authenticated local dashboard remains available. The Agent runs without elevation and delegates required administrator operations to the installed service. The service still hosts system sensors and response; it is not a minimal privilege broker. See [offline operation and validation](docs/OFFLINE_VALIDATION.md).

**3.3.8 online exception:** the separately packaged [NanoAV module](docs/NANOAV.md) retains the supplied program's own online feeds, persistence and response engine. Its only source changes protect Sentinel; it does not follow Sentinel's response rules. Read its retained runtime limitations before relying on it.

**Platform:** Windows 10/11 x64 - .NET Framework 4.8
**Version:** 3.3.8 (single source of truth: `version.txt`)

For collection status, known telemetry limits, and the Windows verification probe, see [monitor health](docs/monitor-health.md).

Public PoC metadata and actively exploited vulnerability triage:
[offline exploit intelligence](tools/exploit-intelligence/README.md). This separate
research tool does not grant response authority or establish blocking coverage.

Pending runtime improvements and validation limits:
[exploit payload protection](docs/EXPLOIT_PAYLOAD_PROTECTION.md).

Pending automatic online protection:
[ExploitShield companion](tools/Sentinel.ExploitShield/README.md) collects public
exploit metadata every four hours and installs applicable CVE-matched vendor
security fixes through Windows Update. It is separate from the offline monitoring
executables; unsupported/no-fix cases remain unresolved. Windows installer and
live patch validation are still pending.

On-demand investigation reports and hardening status:
[read-only security audit](docs/SECURITY_AUDIT.md).

Credential-read and script telemetry coverage, including explicit limitations:
[2026 attack coverage](docs/ATTACK_COVERAGE_2026.md).

Engineering assessment, provisional subsystem ratings and remaining validation:
[quality review](docs/QUALITY_REVIEW.md). Offline replay, evidence verification,
restore inspection and private exports: [diagnostics](tools/Sentinel.Diagnostics/README.md).

## Legal Disclaimer

**Sentinel is provided for defensive, educational, and research purposes only.**

By installing or using this software you agree to the following:

1. You will only run Sentinel on systems you own or have explicit written authorisation to monitor.
2. You will not use Sentinel to monitor, surveil, or collect data on any person without their knowledge and consent where required by applicable law.
3. The authors and contributors accept no liability for damages, data loss, system instability, false positives, missed detections, or any other harm arising from the use or inability to use this software.
4. Sentinel actively kills processes and modifies host security policy. **Test in a non-production environment before deploying broadly.**
5. This software is provided **"as is"**, without warranty of any kind, express or implied.

Use responsibly and in compliance with all applicable local, national, and international laws. Released under the MIT License - see [LICENSE](LICENSE).

See the [documentation index](docs/README.md) for current guidance, validation limits and historical records.

DNS configuration repair is available from the dashboard Scan page with administrator approval. See [DNS repair and limits](docs/DNS_REPAIR.md) and the [capability matrix](docs/CAPABILITY_MATRIX.md).
