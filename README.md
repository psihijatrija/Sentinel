# Sentinel

Userland endpoint detection and response (EDR) for Windows. Sentinel runs entirely in
user mode — no kernel driver, no rootkit — yet fuses real-time telemetry from ten ETW
providers (process, image load, file, registry, DNS, network, PowerShell script-block,
firewall, task scheduler, WMI activity, and the Microsoft Threat-Intelligence provider)
with behavioral rules, weighted multi-signal correlation, and offline ML scoring for PE,
URL, and command-line artifacts. It maps detections to MITRE ATT&CK and terminates a
process tree only when a multi-signal chain confirms a kill-grade attack
(`ObserveUntilChain`).

Detection coverage spans process injection and evasion (including ETW-TI call-stack
analysis of unbacked return frames), credential theft, C2 and beaconing, ransomware I/O,
living-off-the-land binaries, WMI persistence, and local-network man-in-the-middle. The
correlation engine is explainable: every composite emits the score breakdown and the
ATT&CK techniques that fired.

**Platform:** Windows 10/11 x64 - .NET Framework 4.8
**Version:** 2.9.0 (single source of truth: `version.txt`)

## Legal Disclaimer

**Sentinel is provided for defensive, educational, and research purposes only.**

By installing or using this software you agree to the following:

1. You will only run Sentinel on systems you own or have explicit written authorisation to monitor.
2. You will not use Sentinel to monitor, surveil, or collect data on any person without their knowledge and consent where required by applicable law.
3. The authors and contributors accept no liability for damages, data loss, system instability, false positives, missed detections, or any other harm arising from the use or inability to use this software.
4. Sentinel actively kills processes and modifies host security policy. **Test in a non-production environment before deploying broadly.**
5. This software is provided **"as is"**, without warranty of any kind, express or implied.

Use responsibly and in compliance with all applicable local, national, and international laws. Released under the MIT License - see [LICENSE](LICENSE).
