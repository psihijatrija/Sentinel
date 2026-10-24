# 3.4.1: fixes from the October 23 runtime logs

The supplied logs showed a verified termination of Sentinel's installed ExploitShield
companion, degraded ETW visibility and misleading posture/network warnings. They did
not establish malware infection. This release fixes those code paths without adding a
filename-based trust exemption or modifying NanoAV.

| Finding | Correction | Validation boundary |
| --- | --- | --- |
| “Kernel Exploit Loader” filename/command heuristic killed ExploitShield | Context-only at emission, terminal classification, dispatch and correlation. Even legacy family/chain fields cannot grant this rule authority. Concrete independent behavioral detectors retain their response paths. | Regression tests include the companion, arbitrary tool identities, high confidence and legacy authority fields. No real exploit sample was supplied. |
| Local port 54321 on an HTTPS connection labeled inbound malware traffic | Only remote ports supply this observation; initiation direction stays Unknown for TCP snapshots. Endpoint observations are throttled and context-only, including legacy Tier1 inputs. | Tests cover ordinary remote HTTPS, legacy indicator ports and policy bypass attempts. A remote port still does not identify a RAT. |
| Legacy IPSec reapplication failed repeatedly | Replace English `netsh ipsec static` success guessing with owned Windows Firewall TCP/UDP block rules for the existing compiled port set. Read back scope, action, profiles and filters; disclose provider/profile/GPO failures. Successful modern read-back permits best-effort removal of the old owned GSecurity policy. Uninstall removes owned modern filters. | Native fixture applies/reads/removes one disposable test rule. Configuration read-back is not a packet-block or domain-policy test. |
| ETW provider denial masked simultaneous loss in the warning text | Report both causes together; new loss also advances visibility-gap reconciliation while another cause remains degraded. Explain Windows protected Threat Intelligence access separately. | Access denial cannot be bypassed by an ordinary SYSTEM/userland service. Other sensors are not equivalent provider coverage. |
| Billions of collected ETW events and millions lost | Request native event-ID include filters for events actually consumed; retain credential name/read, process/image, DNS and network events. Leave Threat Intelligence unfiltered. Disclose unsupported-filter fallback. Increase bounded session buffers from 16–32 MiB to 32–64 MiB. | Native fixture checks filtered process-start delivery and process/file filter enable results. Filters and buffers reduce unnecessary work; they do not guarantee zero loss or restore historical events. |
| Watcher overflow followed by Healthy subscription checks | Use a 64 KiB watcher buffer and filename/directory notifications, avoiding unused LastWrite traffic. Retry watcher failures locally rather than exhausting group restart attempts. Require reconciliation completion before Healthy; overflow recovery bypasses the metadata scan cache. Count unavailable directories/volumes as incomplete enumeration. | This is best-effort reconciliation, not reconstruction of transient/deleted files. Access-denied directories and scan exclusions remain disclosed limits. |
| Successful process-only kill reported partial because an extra quarantine was refused | Chain tracing attempts file quarantine only when the authorized action requests quarantine. | Tests preserve process-only versus quarantine-and-kill boundaries. Kill verification still requires actual process exits. |
| Disabled Smart App Control and old root certificates described as attacks | Use posture/observation wording, remove campaign attribution from the SAC snapshot, and distinguish first observation from certificate installation time. Explicit certificate distrust authorization remains separate. | These observations cannot identify an actor or establish compromise. |

The modern block rules use the same compiled port set as the former legacy policy,
including the existing restrictive service ports (for example SSH, RDP, SMB and database
ports). Where legacy IPSec failed, these Windows Firewall rules can now enforce blocks
that previously did not work. DNS/HTTPS ports are not added to that set. No new kernel
component, external probe or reputation query is introduced.

## Release checks and installation validation

The product projects and shipping tests cross-build with warnings treated as errors.
A temporary .NET 10 host exercises the compiled Core assembly and selected exact test
sources: 395 passed, seven native Windows fixtures skipped. Windows ACL/ADS/path-dependent
cases are excluded from that portable host and remain in the shipping Framework suite.
All 26 dashboard tests and NanoAV source-preservation verification pass. The optional
Windows Desktop ML trainer is outside this Linux cross-build.

Windows CI requires all seven endpoint fixtures to execute and pass without skips,
including the two new elevated integration cases. Those cases require a disposable
administrator runner; they never elevate the test host themselves. Full Framework,
installer, reboot, effective port blocking, sustained load and real watcher-overflow
recovery still require Windows execution. A clean cross-build is not evidence that the
user's installed environment has recovered. Inspect new runtime health after upgrading;
keep cumulative loss counters and historical gaps visible even after collection recovers.

The first Windows run reported an unavailable-policy failure in the port fixture.
The follow-up handles missing-rule HRESULTs translated by Framework into
`FileNotFoundException`, avoids empty application/service BSTR setters on fresh COM
rules, and tests mapped absence versus access/provider failure. Fresh COM defaults
must still pass mandatory scope read-back. The native fixture now exercises first
creation, repeat application and independent inspection, and emits full stage/error
details instead of a truncated substring assertion. The supplied failure omitted
the exception type/HRESULT; successful native execution is still required to confirm
the reported Windows failure is resolved.
