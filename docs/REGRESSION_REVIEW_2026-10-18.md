# Regression review — 2026-10-18

Product version: 3.2.5. Reviewed range: `4acc2de..4a5c973` (five follow-up commits after the release preparation commit). The checkout was clean before review. Documentation changes from this review do not bump, package or publish a release.

## Changes and findings

- Proxy drift now opens the observed registry key read-only, emits Tier2 LogOnly with no attributed PID, and adopts the latest observation without restoring or deleting values. The three existing proxy observation cases pass. This correction is already recorded under 3.2.5; it is not a new administrator-approved proxy repair feature.
- DNS adapter matching now parses GUIDs in both the service and native backend. The same comparison covers approved-profile lookup, snapshot selection, newer-transaction recovery exclusion and pending-transaction checks. Fresh fingerprints, eligibility, policy checks and read-back remain separate requirements. The existing equivalent-format request regression passes.
- The Windows DNS wrapper selects a connected hardware adapter with a DNS interface, accepts absent static registry values as automatic mode and rejects non-string values. Independent emergency restoration runs when saved static settings differ; a failed test remains failed even after successful restoration. This was inspected, not executed on Linux.
- The Windows pipe fixture starts its read before blocking on the client write, checks the byte received, and isolates token impersonation from the xUnit async context. A 15-second outer deadline reports the blocked stage. It does not cancel a blocked native call: the worker is a background thread, and CI hang/process deadlines remain necessary. Actual token behavior was not exercised here.

No confirmed regression was found in this range with the checks below. This is a focused source and regression review, not a whole-product security assessment.

## Current execution evidence

| Check | Result | Scope |
| --- | --- | --- |
| Full solution Release cross-build, .NET SDK 10.0.402 | Passed, 0 warnings / 0 errors | Includes shipping projects, tests and tools; Linux cross-compilation only |
| `node --test tests/dashboard-response.test.cjs` | 16 passed, 0 failed, 0 skipped | Rendering, verified-effect labels and DNS approval/recovery controls |
| `npm test` in `worker` | 8 passed, 0 failed, 0 skipped | Independent legacy Worker; no deployment or external API calls |
| Existing `DnsRepairServiceTests` and `ProxyObservationTests` | 45 passed, 0 failed, 0 skipped | Temporary net10.0 xUnit host referencing the built net48 Core assembly |
| Full Windows Framework suite / native DNS / pipe impersonation | Not run | Requires Windows; historical results do not validate this HEAD |
| PowerShell firewall regressions and native wrapper execution | Not run | Requires the Windows toolchain and APIs |

The temporary host lives outside the checkout at `/workspace/.setup/regression-review` in the review machine. Its first compilation exposed a host dependency mismatch; matching the production `Microsoft.Extensions.*` assemblies resolved it. The successful TRX is `TestResults/review.trx` under that temporary directory. No product dependency, test or assertion was changed to obtain a pass. The host is a local validation aid, not a supported product target or a checked-in test runner.

The full cross-build used `dotnet build Sentinel.sln -c Release --no-restore -p:EnableWindowsTargeting=true -warnaserror -m:3` after restoring with `EnableWindowsTargeting=true`. Native authorization, mutation, journal ACLs, UAC, reboot/power-loss and DHCP/IPv6 hardware behavior remain separate Windows gates; see [DNS repair](DNS_REPAIR.md) and [Windows validation](OFFLINE_VALIDATION.md).

The next patch notes are staged as 3.2.6 (Unreleased). Release packaging/publication remains pending Windows validation and the repository's Windows release workflow.
