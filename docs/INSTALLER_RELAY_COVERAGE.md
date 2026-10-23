# Installer, relay and secondary-drive coverage — 3.4.0

Fake game installers can launch credential stealers or remote shells. A relay
can carry legitimate or malicious traffic; “Ome-Relay” is unidentified. The two
forum posts supply neither a sample hash nor an antivirus detection name.
These changes target behaviors and do not establish protection against those samples.

## Runtime changes

- The existing raw-socket rule recognizes a narrow inline Python command with
  `socket.socket`, a connection on that socket, and a shell launched with
  stdin/stdout/stderr all attached to that socket's `fileno()`. Supported direct
  subprocess calls are `call`, `Popen` and `run`. Matching is bounded to 64 KiB
  with regex timeouts. No code is executed during inspection.
- The same rule uses the existing PowerShell decoded-code parser, preventing
  a looser TCPClient check from bypassing its code/literal distinction.
- An ETW Kernel-File credential-store read may corroborate confirmed C2 or a
  reverse shell within 60 seconds in the same current process lifetime. Unknown
  identity, PID reuse, future/expired timestamps, consultant observations,
  watcher notifications and weak network signals cannot complete that chain.
  Credential reads alone remain Tier2 LogOnly. Independent confirmed terminal
  detections retain their own existing response authority.
- Ready removable volumes join fixed drives in file watchers and the initial
  lazy walk. A drive-root change is checked every five seconds and rebuilds
  subscriptions and the lazy walk after cancelling the previous walk. This
  expected lifecycle change does not consume the monitor's failure restart
  budget. Network/optical drives remain excluded. The walk retains its 30-second
  startup delay, existing exclusions and scan index; analysis is asynchronous.

NanoAV and its aggressive original response policy are unchanged. Sentinel
does not gain a name-based rule for Ren'Py, Python, installers or relay services.
No additional desktop content collection or outbound reporting is introduced.

## Limits

Python coverage is a lexical signature of the shown inline form, not a Python
parser, execution trace or data-flow proof. Single-quoted outer command lines,
aliases, script files, `dup2` variants, dynamically constructed code, renamed
interpreters and packaged/native payloads are outside this signature. Dead code
or deliberately embedded code-shaped text may resemble the signature. It does
not establish that the network connection succeeded. Legitimate remote shells
can match too; there is no operator-intent inference.

Fixed secondary drives were already scanned. Extending scanning does not make
every file inspectable, remove existing exclusions, prevent first execution or
prove a drive clean. ADS tagging may be unavailable on non-NTFS media. A file
remaining on another drive does not itself establish automatic reinfection.
Same-letter media swaps between checks may not change root membership.

Credential correlation needs working Kernel-File attribution and queryable
process identity. It does not inspect credential contents, guarantee blocking
before theft, or revoke stolen sessions. Child processes are not automatically
assigned the parent's evidence or kill authority.

## Validation and Windows acceptance

`InstallerRelayScenarioTests`, `InfostealerChainTests`,
`ReverseShellPayloadCoverageTests`, `SpywareContainmentTests` and the existing
correlation/lifecycle regressions use inert telemetry. They check detection and
dispatch policy, not real process termination. Production Framework binaries
are cross-built; Linux portable execution cannot replace native Windows checks.

Before treating installed protection as verified, use an isolated Windows VM:

1. Build/install 3.4.0 and run the native Framework test suite. Confirm both
   Sentinel and the separate NanoAV payloads are packaged and launch as expected.
2. Launch a legitimate Ren'Py game, installer and ordinary Python network client;
   confirm these new rules do not authorize response from their names/networking.
3. Use an isolated benign shell/socket fixture with no real credentials or
   external destination. Verify ETW delivery, authorized termination, evidence
   logging and protection of Sentinel processes. Never run an unknown forum sample.
4. Attach/detach a test removable volume, including more than five cycles.
   Confirm scanner health returns, subscriptions are rebuilt, and new scannable
   files generate analysis. Check an already-populated volume is walked too.
5. Review failed/unreadable paths and telemetry degradation explicitly; do not
   equate absence of alerts with a clean drive or a successful containment test.

## DLL-loader follow-up in the same 3.4.0 version

The [injected-payload changes](LOADER_PAYLOAD_COVERAGE.md) address a separate native/DLL-loader stage: arbitrary eligible target hosts, private RX sections with readonly PE headers, and lifetime-pinned victim response. They do not depend on the Python signature or identify a specific malicious adjacent DLL. Existing process-tree and native memory fixtures distinguish portable policy verification from Windows runtime checks.
