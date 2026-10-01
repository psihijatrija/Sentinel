# ETW-TI Call-Stack Detection (Unbacked Return Frames)

Status: implemented in 2.9.0

## The gap

Sentinel enables the Microsoft-Windows-Threat-Intelligence (ETW-TI) provider in
`UnifiedEtwSession` (provider GUID `F4E1897C-BB5D-5668-F1D8-040F4D8DD344`), but until
2.9.0 it did not consume the single most valuable thing ETW-TI can carry: the **call
stack** captured at the moment a sensitive syscall fires.

Concretely, three things were true in the code:

1. `UnifiedEtwSession.EnableProvider()` called `EnableTraceEx2` with
   `enableParameters = IntPtr.Zero`. It never set `EVENT_ENABLE_PROPERTY_STACK_TRACE`,
   so ETW attached no stack to any event.
2. `OnEventRecord()` copied only `UserData`. It ignored `ExtendedData` /
   `ExtendedDataCount`, which is exactly where a `STACKWALK64` extended-data item lives.
3. `OnThreatIntelEvent()` emitted a generic `ThreatIntel_EventId_N` signal with a guessed
   target PID and no return-address chain.

The existing injection detection (`EtwThreatIntelMonitor`) is a periodic **poll** of
thread *start* addresses and RWX regions. It catches classic shellcode but, per its own
documented `LOW-4` limitation, misses:

- Hollowing that preserves `MEM_IMAGE` on the overwritten section.
- In-memory living-off-the-land execution where a **legitimate signed module** issues a
  sensitive syscall from a **spoofed or unbacked return address**.

## Why this matters (2026 threat data)

The dominant intrusion pattern is now malware-free. Industry reporting for 2025/2026 puts
malware-free detections around 82% and living-off-the-land techniques in the large
majority of high-severity attacks, with credential abuse and native tooling replacing
dropped binaries. A file-hash / signer / static-PE model structurally cannot see this
class, because every artifact on disk is genuine. The return-address chain at a sensitive
syscall is one of the few userland signals that survives: injected or manually-mapped code
frequently returns into committed, non-image (unbacked) memory even when every module on
disk is signed and benign.

## The fix

Three scoped changes, no new architecture:

1. **`UnifiedEtwSession`** — `EnableProvider` gained an optional `captureStack` parameter.
   When set (only for the ETW-TI provider), it builds an `ENABLE_TRACE_PARAMETERS`
   (version 2) with `EVENT_ENABLE_PROPERTY_STACK_TRACE` and passes it to `EnableTraceEx2`.
   Scoping to one provider avoids two known hazards: the 64 KB ETW event-size ceiling
   (stacks can push an event over the limit and cause a drop) and the historical LatencyMon
   hard-fault noise from broad walks.

2. **`OnEventRecord()`** — parses the `EVENT_HEADER_EXT_TYPE_STACK_TRACE64` extended-data
   item into a return-address array and surfaces it on `EtwRawEvent.StackFrames`. Parsing
   is fully defensive; a malformed item yields an empty array and never throws (the ETW
   callback must never throw).

3. **`EtwEventDispatcher.OnThreatIntelEvent()`** — does **no** memory inspection on the ETW
   callback thread. It only stashes the captured frames via
   `InjectionSuspectBoard.RecordStack(pid, frames)` (a cheap dictionary write). This is
   deliberate: heavy per-event work on the callback thread was the historical LatencyMon
   hard-fault source, which is why the existing module-walk scanning already lives
   off-thread. Consistency with that architecture is a hard requirement.

4. **`EtwThreatIntelMonitor.ScanOneProcessStack()`** — runs on the existing off-thread scan
   loop (every ~8s, per-PID `AlertCooldown`). It drains the stash with
   `InjectionSuspectBoard.TakeStack(pid)` (one-shot, so a capture can only alert once) and
   classifies each user-mode return frame against `MappedModuleCache` (already maintained
   from `EnumModules` + ETW `ImageLoad`). A frame that resolves to committed, executable,
   non-`MEM_IMAGE` memory is an **unbacked return frame**; the scanner emits a
   `Tier1Behavioral` / `LogOnly` signal into the correlation engine and publishes an
   `InjectionSignal` on the `ContextBus` for `ChainTracer` enrichment.

## Performance / abuse resistance

- **No heavy work on the ETW callback thread.** The callback path only does a dictionary
  write. Module enumeration and remote memory queries happen on the off-thread scan loop,
  matching the existing `EtwThreatIntelMonitor` design and avoiding the LatencyMon
  hard-fault regression that a per-event walk would reintroduce.
- **DoS-bounded.** A process spamming ETW-TI events cannot amplify work: the stash keeps
  only the most recent frames per PID, the scan runs on a fixed ~8s cadence, and the
  per-PID `AlertCooldown` plus one-shot `TakeStack` prevent alert floods.
- **Bounded parsing.** Frame count is capped (`MaxStackFrames`), reads are bounded by the
  ETW-reported `DataSize`, and a malformed extended-data item yields an empty array.

## Constraint compliance

- **Userland only.** Pure ETW consumer; no kernel driver, no hooks. ETW-TI itself is a
  Microsoft-provided kernel telemetry source consumed from userland — the same source the
  session already enables.
- **Observe-until-chain.** The new signal is fed to the correlation engine as evidence; it
  does not directly authorize a kill on its own. Terminal authority stays with the chain.
- **Tier2 = LogOnly.** Unchanged. The unbacked-frame signal is `Tier1Behavioral` evidence
  for correlation, consistent with how the existing unbacked-RWX signal is treated.
- **Fail-closed.** Unresolvable PID / stack / memory query yields no signal rather than a
  guess. `NativeProcessMemory.CanInspect` still gates game/anti-cheat targets.
- **DI, no string-built JSON.** No new statics beyond the existing `MappedModuleCache`; no
  serialization added.

## Known limitations

- Kernel-mode frames in the stack are ignored; only user-mode return addresses are
  classified. This is intentional (userland scope) and sufficient for injection triage.
- Stack capture is best-effort. If ETW drops an oversized event, this handler simply sees
  no stack for that event and the existing poll-based scanner remains the backstop.
- A sophisticated attacker who spoofs a return address into a *backed* image region will
  not be flagged by the unbacked test alone; that case still relies on the broader
  correlation of other signals (credential access, C2 beaconing, etc.).
