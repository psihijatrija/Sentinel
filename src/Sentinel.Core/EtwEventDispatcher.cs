using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Converts raw ETW events from UnifiedEtwSession into typed telemetry objects
    /// and feeds them into the TelemetryFusionEngine -> DetectionEngine pipeline.
    /// 
    /// Each provider has a dedicated handler method registered with UnifiedEtwSession.
    /// Handlers parse the provider-specific event payload and emit the appropriate
    /// telemetry type (ProcessTelemetry, FileActivityTelemetry, NetworkTelemetry, etc.).
    /// 
    /// DESIGN RULES:
    ///   - Handlers must be non-blocking (ETW callback thread pool is limited)
    ///   - Parse defensively (payload layouts vary by Windows build)
    ///   - Never throw from a handler (exceptions are swallowed by the session)
    ///   - Copy any data from UserData pointer before returning
    /// </summary>
    public sealed class EtwEventDispatcher
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly BehavioralBaselineService? _baseline;
        private readonly DllUnloadEngine? _dllUnloadEngine;
        private readonly ILogger<EtwEventDispatcher> _logger;

        // Event IDs for Microsoft-Windows-Kernel-Process
        private const ushort ProcessStart = 1;
        private const ushort ProcessStop = 2;
        private const ushort ImageLoad = 5;

        // Event IDs for Microsoft-Windows-Kernel-File
        private const ushort FileCreate = 12;
        private const ushort FileDelete = 26;
        private const ushort FileRename = 15;  // SetInformation with rename class
        private const ushort FileWrite = 16;   // Write operations
        private const ushort FileNameCreate = 10;
        private const ushort FileNameDelete = 11;

        // Event IDs for Microsoft-Windows-Kernel-Registry
        private const ushort RegCreateKey = 1;
        private const ushort RegOpenKey = 2;
        private const ushort RegDeleteKey = 3;
        private const ushort RegSetValue = 5;
        private const ushort RegDeleteValue = 6;

        // Event IDs for Microsoft-Windows-DNS-Client
        private const ushort DnsQueryStart = 1001;  // QueryStart
        private const ushort DnsQueryComplete = 1002;

        // Event IDs for Microsoft-Windows-PowerShell
        private const ushort ScriptBlockLogging = 4104;

        // Event IDs for Microsoft-Windows-TaskScheduler
        private const ushort TaskCreated = 106;
        private const ushort TaskUpdated = 140;
        private const ushort TaskDeleted = 141;

        // Event IDs for Firewall
        private const ushort FirewallRuleAdded = 2004;
        private const ushort FirewallRuleModified = 2005;
        private const ushort FirewallRuleDeleted = 2006;

        // Event IDs for Kernel-Network (TCP/IP + UDP)
        private const ushort TcpConnect = 12; // TcpIp/Connect
        private const ushort TcpDisconnect = 14;
        private const ushort TcpAccept = 15;
        private const ushort UdpSendIpv4 = 42; // UdpIp/SendIPV4
        private const ushort UdpRecvIpv4 = 43; // UdpIp/RecvIPV4
        private const ushort UdpSendIpv6 = 56;
        private const ushort UdpRecvIpv6 = 57;

        public EtwEventDispatcher(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<EtwEventDispatcher> logger,
            BehavioralBaselineService? baseline = null,
            DllUnloadEngine? dllUnloadEngine = null)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _baseline = baseline;
            _dllUnloadEngine = dllUnloadEngine;
            _logger = logger;
        }

        /// <summary>
        /// Registers all provider handlers with the unified ETW session.
        /// Call this before UnifiedEtwSession.StartAsync().
        /// </summary>
        public void RegisterHandlers(UnifiedEtwSession session)
        {
            session.RegisterHandler(UnifiedEtwSession.Providers.KernelProcess, OnKernelProcessEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.KernelFile, OnKernelFileEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.KernelRegistry, OnKernelRegistryEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.DnsClient, OnDnsClientEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.ThreatIntelligence, OnThreatIntelEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.PowerShell, OnPowerShellEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.Firewall, OnFirewallEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.TaskScheduler, OnTaskSchedulerEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.KernelNetwork, OnKernelNetworkEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.WmiActivity, OnWmiActivityEvent);
        }

        // 
        // Process Events (Microsoft-Windows-Kernel-Process)
        // 

        private void OnKernelProcessEvent(EtwRawEvent evt)
        {
            if (evt.EventId == ProcessStart)
            {
                HandleProcessStart(evt);
                return;
            }
            if (evt.EventId == ImageLoad)
            {
                HandleImageLoad(evt);
                return;
            }
            if (evt.EventId == ProcessStop)
                HandleProcessStop(evt);
        }

        private void HandleProcessStop(EtwRawEvent evt)
        {
            // Evict the dead PID from MappedModuleCache so its image ranges don't
            // accumulate forever (PIDs are recycled; stale entries are misleading).
            int pid = evt.ProcessId;
            if (pid <= 4) return;
            MappedModuleCache.Remove(pid);
        }

        private void HandleImageLoad(EtwRawEvent evt)
        {
            if (_dllUnloadEngine == null) return;
            int pid = evt.ProcessId;
            if (pid <= 4) return;

            if (evt.UserData == IntPtr.Zero || evt.UserDataLength < IntPtr.Size + 4) return;
            ulong imageBase = (ulong)Marshal.ReadIntPtr(evt.UserData, 0);
            uint imageSize = unchecked((uint)Marshal.ReadInt32(evt.UserData, IntPtr.Size));
            if (imageBase != 0)
                MappedModuleCache.Add(pid, imageBase, imageSize);

            int nameOff = IntPtr.Size == 8 ? 32 : 20;
            if (evt.UserDataLength <= nameOff) return;
            string path = TryExtractUnicodeString(evt.UserData, nameOff, evt.UserDataLength - nameOff);
            if (string.IsNullOrEmpty(path) || (path.IndexOf('\\') < 0 && path.IndexOf('/') < 0))
                return;
            if (path.StartsWith(@"\??\", StringComparison.Ordinal))
                path = path.Substring(4);

            string name = "";
            try { name = _ancestryCache.GetProcessInfo(pid).name; } catch { /* ImageLoad is enough */ }

            _ = _dllUnloadEngine.NotifyMappedModuleAsync(pid, name, path);
        }

        private void HandleProcessStart(EtwRawEvent evt)
        {
            if (evt.UserData == IntPtr.Zero || evt.UserDataLength < 24) return;

            int pid = Marshal.ReadInt32(evt.UserData, 0);
            int parentPid = Marshal.ReadInt32(evt.UserData, 12);

            if (pid <= 4) return;

            // Resolve process details via PID (more reliable than variable-length ETW payload)
            string imagePath = SecurityValidation.GetProcessImagePath(pid) ?? "";
            string processName = !string.IsNullOrEmpty(imagePath) ? Path.GetFileName(imagePath) : "";

            if (string.IsNullOrEmpty(processName))
            {
                try { processName = Process.GetProcessById(pid).ProcessName; } catch { return; }
            }

            // Resolve parent
            string parentName = "";
            try { parentName = _ancestryCache.GetProcessInfo(parentPid).name; } catch { }

            // Update baseline
            _baseline?.RecordProcess(processName, imagePath, pid, parentName);

            // Emit telemetry
            var telemetry = new ProcessTelemetry
            {
                ProcessName = processName,
                ProcessId = pid,
                ParentProcessId = parentPid,
                ParentProcessName = parentName,
                ImagePath = imagePath,
                CommandLine = "", // Command line resolved by WMI fallback or ProcessAncestryCache
                Timestamp = evt.Timestamp
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);

            if (!string.IsNullOrEmpty(imagePath) &&
                !imagePath.StartsWith(@"\\") &&
                imagePath.Length > 3 &&
                !File.Exists(imagePath))
            {
                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Process Hollowing: Image File Missing",
                    Evidence = $"Process '{processName}' (PID {pid}) image path '{imagePath}' does not exist on disk",
                    Reasoning = "Possible hollowing indicator (T1055.012). Observe-first LogOnly until " +
                                "corroborating behavioral signals prove malice.",
                    Confidence = 0.75,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = processName,
                    ProcessId = pid,
                    Metadata = new Dictionary<string, string>
                    {
                        ["WeakObserveSeed"] = "true",
                        ["ImagePath"] = imagePath
                    }
                });
            }
        }

        // 
        // File Events (Microsoft-Windows-Kernel-File)
        // 

        private void OnKernelFileEvent(EtwRawEvent evt)
        {
            // NameCreate/NameDelete carry the path. FileCreate/Rename/Delete are
            // FileObject-only and still caused extract+alloc traffic (hard faults).
            if (evt.EventId != FileNameCreate && evt.EventId != FileNameDelete)
                return;

            if (evt.UserData == IntPtr.Zero || evt.UserDataLength < 4) return;

            string operationType = evt.EventId switch
            {
                FileNameCreate or FileCreate => "CREATE",
                FileNameDelete or FileDelete => "DELETE",
                FileRename => "RENAME",
                FileWrite => "WRITE",
                _ => "UNKNOWN"
            };

            // Resolve the process that caused the file event
            int pid = evt.ProcessId;
            string processName = "";
            try
            {
                var info = _ancestryCache.GetProcessInfo(pid);
                processName = info.name;
            }
            catch
            {
                try { processName = Process.GetProcessById(pid).ProcessName; } catch { }
            }

            if (string.IsNullOrEmpty(processName)) return;

            // File path extraction from ETW payload is provider-specific.
            // Microsoft-Windows-Kernel-File uses opaque FileObject pointers in some events.
            // For high-value events (NameCreate/NameDelete), the filename is in UserData.
            string filePath = TryExtractFilePath(evt);
            if (string.IsNullOrEmpty(filePath)) return;
            if (!SecurityFileScope.IsEtwFileEventRelevant(filePath)) return;

            var telemetry = new FileActivityTelemetry
            {
                ProcessName = processName,
                ProcessId = pid,
                FilePath = filePath,
                OperationType = operationType,
                Timestamp = evt.Timestamp
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);
        }

        // 
        // Registry Events (Microsoft-Windows-Kernel-Registry)
        // 

        private void OnKernelRegistryEvent(EtwRawEvent evt)
        {
            if (evt.EventId != RegSetValue && evt.EventId != RegCreateKey &&
                evt.EventId != RegDeleteKey && evt.EventId != RegDeleteValue)
                return;

            // Registry events from the kernel provider.
            // Emit a detection directly for high-interest operations (Run keys, services)
            int pid = evt.ProcessId;
            string processName = "";
            try { processName = _ancestryCache.GetProcessInfo(pid).name; } catch { }
            if (string.IsNullOrEmpty(processName))
            {
                try { processName = Process.GetProcessById(pid).ProcessName; } catch { return; }
            }

            WmiHostRegistryHint.Record(pid, processName);
            // No key path in this provider payload (handle-based). Path-less SetValue
            // filled fusion and paged the service. RegistryMonitor still has paths.
        }

        // 
        // DNS Events (Microsoft-Windows-DNS-Client)
        // 

        private void OnDnsClientEvent(EtwRawEvent evt)
        {
            // DNS query events give us domain name + PID
            if (evt.EventId != DnsQueryStart && evt.EventId != DnsQueryComplete) return;
            if (evt.UserData == IntPtr.Zero || evt.UserDataLength < 8) return;

            // DNS-Client provider payload for QueryStart:
            // QueryName (UnicodeString) at variable offset
            string queryName = TryExtractUnicodeString(evt.UserData, 0, evt.UserDataLength);
            if (string.IsNullOrEmpty(queryName)) return;

            int pid = evt.ProcessId;
            string processName = "";
            try { processName = _ancestryCache.GetProcessInfo(pid).name; } catch { }
            if (string.IsNullOrEmpty(processName))
            {
                try { processName = Process.GetProcessById(pid).ProcessName; } catch { }
            }

            var telemetry = new DnsTelemetry
            {
                ProcessName = processName,
                ProcessId = pid,
                QueryName = queryName,
                EventType = evt.EventId == DnsQueryStart ? "QUERY" : "RESPONSE",
                Timestamp = evt.Timestamp
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);
        }

        // 
        // Threat Intelligence Events
        // 

        private void OnThreatIntelEvent(EtwRawEvent evt)
        {
            // Microsoft-Windows-Threat-Intelligence provides kernel-level API observation:
            // Remote allocation / thread context / section map APIs (names omitted for AV hygiene).
            // These events are the strongest injection signal available from userland.
            if (evt.UserData == IntPtr.Zero || evt.UserDataLength < 8) return;

            int callerPid = evt.ProcessId;
            // Target PID is typically in the event payload at offset 0 or 4
            int targetPid = evt.UserDataLength >= 8 ? Marshal.ReadInt32(evt.UserData, 0) : 0;

            string processName = "";
            try { processName = _ancestryCache.GetProcessInfo(callerPid).name; } catch { }
            if (string.IsNullOrEmpty(processName))
            {
                try { processName = Process.GetProcessById(callerPid).ProcessName; } catch { }
            }

            var telemetry = new ThreatIntelTelemetry
            {
                ProcessName = processName,
                ProcessId = callerPid,
                TargetProcessId = targetPid,
                ApiName = $"ThreatIntel_EventId_{evt.EventId}",
                Timestamp = evt.Timestamp
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);

            // Stash the captured call stack (if any) for OFF-THREAD analysis. We must not
            // walk modules or read remote memory here: this runs on the ETW callback thread,
            // and heavy per-event work there is exactly what caused the historical LatencyMon
            // hard faults. EtwThreatIntelMonitor drains the stash on its own cadence, with a
            // per-PID cooldown, and classifies frames against loaded modules there.
            if (evt.StackFrames != null && evt.StackFrames.Length > 0)
                InjectionSuspectBoard.RecordStack(callerPid, evt.StackFrames);
        }

        // 
        // PowerShell Events (Script Block Logging)
        // 

        private void OnPowerShellEvent(EtwRawEvent evt)
        {
            // Event ID 4104 = Script Block Logging (deobfuscated content)
            if (evt.EventId != ScriptBlockLogging) return;
            if (evt.UserData == IntPtr.Zero || evt.UserDataLength < 4) return;

            // Script block text is in the UserData as a Unicode string
            string scriptBlock = TryExtractUnicodeString(evt.UserData, 0, evt.UserDataLength);
            if (string.IsNullOrEmpty(scriptBlock)) return;

            int pid = evt.ProcessId;
            string processName = "powershell.exe";
            try { processName = Process.GetProcessById(pid).ProcessName; } catch { }

            // Feed as a ProcessTelemetry with the script block as the command line
            // This allows existing detection rules (ReverseShellRule, AttackToolsRule) to evaluate it
            var telemetry = new ProcessTelemetry
            {
                ProcessName = processName,
                ProcessId = pid,
                CommandLine = scriptBlock.Length > 8192 ? scriptBlock[..8192] : scriptBlock,
                ImagePath = "",
                ParentProcessName = "",
                Timestamp = evt.Timestamp
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);
        }

        // 
        // Firewall Events
        // 

        private void OnFirewallEvent(EtwRawEvent evt)
        {
            if (evt.EventId != FirewallRuleAdded && evt.EventId != FirewallRuleModified &&
                evt.EventId != FirewallRuleDeleted)
                return;

            // Firewall rule changes - emit a detection signal for monitors to correlate
            string action = evt.EventId switch
            {
                FirewallRuleAdded => "RULE_ADDED",
                FirewallRuleModified => "RULE_MODIFIED",
                FirewallRuleDeleted => "RULE_DELETED",
                _ => "UNKNOWN"
            };

            _detectionEngine.SubmitTelemetry(new FusedTelemetryContext
            {
                TriggeringEvent = new FirewallTelemetry
                {
                    ProcessId = evt.ProcessId,
                    ProcessName = "",
                    Action = action,
                    Timestamp = evt.Timestamp
                }
            });
        }

        // 
        // Task Scheduler Events
        // 

        private void OnTaskSchedulerEvent(EtwRawEvent evt)
        {
            if (evt.EventId != TaskCreated && evt.EventId != TaskUpdated && evt.EventId != TaskDeleted)
                return;

            string action = evt.EventId switch
            {
                TaskCreated => "TASK_CREATED",
                TaskUpdated => "TASK_UPDATED",
                TaskDeleted => "TASK_DELETED",
                _ => "UNKNOWN"
            };

            _detectionEngine.SubmitTelemetry(new FusedTelemetryContext
            {
                TriggeringEvent = new TaskSchedulerTelemetry
                {
                    ProcessId = evt.ProcessId,
                    ProcessName = "",
                    Action = action,
                    Timestamp = evt.Timestamp
                }
            });
        }

        // 
        // Network Events (Microsoft-Windows-Kernel-Network / TCPIP)
        // 

        private void OnKernelNetworkEvent(EtwRawEvent evt)
        {
            bool udp = evt.EventId == UdpSendIpv4 || evt.EventId == UdpRecvIpv4 ||
                       evt.EventId == UdpSendIpv6 || evt.EventId == UdpRecvIpv6;
            bool tcp = evt.EventId == TcpConnect || evt.EventId == TcpAccept;
            if (!udp && !tcp) return;
            if (evt.UserData == IntPtr.Zero || evt.UserDataLength < 16) return;

            try
            {
                if (udp)
                    HandleUdpNetworkEvent(evt);
                else
                    HandleTcpNetworkEvent(evt);
            }
            catch { /* ETW callback must never throw */ }
        }

        private void HandleTcpNetworkEvent(EtwRawEvent evt)
        {
            int pid = evt.ProcessId;
            string processName = ResolveEtwProcessName(pid);

            // Layout (simplified): localAddr(4) + localPort(2) + remoteAddr(4) + remotePort(2)
            byte b1 = Marshal.ReadByte(evt.UserData, 8);
            byte b2 = Marshal.ReadByte(evt.UserData, 9);
            byte b3 = Marshal.ReadByte(evt.UserData, 10);
            byte b4 = Marshal.ReadByte(evt.UserData, 11);
            string remoteAddr = $"{b1}.{b2}.{b3}.{b4}";

            ushort remotePort = (ushort)Marshal.ReadInt16(evt.UserData, 12);
            remotePort = (ushort)((remotePort >> 8) | (remotePort << 8));

            if (remoteAddr == "0.0.0.0" || remoteAddr == "127.0.0.1") return;

            var telemetry = new NetworkTelemetry
            {
                ProcessName = processName,
                ProcessId = pid,
                RemoteAddress = remoteAddr,
                RemotePort = remotePort,
                Protocol = "TCP",
                State = evt.EventId == TcpConnect ? "CONNECT" : "ACCEPT",
                Timestamp = evt.Timestamp
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);
        }

        /// <summary>
        /// UdpIp_TypeGroup1: PID(4) size(4) daddr(4) saddr(4) dport(2) sport(2) ...
        /// Kernel-Network often reports session PID 0; the payload PID is then the
        /// only attribution. Never clobber a real evt.ProcessId with offset-0 garbage.
        /// </summary>
        private void HandleUdpNetworkEvent(EtwRawEvent evt)
        {
            bool ipv6 = evt.EventId == UdpSendIpv6 || evt.EventId == UdpRecvIpv6;
            if (ipv6 && evt.UserDataLength < 40) return;

            int pid = evt.ProcessId;
            if (pid <= 4 && evt.UserDataLength >= 4)
            {
                int payloadPid = Marshal.ReadInt32(evt.UserData, 0);
                if (payloadPid > 4)
                    pid = payloadPid;
            }

            string remoteAddr;
            ushort remotePort;
            if (ipv6)
            {
                var addr = new byte[16];
                Marshal.Copy(IntPtr.Add(evt.UserData, 8), addr, 0, 16);
                remoteAddr = new System.Net.IPAddress(addr).ToString();
                remotePort = (ushort)Marshal.ReadInt16(evt.UserData, 40);
            }
            else
            {
                uint daddr = (uint)Marshal.ReadInt32(evt.UserData, 8);
                remoteAddr = new System.Net.IPAddress(BitConverter.GetBytes(daddr)).ToString();
                remotePort = (ushort)Marshal.ReadInt16(evt.UserData, 16);
            }
            remotePort = (ushort)((remotePort >> 8) | (remotePort << 8));

            if (remoteAddr == "0.0.0.0" || remoteAddr == "127.0.0.1" || remoteAddr == "::" || remoteAddr == "::1")
                return;

            string processName = ResolveEtwProcessName(pid);
            var telemetry = new NetworkTelemetry
            {
                ProcessName = processName,
                ProcessId = pid,
                RemoteAddress = remoteAddr,
                RemotePort = remotePort,
                Protocol = "UDP",
                State = (evt.EventId == UdpSendIpv4 || evt.EventId == UdpSendIpv6) ? "SEND" : "RECV",
                Timestamp = evt.Timestamp
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);
        }

        private string ResolveEtwProcessName(int pid)
        {
            string processName = "";
            try { processName = _ancestryCache.GetProcessInfo(pid).name; } catch { }
            if (string.IsNullOrEmpty(processName) ||
                processName.Equals("unknown", StringComparison.OrdinalIgnoreCase))
            {
                try { processName = Process.GetProcessById(pid).ProcessName; } catch { }
            }
            return processName ?? "";
        }

        // 
        // WMI-Activity (Microsoft-Windows-WMI-Activity) - v2.2.8
        // Event 5859 temporary consumer, 5860/5861 permanent consumer / binding.
        // 

        private const ushort WmiTempConsumer = 5859;
        private const ushort WmiPermConsumer = 5860;
        private const ushort WmiPermBinding = 5861;

        private void OnWmiActivityEvent(EtwRawEvent evt)
        {
            if (evt.EventId != WmiTempConsumer && evt.EventId != WmiPermConsumer &&
                evt.EventId != WmiPermBinding)
                return;

            string payload = "";
            if (evt.UserData != IntPtr.Zero && evt.UserDataLength >= 4)
                payload = TryExtractUnicodeString(evt.UserData, 0, evt.UserDataLength) ?? "";

            int pid = evt.ProcessId;
            if (pid <= 4)
                pid = WmiPersistenceSignals.TryGetLiveWmiHostPid();

            string processName = "WmiPrvSE.exe";
            try
            {
                if (pid > 4)
                    processName = Process.GetProcessById(pid).ProcessName;
            }
            catch { }

            bool permanent = evt.EventId == WmiPermConsumer || evt.EventId == WmiPermBinding;
            bool hostile = WmiPersistenceSignals.LooksHostile(payload);
            if (hostile)
                WmiPersistenceSignals.MarkHostileObserved();

            var detection = new DetectionEvent
            {
                RuleName = permanent
                    ? (hostile
                        ? "WMI Persistence: Hostile Event Subscription"
                        : "WMI-Activity: Permanent Consumer")
                    : "WMI-Activity: Temporary Consumer",
                Evidence = $"WMI-Activity Event {evt.EventId} PID={pid} payload='{(payload.Length > 200 ? payload.Substring(0, 200) : payload)}'",
                Reasoning = permanent
                    ? "Microsoft-Windows-WMI-Activity reported a permanent event consumer or filter-to-consumer binding (T1546.003). Polling WmiPersistenceMonitor is the fallback; this is the ~50ms path."
                    : "Temporary WMI event consumer registered. Observe fuel unless the payload is an executable LOLBin.",
                Confidence = hostile ? 0.92 : (permanent ? 0.78 : 0.55),
                Tier = hostile ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = processName,
                ProcessId = pid,
                SignalType = SignalType.SecurityEvasion,
                // Terminal WmiPersistence for both permanent branches: hostile ->
                // "WMI Persistence: Hostile Event Subscription" and non-hostile ->
                // "WMI-Activity: Permanent Consumer" both match WmiPersistence fragments.
                // The temporary branch matches no fragment and stays non-terminal today.
                Family = permanent ? (TerminalFamily?)TerminalFamily.WmiPersistence : null,
                Metadata = new Dictionary<string, string>
                {
                    { "WmiActivityEventId", evt.EventId.ToString() },
                    { "HostileConsumer", hostile ? "true" : "false" },
                }
            };

            try { _ = _detectionEngine.EmitAsync(detection); }
            catch { }
        }

        // 
        // Helpers
        // 

        private static string TryExtractFilePath(EtwRawEvent evt)
        {
            // Kernel-File NameCreate/NameDelete events include the filename in UserData
            // Layout: FileObject(8) + IRQL(1) + ... + FileName(UnicodeString)
            // Simplified: try to read a Unicode string starting after the first 8 bytes
            if (evt.UserDataLength < 16) return "";
            return TryExtractUnicodeString(evt.UserData, 8, evt.UserDataLength - 8);
        }

        private static string TryExtractUnicodeString(IntPtr data, int offset, int maxBytes)
        {
            try
            {
                if (data == IntPtr.Zero || maxBytes <= 0) return "";

                // Scan for a null-terminated Unicode string starting at offset
                int remaining = maxBytes - offset;
                if (remaining <= 0) return "";

                int maxChars = Math.Min(remaining / 2, SecurityFileScope.MaxEtwPathChars);
                var sb = new StringBuilder(maxChars);

                for (int i = 0; i < maxChars; i++)
                {
                    char c = (char)Marshal.ReadInt16(data, offset + i * 2);
                    if (c == '\0') break;
                    if (c < 32 && c != '\t') break; // Non-printable = corrupt
                    sb.Append(c);
                }

                return sb.Length > 0 ? sb.ToString() : "";
            }
            catch { return ""; }
        }
    }

    // 
    // New Telemetry Types for ETW-sourced events
    // 

    /// <summary>Registry operation telemetry from Kernel-Registry ETW provider.</summary>
    public class RegistryTelemetry : TelemetryEvent
    {
        public string OperationType { get; set; } = "";
        public string KeyPath { get; set; } = "";
        public string ValueName { get; set; } = "";
    }

    /// <summary>DNS query telemetry from DNS-Client ETW provider.</summary>
    public class DnsTelemetry : TelemetryEvent
    {
        public string QueryName { get; set; } = "";
        public string EventType { get; set; } = ""; // QUERY or RESPONSE
        public string ResponseData { get; set; } = "";
    }

    /// <summary>Firewall rule change telemetry.</summary>
    public class FirewallTelemetry : TelemetryEvent
    {
        public string Action { get; set; } = "";
        public string RuleName { get; set; } = "";
    }

    /// <summary>Task Scheduler operation telemetry.</summary>
    public class TaskSchedulerTelemetry : TelemetryEvent
    {
        public string Action { get; set; } = "";
        public string TaskName { get; set; } = "";
        public string TaskPath { get; set; } = "";
    }
}
