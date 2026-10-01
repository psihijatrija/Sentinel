using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Unified ETW real-time session - subscribes to multiple system providers simultaneously.
    /// Replaces poll-based monitoring with event-driven telemetry at ~50ms latency.
    /// 
    /// v1.5.5: Fully implemented using buffer-offset P/Invoke approach.
    /// Instead of marshaling complex nested structs (EVENT_TRACE_PROPERTIES contains WNODE_HEADER,
    /// EVENT_TRACE_LOGFILEW contains EVENT_TRACE + TRACE_LOGFILE_HEADER), we allocate raw buffers
    /// and write fields at known offsets. This avoids struct alignment issues across Windows builds.
    /// 
    /// Architecture:
    ///   - StartAsync() creates the "SentinelUnifiedTrace" session via StartTraceW
    ///   - Enables 10 providers via EnableTraceEx2
    ///   - A dedicated background thread calls OpenTrace + ProcessTrace (blocking)
    ///   - Event callbacks dispatch to registered handlers by provider GUID
    ///   - StopAsync() calls ControlTrace(STOP) and waits for the processing thread to exit
    /// </summary>
    public sealed class UnifiedEtwSession : IDisposable
    {
        private readonly ILogger<UnifiedEtwSession> _logger;
        private readonly ConcurrentDictionary<Guid, Action<EtwRawEvent>> _handlers = new();

        private long _sessionHandle;
        private long _traceHandle = INVALID_PROCESSTRACE_HANDLE;
        private Thread? _processingThread;
        private volatile bool _stopping;
        private IntPtr _propertiesBuffer = IntPtr.Zero;

        private long _eventsProcessed;
        private long _eventsDropped;

        /// <summary>True if the ETW session started successfully and is actively processing.</summary>
        public bool IsActive { get; private set; }
        public long EventsProcessed => Interlocked.Read(ref _eventsProcessed);
        public long EventsDropped => Interlocked.Read(ref _eventsDropped);

        private const string SessionName = "SentinelUnifiedTrace";
        private const long INVALID_PROCESSTRACE_HANDLE = -1; // INVALID_PROCESSTRACE_HANDLE on x64

        // ETW constants
        private const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
        private const uint WNODE_FLAG_TRACED_GUID = 0x00020000;
        private const uint EVENT_TRACE_CONTROL_STOP = 1;
        private const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
        private const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
        private const byte TRACE_LEVEL_VERBOSE = 5;
        private const ulong MATCH_ANY_KEYWORD = 0xFFFFFFFFFFFFFFFF;
        private const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;

        // Request that ETW attach a captured call stack to each event from the provider.
        // Scoped to the Threat-Intelligence provider only: stacks can push an event past
        // the 64 KB ETW event ceiling (causing a drop), and broad stack walks were the
        // historical LatencyMon hard-fault source, so we never enable this globally.
        private const uint EVENT_ENABLE_PROPERTY_STACK_TRACE = 0x00000004;
        private const uint ENABLE_TRACE_PARAMETERS_VERSION_2 = 2;

        // EVENT_HEADER extended-data item type for a 64-bit captured stack trace.
        private const ushort EVENT_HEADER_EXT_TYPE_STACK_TRACE64 = 0x0005;

        // Ignore kernel-mode return addresses: on x64 user-mode addresses are below this.
        // Frames at/above this are kernel space and out of scope for userland analysis.
        private const ulong KernelSpaceThreshold = 0x0000_8000_0000_0000UL;
        private const int MaxStackFrames = 64;

        // WNODE_HEADER offsets (x64)
        private const int WNODE_BufferSize_Offset = 0;          // ULONG  (4)
        private const int WNODE_ProviderId_Offset = 4;          // ULONG  (4)
        private const int WNODE_HistoricalContext_Offset = 8;   // ULONG64 (8)
        private const int WNODE_TimeStamp_Offset = 16;          // LARGE_INTEGER (8)
        private const int WNODE_Guid_Offset = 24;               // GUID (16)
        private const int WNODE_ClientContext_Offset = 40;      // ULONG (4) - clock resolution
        private const int WNODE_Flags_Offset = 44;              // ULONG (4)
        private const int WNODE_SIZE = 48;

        // EVENT_TRACE_PROPERTIES offsets after WNODE_HEADER
        private const int ETP_BufferSize_Offset = WNODE_SIZE + 0;       // ULONG (4) - KB per buffer
        private const int ETP_MinimumBuffers_Offset = WNODE_SIZE + 4;   // ULONG (4)
        private const int ETP_MaximumBuffers_Offset = WNODE_SIZE + 8;   // ULONG (4)
        private const int ETP_MaximumFileSize_Offset = WNODE_SIZE + 12; // ULONG (4)
        private const int ETP_LogFileMode_Offset = WNODE_SIZE + 16;     // ULONG (4)
        private const int ETP_FlushTimer_Offset = WNODE_SIZE + 20;      // ULONG (4)
        private const int ETP_EnableFlags_Offset = WNODE_SIZE + 24;     // ULONG (4)
        private const int ETP_AgeLimit_Offset = WNODE_SIZE + 28;        // LONG  (4)
        private const int ETP_NumberOfBuffers_Offset = WNODE_SIZE + 32; // ULONG (4)
        private const int ETP_FreeBuffers_Offset = WNODE_SIZE + 36;     // ULONG (4)
        private const int ETP_EventsLost_Offset = WNODE_SIZE + 40;      // ULONG (4)
        private const int ETP_BuffersWritten_Offset = WNODE_SIZE + 44;  // ULONG (4)
        private const int ETP_LogBuffersLost_Offset = WNODE_SIZE + 48;  // ULONG (4)
        private const int ETP_RealTimeBuffersLost_Offset = WNODE_SIZE + 52; // ULONG (4)
        private const int ETP_LoggerThreadId_Offset = WNODE_SIZE + 56;  // HANDLE (8 on x64)
        private const int ETP_LogFileNameOffset_Offset = WNODE_SIZE + 64; // ULONG (4)
        private const int ETP_LoggerNameOffset_Offset = WNODE_SIZE + 68;  // ULONG (4)
        private const int ETP_STRUCT_SIZE = WNODE_SIZE + 72; // Total fixed portion

        // Provider GUIDs
        public static class Providers
        {
            public static readonly Guid KernelProcess = new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");
            public static readonly Guid KernelFile = new("EDD08927-9CC4-4E65-B970-C2560FB5C289");
            public static readonly Guid KernelRegistry = new("70EB4F03-C1DE-4F73-A051-33D13D5413BD");
            public static readonly Guid DnsClient = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
            public static readonly Guid ThreatIntelligence = new("F4E1897C-BB5D-5668-F1D8-040F4D8DD344");
            public static readonly Guid PowerShell = new("A0C1853B-5C40-4B15-8766-3CF1C58F985A");
            public static readonly Guid Firewall = new("D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85");
            public static readonly Guid TaskScheduler = new("DE7B24EA-73C8-4A09-985D-5BDADCFA9017");
            public static readonly Guid KernelNetwork = new("7DD42A49-5329-4832-8DFD-43D979153A88");
            // Microsoft-Windows-WMI-Activity - filter/consumer/binding create (5859-5861)
            public static readonly Guid WmiActivity = new("1418EF04-B0B4-4623-BF7B-2DE461B4F4CB");
        }

        #region Native P/Invoke

        [DllImport("advapi32.dll", EntryPoint = "StartTraceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint StartTraceW(out long sessionHandle, string sessionName, IntPtr properties);

        [DllImport("advapi32.dll", EntryPoint = "ControlTraceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint ControlTraceW(long sessionHandle, string? sessionName, IntPtr properties, uint controlCode);

        [DllImport("advapi32.dll", EntryPoint = "EnableTraceEx2", SetLastError = true)]
        private static extern uint EnableTraceEx2(long traceHandle, ref Guid providerId, uint controlCode,
            byte level, ulong matchAnyKeyword, ulong matchAllKeyword, uint timeout, IntPtr enableParameters);

        [DllImport("advapi32.dll", EntryPoint = "OpenTraceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern long OpenTraceW(ref EVENT_TRACE_LOGFILEW logfile);

        [DllImport("advapi32.dll", EntryPoint = "ProcessTrace", SetLastError = true)]
        private static extern uint ProcessTrace(long[] handleArray, uint handleCount, IntPtr startTime, IntPtr endTime);

        [DllImport("advapi32.dll", EntryPoint = "CloseTrace", SetLastError = true)]
        private static extern uint CloseTrace(long traceHandle);

        // Delegate types for ETW callbacks
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void EventRecordCallbackDelegate(ref EVENT_RECORD eventRecord);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint BufferCallbackDelegate(ref EVENT_TRACE_LOGFILEW logfile);

        // EVENT_TRACE_LOGFILEW - using explicit layout for the fields we need.
        // The full struct is very large due to embedded EVENT_TRACE and TRACE_LOGFILE_HEADER.
        // We only set the fields OpenTrace requires for real-time consumption and let the
        // rest be zero-initialized (which is valid for real-time mode).
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct EVENT_TRACE_LOGFILEW
        {
            public IntPtr LogFileName;        // LPWSTR - NULL for real-time
            public IntPtr LoggerName;         // LPWSTR - session name for real-time
            public long CurrentTime;          // LONGLONG (output)
            public uint BuffersRead;          // ULONG (output)
            public uint ProcessTraceMode;     // ULONG - processing flags
            // EVENT_TRACE CurrentEvent - 176 bytes on x64
            // We need to pad this correctly. EVENT_TRACE on x64:
            //   WNODE_HEADER (48) + BufferContext (4) + ... remainder
            // Actually the exact EVENT_TRACE layout varies. For OpenTrace input, we only
            // set LoggerName, ProcessTraceMode, EventRecordCallback, and Context.
            // The trick: put the struct in a large byte array padding and only set the offsets.
            // Alternatively, we use a flat buffer approach below.
            // SIMPLIFICATION: We use Marshal.AllocHGlobal for a zeroed buffer and write
            // fields at known offsets rather than define this complex struct.
            public long Padding_CurrentEvent_0;
            public long Padding_CurrentEvent_1;
            public long Padding_CurrentEvent_2;
            public long Padding_CurrentEvent_3;
            public long Padding_CurrentEvent_4;
            public long Padding_CurrentEvent_5;
            public long Padding_CurrentEvent_6;
            public long Padding_CurrentEvent_7;
            public long Padding_CurrentEvent_8;
            public long Padding_CurrentEvent_9;
            public long Padding_CurrentEvent_10;
            public long Padding_CurrentEvent_11;
            public long Padding_CurrentEvent_12;
            public long Padding_CurrentEvent_13;
            public long Padding_CurrentEvent_14;
            public long Padding_CurrentEvent_15;
            public long Padding_CurrentEvent_16;
            public long Padding_CurrentEvent_17;
            public long Padding_CurrentEvent_18;
            public long Padding_CurrentEvent_19;
            public long Padding_CurrentEvent_20;
            public long Padding_CurrentEvent_21; // 176 bytes = 22 * 8
            // TRACE_LOGFILE_HEADER LogfileHeader - ~280 bytes on x64 = 35 * 8
            public long Padding_LogfileHeader_0;
            public long Padding_LogfileHeader_1;
            public long Padding_LogfileHeader_2;
            public long Padding_LogfileHeader_3;
            public long Padding_LogfileHeader_4;
            public long Padding_LogfileHeader_5;
            public long Padding_LogfileHeader_6;
            public long Padding_LogfileHeader_7;
            public long Padding_LogfileHeader_8;
            public long Padding_LogfileHeader_9;
            public long Padding_LogfileHeader_10;
            public long Padding_LogfileHeader_11;
            public long Padding_LogfileHeader_12;
            public long Padding_LogfileHeader_13;
            public long Padding_LogfileHeader_14;
            public long Padding_LogfileHeader_15;
            public long Padding_LogfileHeader_16;
            public long Padding_LogfileHeader_17;
            public long Padding_LogfileHeader_18;
            public long Padding_LogfileHeader_19;
            public long Padding_LogfileHeader_20;
            public long Padding_LogfileHeader_21;
            public long Padding_LogfileHeader_22;
            public long Padding_LogfileHeader_23;
            public long Padding_LogfileHeader_24;
            public long Padding_LogfileHeader_25;
            public long Padding_LogfileHeader_26;
            public long Padding_LogfileHeader_27;
            public long Padding_LogfileHeader_28;
            public long Padding_LogfileHeader_29;
            public long Padding_LogfileHeader_30;
            public long Padding_LogfileHeader_31;
            public long Padding_LogfileHeader_32;
            public long Padding_LogfileHeader_33;
            public long Padding_LogfileHeader_34; // 280 bytes = 35 * 8
            public IntPtr BufferCallback;     // PEVENT_TRACE_BUFFER_CALLBACKW
            public uint BufferSize;           // ULONG (output)
            public uint Filled;               // ULONG (output)
            public uint EventsLost;           // ULONG (output - not used)
            public IntPtr EventRecordCallback; // PEVENT_RECORD_CALLBACK or EventCallback
            public uint IsKernelTrace;        // ULONG (output)
            public IntPtr Context;            // PVOID - user context
        }

        // EVENT_RECORD - the struct delivered to EventRecordCallback
        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_RECORD
        {
            public EVENT_HEADER EventHeader;
            public ETW_BUFFER_CONTEXT BufferContext;
            public ushort ExtendedDataCount;
            public ushort UserDataLength;
            public IntPtr ExtendedData;
            public IntPtr UserData;
            public IntPtr UserContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_HEADER
        {
            public ushort Size;
            public ushort HeaderType;
            public ushort Flags;
            public ushort EventProperty;
            public uint ThreadId;
            public uint ProcessId;
            public long TimeStamp;
            public Guid ProviderId;
            public EVENT_DESCRIPTOR EventDescriptor;
            public long KernelTime_ProcessorTime; // union
            public Guid ActivityId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_DESCRIPTOR
        {
            public ushort Id;
            public byte Version;
            public byte Channel;
            public byte Level;
            public byte Opcode;
            public ushort Task;
            public ulong Keyword;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ETW_BUFFER_CONTEXT
        {
            public ushort ProcessorIndex; // union with ProcessorNumber
            public ushort LoggerId;
        }

        // One extended-data item appended after EVENT_RECORD. For a stack trace the
        // DataPtr points at an EVENT_EXTENDED_ITEM_STACK_TRACE64 (MatchId + address[]).
        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_HEADER_EXTENDED_DATA_ITEM
        {
            public ushort Reserved1;
            public ushort ExtType;
            public ushort Reserved2; // Linkage:1, Reserved2:15 packed as a ushort
            public ushort DataSize;
            public ulong DataPtr;
        }

        // ENABLE_TRACE_PARAMETERS (V2 layout). We only need Version + EnableProperty;
        // the remaining fields stay zeroed so ETW applies defaults.
        [StructLayout(LayoutKind.Sequential)]
        private struct ENABLE_TRACE_PARAMETERS
        {
            public uint Version;
            public uint EnableProperty;
            public uint ControlFlags;
            public Guid SourceId;
            public IntPtr EnableFilterDesc;
            public uint FilterDescCount;
        }

        #endregion

        // Pin the delegate to prevent GC collection during native callback
        private EventRecordCallbackDelegate? _eventRecordCallback;
        private GCHandle _callbackHandle;
        private GCHandle _sessionNameHandle;

        public UnifiedEtwSession(ILogger<UnifiedEtwSession> logger)
        {
            _logger = logger;
        }

        public void RegisterHandler(Guid providerGuid, Action<EtwRawEvent> handler)
        {
            _handlers[providerGuid] = handler;
        }

        public Task StartAsync(CancellationToken ct)
        {
            try
            {
                // Stop any orphaned session with the same name (from a previous crash)
                StopOrphanedSession();

                // Allocate properties buffer: struct + session name + log file name (empty)
                int sessionNameBytes = (SessionName.Length + 1) * 2; // Unicode + null
                int totalSize = ETP_STRUCT_SIZE + sessionNameBytes + 2; // +2 for empty log file name null
                _propertiesBuffer = Marshal.AllocHGlobal(totalSize);
                NativeMemory.Clear(_propertiesBuffer, totalSize);

                // Write WNODE_HEADER fields
                Marshal.WriteInt32(_propertiesBuffer, WNODE_BufferSize_Offset, totalSize);
                Marshal.WriteInt32(_propertiesBuffer, WNODE_ClientContext_Offset, 1); // QPC timestamps
                Marshal.WriteInt32(_propertiesBuffer, WNODE_Flags_Offset, (int)WNODE_FLAG_TRACED_GUID);

                // Write EVENT_TRACE_PROPERTIES fields
                Marshal.WriteInt32(_propertiesBuffer, ETP_BufferSize_Offset, 256);  // 256 KB per buffer
                Marshal.WriteInt32(_propertiesBuffer, ETP_MinimumBuffers_Offset, 64);
                Marshal.WriteInt32(_propertiesBuffer, ETP_MaximumBuffers_Offset, 128);
                Marshal.WriteInt32(_propertiesBuffer, ETP_LogFileMode_Offset, (int)EVENT_TRACE_REAL_TIME_MODE);
                Marshal.WriteInt32(_propertiesBuffer, ETP_FlushTimer_Offset, 1); // 1 second flush
                Marshal.WriteInt32(_propertiesBuffer, ETP_LoggerNameOffset_Offset, ETP_STRUCT_SIZE);
                Marshal.WriteInt32(_propertiesBuffer, ETP_LogFileNameOffset_Offset, ETP_STRUCT_SIZE + sessionNameBytes);

                // Start the trace session
                uint result = StartTraceW(out _sessionHandle, SessionName, _propertiesBuffer);

                if (result != 0)
                {
                    _logger.LogWarning("[UnifiedEtwSession] StartTraceW failed with error {Error}. " +
                        "Monitors will use WMI/polling fallback. " +
                        "(0x000000B7 = session already exists, 5 = access denied - requires admin)", result);
                    FreePropertiesBuffer();
                    IsActive = false;
                    return Task.CompletedTask;
                }

                _logger.LogInformation("[UnifiedEtwSession] Session '{Name}' started (handle={Handle})", SessionName, _sessionHandle);

                // Enable all providers
                EnableProvider(Providers.KernelProcess);
                EnableProvider(Providers.KernelFile);
                EnableProvider(Providers.KernelRegistry);
                EnableProvider(Providers.DnsClient);
                // Threat-Intelligence: request captured call stacks so the dispatcher can
                // classify return frames against loaded modules (unbacked-frame detection).
                EnableProvider(Providers.ThreatIntelligence, captureStack: true);
                EnableProvider(Providers.PowerShell);
                EnableProvider(Providers.Firewall);
                EnableProvider(Providers.TaskScheduler);
                EnableProvider(Providers.KernelNetwork);
                EnableProvider(Providers.WmiActivity);

                // Start the processing thread
                _stopping = false;
                _processingThread = new Thread(ProcessTraceThread)
                {
                    Name = "SentinelEtwProcessor",
                    IsBackground = true,
                    Priority = ThreadPriority.AboveNormal
                };
                _processingThread.Start();

                IsActive = true;
                _logger.LogInformation("[UnifiedEtwSession] Real-time processing started. 10 providers enabled.");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[UnifiedEtwSession] Failed to start ETW session. " +
                    "Monitors will use WMI/polling fallback.");
                IsActive = false;
                FreePropertiesBuffer();
            }

            return Task.CompletedTask;
        }

        private void EnableProvider(Guid providerId, bool captureStack = false)
        {
            IntPtr enableParams = IntPtr.Zero;
            if (captureStack)
            {
                var p = new ENABLE_TRACE_PARAMETERS
                {
                    Version = ENABLE_TRACE_PARAMETERS_VERSION_2,
                    EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE
                };
                enableParams = Marshal.AllocHGlobal(Marshal.SizeOf<ENABLE_TRACE_PARAMETERS>());
                Marshal.StructureToPtr(p, enableParams, false);
            }

            try
            {
                uint result = EnableTraceEx2(
                    _sessionHandle,
                    ref providerId,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    TRACE_LEVEL_VERBOSE,
                    MATCH_ANY_KEYWORD,
                    0, // matchAllKeyword
                    0, // timeout
                    enableParams);

                if (result != 0)
                {
                    _logger.LogDebug("[UnifiedEtwSession] EnableTraceEx2 for {Provider} returned {Error}",
                        providerId, result);
                }
            }
            finally
            {
                if (enableParams != IntPtr.Zero)
                    Marshal.FreeHGlobal(enableParams);
            }
        }

        private void ProcessTraceThread()
        {
            try
            {
                // Set up the callback delegate and pin it
                _eventRecordCallback = OnEventRecord;
                _callbackHandle = GCHandle.Alloc(_eventRecordCallback);

                // Allocate the session name as a pinned string
                _sessionNameHandle = GCHandle.Alloc(SessionName, GCHandleType.Pinned);

                // Create EVENT_TRACE_LOGFILEW for OpenTrace
                var logfile = new EVENT_TRACE_LOGFILEW();
                logfile.LoggerName = Marshal.StringToHGlobalUni(SessionName);
                logfile.LogFileName = IntPtr.Zero;
                logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
                logfile.EventRecordCallback = Marshal.GetFunctionPointerForDelegate(_eventRecordCallback);
                logfile.Context = IntPtr.Zero;

                _traceHandle = OpenTraceW(ref logfile);

                // Free the allocated session name string
                Marshal.FreeHGlobal(logfile.LoggerName);

                if (_traceHandle == INVALID_PROCESSTRACE_HANDLE || _traceHandle == 0)
                {
                    var err = Marshal.GetLastWin32Error();
                    _logger.LogWarning("[UnifiedEtwSession] OpenTraceW failed (error={Error})", err);
                    IsActive = false;
                    return;
                }

                _logger.LogInformation("[UnifiedEtwSession] OpenTrace succeeded (handle={Handle}). Entering ProcessTrace loop.", _traceHandle);

                // ProcessTrace blocks until the session is stopped
                var handles = new long[] { _traceHandle };
                uint ptResult = ProcessTrace(handles, 1, IntPtr.Zero, IntPtr.Zero);

                if (ptResult != 0 && !_stopping)
                {
                    _logger.LogWarning("[UnifiedEtwSession] ProcessTrace returned {Error}", ptResult);
                }
            }
            catch (Exception ex)
            {
                if (!_stopping)
                {
                    _logger.LogError(ex, "[UnifiedEtwSession] ProcessTrace thread crashed");
                }
            }
            finally
            {
                if (_callbackHandle.IsAllocated) _callbackHandle.Free();
                if (_sessionNameHandle.IsAllocated) _sessionNameHandle.Free();
                IsActive = false;
            }
        }

        private void OnEventRecord(ref EVENT_RECORD eventRecord)
        {
            try
            {
                Interlocked.Increment(ref _eventsProcessed);

                var providerId = eventRecord.EventHeader.ProviderId;
                if (!_handlers.TryGetValue(providerId, out var handler))
                    return;

                var rawEvent = new EtwRawEvent
                {
                    ProviderId = providerId,
                    EventId = eventRecord.EventHeader.EventDescriptor.Id,
                    Version = eventRecord.EventHeader.EventDescriptor.Version,
                    Level = eventRecord.EventHeader.EventDescriptor.Level,
                    Opcode = eventRecord.EventHeader.EventDescriptor.Opcode,
                    Keyword = eventRecord.EventHeader.EventDescriptor.Keyword,
                    ProcessId = (int)eventRecord.EventHeader.ProcessId,
                    ThreadId = (int)eventRecord.EventHeader.ThreadId,
                    Timestamp = DateTime.FromFileTimeUtc(eventRecord.EventHeader.TimeStamp),
                    UserData = eventRecord.UserData,
                    UserDataLength = eventRecord.UserDataLength,
                    StackFrames = ExtractStackTrace(ref eventRecord)
                };

                handler(rawEvent);
            }
            catch
            {
                // Never throw from ETW callback - swallow all exceptions
                Interlocked.Increment(ref _eventsDropped);
            }
        }

        /// <summary>
        /// Extracts the user-mode return-address chain from an event's extended data,
        /// if a STACKWALK64 item is present. Returns an empty array when no stack was
        /// captured or the item is malformed. Must never throw (ETW callback contract).
        /// </summary>
        private static ulong[] ExtractStackTrace(ref EVENT_RECORD eventRecord)
        {
            try
            {
                int count = eventRecord.ExtendedDataCount;
                if (count <= 0 || eventRecord.ExtendedData == IntPtr.Zero)
                    return Array.Empty<ulong>();

                int itemSize = Marshal.SizeOf<EVENT_HEADER_EXTENDED_DATA_ITEM>();
                for (int i = 0; i < count; i++)
                {
                    IntPtr itemPtr = IntPtr.Add(eventRecord.ExtendedData, i * itemSize);
                    var item = Marshal.PtrToStructure<EVENT_HEADER_EXTENDED_DATA_ITEM>(itemPtr);
                    if (item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE64)
                        continue;
                    if (item.DataPtr == 0 || item.DataSize < 8)
                        continue;

                    // EVENT_EXTENDED_ITEM_STACK_TRACE64: ULONG64 MatchId, then ULONG64[] addresses.
                    IntPtr data = new IntPtr(unchecked((long)item.DataPtr));
                    int addrBytes = item.DataSize - 8; // subtract MatchId
                    int frames = Math.Min(addrBytes / 8, MaxStackFrames);
                    if (frames <= 0) return Array.Empty<ulong>();

                    var result = new List<ulong>(frames);
                    for (int f = 0; f < frames; f++)
                    {
                        ulong addr = unchecked((ulong)Marshal.ReadInt64(data, 8 + f * 8));
                        if (addr == 0) break; // zero terminates the usable chain
                        if (addr >= KernelSpaceThreshold) continue; // user-mode frames only
                        result.Add(addr);
                    }
                    return result.Count > 0 ? result.ToArray() : Array.Empty<ulong>();
                }
            }
            catch { /* never throw from the ETW callback */ }
            return Array.Empty<ulong>();
        }

        public Task StopAsync()
        {
            if (!IsActive && _sessionHandle == 0) return Task.CompletedTask;

            _stopping = true;

            try
            {
                // Close the trace handle first - this unblocks ProcessTrace
                if (_traceHandle != INVALID_PROCESSTRACE_HANDLE && _traceHandle != 0)
                {
                    CloseTrace(_traceHandle);
                    _traceHandle = INVALID_PROCESSTRACE_HANDLE;
                }

                // Stop the session
                if (_propertiesBuffer != IntPtr.Zero)
                {
                    // Need to reallocate or reuse properties buffer for the stop call
                    ControlTraceW(0, SessionName, _propertiesBuffer, EVENT_TRACE_CONTROL_STOP);
                }

                // Wait for processing thread to exit
                _processingThread?.Join(5000);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[UnifiedEtwSession] Error during stop");
            }
            finally
            {
                FreePropertiesBuffer();
                _sessionHandle = 0;
                _processingThread = null;
                IsActive = false;
            }

            _logger.LogInformation("[UnifiedEtwSession] Stopped. Processed={Processed}, Dropped={Dropped}",
                EventsProcessed, EventsDropped);

            return Task.CompletedTask;
        }

        /// <summary>
        /// v1.6.1: Restart the real-time session after external stop/tamper
        /// (e.g. logman stop SentinelUnifiedTrace / EDR killers).
        /// Registered provider handlers are preserved on the instance.
        /// </summary>
        public async Task<bool> RestartAsync(CancellationToken ct = default)
        {
            try
            {
                _logger.LogWarning("[UnifiedEtwSession] RestartAsync - stopping and recreating session");
                await StopAsync();
                // Brief pause so kernel releases the session name
                await Task.Delay(500, ct);
                await StartAsync(ct);
                return IsActive;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[UnifiedEtwSession] RestartAsync failed");
                IsActive = false;
                return false;
            }
        }

        /// <summary>
        /// Stops any orphaned session from a previous crash.
        /// If Sentinel crashes without stopping the session, it persists in the kernel
        /// and prevents a new session with the same name from being created.
        /// </summary>
        private void StopOrphanedSession()
        {
            try
            {
                int sessionNameBytes = (SessionName.Length + 1) * 2;
                int totalSize = ETP_STRUCT_SIZE + sessionNameBytes + 2;
                var buf = Marshal.AllocHGlobal(totalSize);
                try
                {
                    NativeMemory.Clear(buf, totalSize);
                    Marshal.WriteInt32(buf, WNODE_BufferSize_Offset, totalSize);
                    Marshal.WriteInt32(buf, WNODE_Flags_Offset, (int)WNODE_FLAG_TRACED_GUID);
                    Marshal.WriteInt32(buf, ETP_LoggerNameOffset_Offset, ETP_STRUCT_SIZE);
                    Marshal.WriteInt32(buf, ETP_LogFileNameOffset_Offset, ETP_STRUCT_SIZE + sessionNameBytes);

                    ControlTraceW(0, SessionName, buf, EVENT_TRACE_CONTROL_STOP);
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            catch { }
        }

        private void FreePropertiesBuffer()
        {
            if (_propertiesBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_propertiesBuffer);
                _propertiesBuffer = IntPtr.Zero;
            }
        }

        public void Dispose()
        {
            if (IsActive)
            {
                StopAsync().GetAwaiter().GetResult();
            }
            FreePropertiesBuffer();
        }

        /// <summary>
        /// Helper to zero-initialize native memory.
        /// </summary>
        private static class NativeMemory
        {
            public static void Clear(IntPtr ptr, int size)
            {
                // Zero out the buffer byte by byte using Marshal
                for (int i = 0; i < size; i++)
                {
                    Marshal.WriteByte(ptr, i, 0);
                }
            }
        }
    }

    /// <summary>
    /// Lightweight struct representing a raw ETW event delivered to registered handlers.
    /// </summary>
    public struct EtwRawEvent
    {
        public Guid ProviderId;
        public ushort EventId;
        public byte Version;
        public byte Level;
        public byte Opcode;
        public ulong Keyword;
        public int ProcessId;
        public int ThreadId;
        public DateTime Timestamp;
        public IntPtr UserData;
        public ushort UserDataLength;

        /// <summary>
        /// User-mode return-address chain captured with the event (STACKWALK64), when the
        /// provider was enabled with stack capture. Empty when no stack was attached.
        /// </summary>
        public ulong[] StackFrames;
    }
}
