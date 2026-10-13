using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors for token manipulation and privilege escalation:
    /// - Processes with duplicated tokens from higher-integrity processes
    /// - Unexpected SYSTEM tokens in user-context processes
    /// - SeDebugPrivilege enabled in non-administrative processes
    /// Purely behavioral - detects anomalous privilege states.
    /// </summary>
    public sealed class TokenIntegrityMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<TokenIntegrityMonitor> _logger;
        private readonly System.Threading.Timer _timer;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(45);

        public TokenIntegrityMonitor(
            DetectionEngine detectionEngine,
            ILogger<TokenIntegrityMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _timer = new System.Threading.Timer(ScanTokens, null, ScanInterval, ScanInterval);
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
            IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetSidSubAuthorityCount(IntPtr pSid, out IntPtr pSubAuthorityCount);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenElevation = 20;
        private const int TokenUser = 1;
        private const int TokenIntegrityLevel = 25;

        // Windows integrity-level RIDs (the last sub-authority of the integrity SID
        // S-1-16-x). These are the documented SECURITY_MANDATORY_*_RID values.
        private const int SECURITY_MANDATORY_MEDIUM_RID = 0x2000;   // 8192  - normal user
        private const int SECURITY_MANDATORY_HIGH_RID = 0x3000;     // 12288 - elevated admin
        private const int SECURITY_MANDATORY_SYSTEM_RID = 0x4000;   // 16384 - SYSTEM/service

        private readonly HashSet<int> _alertedPids = new();

        /// <summary>
        /// The integrity level a process's token is running at, derived from the RID of its
        /// mandatory-integrity SID. This is a fact the process cannot fake without actually
        /// holding the token - it is what the process IS at the kernel's accounting, not what
        /// it is named. Used as the "the exploit succeeded" anchor for LPE chains.
        /// </summary>
        internal enum IntegrityLevel { Unknown = 0, Low, Medium, High, System }

        /// <summary>
        /// Classifies an integrity RID into a level. Pure and test-visible.
        /// </summary>
        internal static IntegrityLevel ClassifyIntegrityRid(int rid)
        {
            if (rid >= SECURITY_MANDATORY_SYSTEM_RID) return IntegrityLevel.System;
            if (rid >= SECURITY_MANDATORY_HIGH_RID) return IntegrityLevel.High;
            if (rid >= SECURITY_MANDATORY_MEDIUM_RID) return IntegrityLevel.Medium;
            return IntegrityLevel.Low;
        }

        private void ScanTokens(object? state)
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.Id <= 4) continue;
                        if (_alertedPids.Contains(proc.Id)) continue;

                        if (!OpenProcessToken(proc.Handle, TOKEN_QUERY, out var tokenHandle))
                            continue;

                        try
                        {
                            // Check TOKEN_ELEVATION
                            var elevBuffer = Marshal.AllocHGlobal(4);
                            try
                            {
                                if (GetTokenInformation(tokenHandle, TokenElevation, elevBuffer, 4, out _))
                                {
                                    int elevated = Marshal.ReadInt32(elevBuffer);
                                    if (elevated != 0)
                                    {
                                        // Elevated process - check if it's from a user-writable path
                                         string? imagePath = null;
                                         try { imagePath = SecurityValidation.GetProcessImagePath(proc.Id); } catch { }

                                         if (imagePath != null)
                                         {
                                             bool inUserPath = imagePath.Contains(@"\Temp\") ||
                                                               imagePath.Contains(@"\Downloads\") ||
                                                               imagePath.Contains(@"\AppData\");

                                             if (inUserPath)
                                             {
                                                 // Installers elevate from Temp/Downloads by design (Inno, WiX, MSI extract).
                                                 if (InstallerHeuristics.IsInstallerExtractor(proc.ProcessName, imagePath) ||
                                                     InstallerHeuristics.LooksLikeInstallerName(proc.ProcessName, imagePath))
                                                 {
                                                     _alertedPids.Add(proc.Id);
                                                     continue;
                                                 }

                                                 _ = _detectionEngine.EmitAsync(new DetectionEvent
                                                 {
                                                     RuleName = "Privilege Escalation: Elevated Process from User Path",
                                                     Evidence = $"Elevated process '{proc.ProcessName}' (PID {proc.Id}) running from '{imagePath}'",
                                                     Reasoning = "An elevated (admin) process is running from a user-writable directory, suggesting a privilege escalation or UAC bypass.",
                                                     Confidence = 0.80, Tier = DetectionTier.Tier2Indicator,
                                                     AuthorizedResponse = ResponseAction.LogOnly,
                                                     ProcessName = proc.ProcessName, ProcessId = proc.Id
                                                 });
                                                 _alertedPids.Add(proc.Id);
                                             }
                                         }
                                    }
                                }
                            }
                            finally { Marshal.FreeHGlobal(elevBuffer); }

                            // Integrity-level jump detection (the "exploit succeeded" anchor).
                            // A process running in an interactive USER session whose token has
                            // climbed to SYSTEM integrity is the observable footprint of a
                            // successful local privilege escalation. This is behavioral - it is
                            // the integrity level the kernel actually granted the token, not a
                            // filename or path. We only fire for a user-session process from a
                            // user-writable image (installers/servicing run at High by design and
                            // are anchored in trusted OS/Program Files trees).
                            TryDetectIntegrityJump(proc, tokenHandle);
                        }
                        finally { CloseHandle(tokenHandle); }
                    }
                    catch (InvalidOperationException) { }
                    catch (System.ComponentModel.Win32Exception) { }
                    catch { }
                    finally
                    {
                        proc.Dispose();
                    }
                }

                // Prune old PIDs
                if (_alertedPids.Count > 500) _alertedPids.Clear();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[TokenIntegrityMonitor] Scan error");
            }
        }

        /// <summary>
        /// Detects a genuine integrity-level jump: an interactive USER-session process, running
        /// from a user-writable image, whose token integrity has climbed to SYSTEM. This is the
        /// behavioral footprint of a completed local privilege escalation - the process now holds
        /// SYSTEM-grade integrity it should not have. Emitted as a kill-grade TokenTheft terminal.
        ///
        /// Adversarial reasoning: an attacker controls the filename and the drop path, so those
        /// alone never authorize anything (a lone drop is not even flagged here). What the
        /// attacker does NOT control is the integrity level the kernel accounts to the token -
        /// reaching SYSTEM integrity from a user session and a user-writable image is the proof
        /// that the escalation actually happened. Legitimate SYSTEM/service processes run in
        /// session 0 and/or from trusted OS trees, and are excluded.
        /// </summary>
        private void TryDetectIntegrityJump(Process proc, IntPtr tokenHandle)
        {
            try
            {
                if (_alertedPids.Contains(proc.Id)) return;

                var level = QueryIntegrityLevel(tokenHandle);
                if (level != IntegrityLevel.System) return; // only a jump to SYSTEM integrity

                // Session 0 is the service/SYSTEM session - SYSTEM integrity there is expected.
                // A jump to SYSTEM integrity inside an interactive user session (>= 1) is not.
                int session;
                try { session = proc.SessionId; } catch { return; }
                if (session == 0) return;

                string? imagePath = null;
                try { imagePath = SecurityValidation.GetProcessImagePath(proc.Id); } catch { }
                if (string.IsNullOrEmpty(imagePath)) return;

                // Anchor: only a user-writable image path is attacker-plantable. A SYSTEM-integrity
                // process backed by a trusted OS / Program Files tree is normal servicing, not an
                // escalation we should ever kill.
                bool userWritableImage =
                    imagePath!.IndexOf(@"\Temp\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    imagePath.IndexOf(@"\Downloads\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    imagePath.IndexOf(@"\AppData\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    imagePath.IndexOf(@"\Users\Public\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    imagePath.IndexOf(@"\PerfLogs\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    imagePath.IndexOf(@"\ProgramData\", StringComparison.OrdinalIgnoreCase) >= 0;
                if (!userWritableImage) return;

                // Installers legitimately run elevated from Temp/Downloads. High integrity is
                // their normal ceiling; SYSTEM integrity is not - so we do NOT exempt them here,
                // but we still guard the obvious signed-servicing extractor case.
                if (InstallerHeuristics.IsInstallerExtractor(proc.ProcessName, imagePath!))
                    return;

                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Privilege Escalation: Token Integrity Jump to SYSTEM",
                    Evidence = $"User-session process '{proc.ProcessName}' (PID {proc.Id}, session {session}) " +
                               $"from user-writable image '{imagePath}' is running at SYSTEM integrity.",
                    Reasoning = "A process in an interactive user session, launched from a user-writable directory, " +
                                "holds a SYSTEM-integrity token. This is the observable result of a successful local " +
                                "privilege escalation (kernel/driver LPE, potato-class token theft, or service abuse) - " +
                                "the process gained an integrity level it could not have started with. Kill-grade token theft.",
                    Confidence = 0.90,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.KillProcessTree,
                    ProcessName = proc.ProcessName,
                    ProcessId = proc.Id,
                    SignalType = SignalType.SuspiciousProcess,
                    Family = TerminalFamily.TokenTheft,
                    Metadata = new Dictionary<string, string>
                    {
                        ["IntegrityLevel"] = "System",
                        ["SessionId"] = session.ToString(),
                        ["ImagePath"] = imagePath!,
                        ["Technique"] = "T1134 (Access Token Manipulation) / T1068 (Exploitation for Privilege Escalation)",
                    }
                });
                _alertedPids.Add(proc.Id);
            }
            catch { /* process exited / access denied - degrade silently */ }
        }

        /// <summary>
        /// Reads a token's mandatory integrity level via TokenIntegrityLevel. Returns
        /// <see cref="IntegrityLevel.Unknown"/> on any failure (fail closed - never invents a jump).
        /// </summary>
        private IntegrityLevel QueryIntegrityLevel(IntPtr tokenHandle)
        {
            // First call to size the buffer.
            GetTokenInformation(tokenHandle, TokenIntegrityLevel, IntPtr.Zero, 0, out int needed);
            if (needed <= 0) return IntegrityLevel.Unknown;

            IntPtr buffer = Marshal.AllocHGlobal(needed);
            try
            {
                if (!GetTokenInformation(tokenHandle, TokenIntegrityLevel, buffer, needed, out _))
                    return IntegrityLevel.Unknown;

                // TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES Label }; Label.Sid is first field.
                IntPtr pSid = Marshal.ReadIntPtr(buffer); // Label.Sid
                if (pSid == IntPtr.Zero) return IntegrityLevel.Unknown;

                if (!GetSidSubAuthorityCount(pSid, out IntPtr pCount) || pCount == IntPtr.Zero)
                    return IntegrityLevel.Unknown;
                int count = Marshal.ReadByte(pCount);
                if (count <= 0) return IntegrityLevel.Unknown;

                // The integrity RID is the last sub-authority.
                IntPtr pRid = GetSidSubAuthority(pSid, (uint)(count - 1));
                if (pRid == IntPtr.Zero) return IntegrityLevel.Unknown;
                int rid = Marshal.ReadInt32(pRid);

                return ClassifyIntegrityRid(rid);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
