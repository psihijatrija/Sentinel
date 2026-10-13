using System;
using System.Collections.Generic;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.3.1 - Always-on policies that CANNOT be disabled by configuration, observe-until-chain,
    /// tier law, or any future code changes. These represent fundamental product invariants:
    ///
    /// 1. GAME PROTECTION: Never kill, quarantine, memory-inspect, or FreeLibrary game processes.
    /// 2. DLL UNLOAD: Always remediate hostile module identity violations immediately.
    ///
    /// These are NOT detection rules (they don't fire detections). They are response-level
    /// hard stops that override all other logic. Checked before observe-until-chain, before
    /// tier law, before allowlist evaluation.
    ///
    /// SECURITY: These cannot be weakened by:
    ///   - Setting ObserveUntilChain=false
    ///   - Changing ActiveResponse
    ///   - Adding/removing allowlist entries
    ///   - Rule pack configuration
    ///   - MinTier1Confidence tuning
    ///
    /// To modify these policies, you must edit THIS FILE. That's the point.
    /// </summary>
    public static class AlwaysOnPolicies
    {
        // 
        // POLICY 1: GAME PROTECTION
        // Games with Denuvo/BattlEye/EAC/Vanguard self-terminate on VM_READ.
        // Anti-cheat processes crash if FreeLibrary'd or quarantined.
        // This policy guarantees Sentinel never interferes with interactive
        // entertainment workloads.
        // 

        /// <summary>
        /// Master gate for game protection. Returns true if the given process/path
        /// is a game or anti-cheat workload that must NEVER receive destructive actions.
        ///
        /// When this returns true, the caller MUST:
        ///   - Skip PROCESS_VM_READ (memory inspection)
        ///   - Skip FreeLibrary (DLL unload)
        ///   - Skip quarantine of the binary
        ///   - Skip process termination (kill/kill-tree)
        ///   - Demote any detection to LogOnly
        ///
        /// This method consolidates SecurityValidation.IsGameOrAntiCheatProcess
        /// as the single authoritative check. All call sites should use this.
        /// </summary>
        public static bool IsProtectedGameProcess(int pid, string? imagePath = null)
        {
            return SecurityValidation.IsGameOrAntiCheatProcess(pid, imagePath);
        }

        /// <summary>
        /// Path-only check (when PID is unavailable or already exited).
        /// Returns true if the binary resides in a known game installation directory.
        /// </summary>
        public static bool IsProtectedGamePath(string? path)
        {
            return SecurityValidation.IsGameOrAntiCheatPath(path);
        }

        /// <summary>
        /// Process-name-only check (startup race: path not yet resolvable).
        /// Returns true if the process name matches known game/anti-cheat basenames.
        /// Name-only is NOT a trust grant - only prevents memory inspection that would
        /// trigger Denuvo self-exit.
        /// </summary>
        public static bool IsProtectedGameProcessName(string? processName)
        {
            return SecurityValidation.IsKnownGameProcessName(processName);
        }

        /// <summary>
        /// Applies game protection to a detection event. If the detection targets a
        /// game process, forces LogOnly response and marks it as game-protected.
        /// Returns true if protection was applied (caller should return early).
        /// </summary>
        public static bool ApplyGameProtection(DetectionEvent detection, string? imagePath)
        {
            if (detection == null) return false;

            // v2.5.3: path identity only. steam.exe in Temp is not a game.
            // Name-only skip stays in CanInspect (Denuvo handle safety), never here.
            if (string.IsNullOrEmpty(imagePath) || !IsProtectedGamePath(imagePath))
                return false;

            // Force LogOnly - game processes are NEVER subject to destructive response.
            detection.Tier = DetectionTier.Tier2Indicator;
            detection.AuthorizedResponse = ResponseAction.LogOnly;
            detection.Metadata ??= new Dictionary<string, string>();
            detection.Metadata["AlwaysOnPolicy"] = "GameProtection";
            detection.Metadata["GameProtected"] = "true";
            return true;
        }

        // 
        // POLICY 2: DLL UNLOAD (MODULE IDENTITY)
        // Foreign/hostile module identity violations are remediated immediately.
        // This is permanent product law - NOT gated on ObserveUntilChain,
        // NOT gated on ActiveResponse, NOT suppressible by allowlist.
        // 

        /// <summary>
        /// Returns true if a detection represents a DLL unload/module identity action
        /// that must ALWAYS be permitted to act, regardless of observe-until-chain
        /// or other response gates.
        ///
        /// When this returns true, the response engine MUST:
        ///   - Keep Tier1 status (never demote to Tier2)
        ///   - Allow FreeLibrary/quarantine to proceed
        ///   - NOT gate on ObserveUntilChain
        ///   - NOT gate on ActiveResponse config
        ///   - NOT suppress via allowlist
        /// </summary>
        public static bool IsDllUnloadAlwaysOn(DetectionEvent? detection)
        {
            if (detection == null) return false;

            // Check explicit metadata markers (set by DllUnloadEngine when emitting)
            if (detection.Metadata != null)
            {
                if (detection.Metadata.TryGetValue("AlwaysOnPolicy", out var policy) &&
                    string.Equals(policy, "DllUnload", StringComparison.OrdinalIgnoreCase))
                    return true;

                if (detection.Metadata.TryGetValue("PermanentRule", out var perm) &&
                    string.Equals(perm, "ModuleIdentityUnload", StringComparison.OrdinalIgnoreCase))
                    return true;

                // Explicit DllUnloadExempt flag (set directly by DllUnloadEngine emissions)
                if (detection.Metadata.TryGetValue("DllUnloadExempt", out var flag) &&
                    string.Equals(flag, "true", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Name-based match: only the proven-remediation rule names, NOT observe-only plants.
            // ResponsePolicy.IsPermanentModuleIdentityUnload is the authoritative name check.
            return ResponsePolicy.IsPermanentModuleIdentityUnload(detection);
        }

        /// <summary>
        /// Returns true if the DLL unload action itself is permitted for the given PID.
        /// Game processes are excluded even from DLL unload (handle safety / anti-cheat crash).
        /// </summary>
        public static bool MayUnloadDllsFrom(int processId, string? imagePath = null)
        {
            // Game protection takes precedence over DLL unload
            if (IsProtectedGameProcess(processId, imagePath))
                return false;

            // Everything else is fair game for module identity enforcement
            return true;
        }
    }
}
