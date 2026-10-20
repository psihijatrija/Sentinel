using System;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace Sentinel.Core
{
    /// <summary>Records only children actually launched by the fixed firewall bridge. Never grants response immunity.</summary>
    public sealed class ManagementChildRegistry
    {
        private readonly ConcurrentDictionary<int, (DateTime Start, string Path)> _children = new();
        private readonly Func<int, (DateTime Start, string Path)?> _identity;
        public ManagementChildRegistry() : this(ReadIdentity) { }
        internal ManagementChildRegistry(Func<int, (DateTime Start, string Path)?> identity) { _identity = identity; }
        internal bool RegisterIdentity(int pid, DateTime start, string actualPath, string expectedPath, bool signatureVerified)
        {
            if (pid <= 0 || start == DateTime.MinValue || !signatureVerified ||
                !string.Equals(actualPath, expectedPath, StringComparison.OrdinalIgnoreCase)) return false;
            _children[pid] = (start, expectedPath);
            return true;
        }
        internal bool Register(Process child, string expectedPath)
        {
            try
            {
                // ProcessModule.get_FileName() can throw a bare NullReferenceException on .NET
                // Framework when the main module handle is unreadable (exited / protected /
                // cross-bitness process). A null-conditional on MainModule does NOT guard that
                // internal throw, so the NRE escaped and aborted every firewall reconciliation
                // pass. SafeGetMainModuleFileName() isolates and swallows it -> null -> no match.
                string? actual = SafeGetMainModuleFileName(child);
                if (actual == null ||
                    !string.Equals(actual, expectedPath, StringComparison.OrdinalIgnoreCase) ||
                    !SecurityValidation.VerifyAuthenticodeSignature(expectedPath)) return false;
                return RegisterIdentity(child.Id, child.StartTime.ToUniversalTime(), actual, expectedPath, true);
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception || ex is InvalidOperationException || ex is NotSupportedException || ex is NullReferenceException)
            { return false; } // Unknown identity receives no noise exemption.
        }

        /// <summary>
        /// Reads a process's main-module path without letting ProcessModule's internal
        /// NullReferenceException (unreadable module handle) escape. Any failure to resolve a
        /// trustworthy path returns null, which the callers treat as "unknown identity" and
        /// fail closed - no exemption is ever granted on an unresolved path.
        /// </summary>
        private static string? SafeGetMainModuleFileName(Process process)
        {
            try
            {
                if (process.HasExited) return null;
                string? path = process.MainModule?.FileName;
                return string.IsNullOrEmpty(path) ? null : path;
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception || ex is InvalidOperationException || ex is NotSupportedException || ex is NullReferenceException)
            {
                return null;
            }
        }
        internal void Remove(int pid) => _children.TryRemove(pid, out _);
        internal bool IsCurrentChild(int pid)
        {
            if (!_children.TryGetValue(pid, out var expected)) return false;
            var current = _identity(pid);
            if (current.HasValue && current.Value.Start == expected.Start &&
                string.Equals(current.Value.Path, expected.Path, StringComparison.OrdinalIgnoreCase)) return true;
            Remove(pid);
            return false;
        }
        private static (DateTime Start, string Path)? ReadIdentity(int pid)
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                if (process.HasExited) return null;
                string? path = SafeGetMainModuleFileName(process);
                if (!string.IsNullOrEmpty(path)) return (process.StartTime.ToUniversalTime(), path!);
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception || ex is InvalidOperationException || ex is ArgumentException || ex is NotSupportedException || ex is NullReferenceException)
            { /* Unavailable identity receives no exemption. */ }
            return null;
        }
        internal static bool IsRoutineObservation(DetectionEvent detection) =>
            detection.Tier == DetectionTier.Tier2Indicator && detection.AuthorizedResponse == ResponseAction.LogOnly &&
            detection.Confidence <= 0.65 &&
            (detection.RuleName == "PowerShell: Encoded Command Observation" ||
             detection.RuleName == "File Reputation: Suspicious Binary Executed" ||
             detection.RuleName == "Named Pipe: High-Entropy Name (Non-System Owner)");
    }
}
