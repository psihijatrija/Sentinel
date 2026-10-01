using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public sealed class ModuleAuditEntry
    {
        public string Name { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public string BaseAddressHex { get; set; } = string.Empty;
        public long BaseAddress { get; set; }
        public int Size { get; set; }
        public string SizeFormatted { get; set; } = string.Empty;
        public string Publisher { get; set; } = string.Empty;
        public bool IsSigned { get; set; }
        public bool IsMicrosoftSigned { get; set; }
        public bool IsKeepTree { get; set; }
        public bool IsAppDirectory { get; set; }
        public bool IsUserWritableDrop { get; set; }
        public bool Allowed { get; set; }
        public string VerdictReason { get; set; } = string.Empty;
        public string Md5Hash { get; set; } = string.Empty;
        public string Sha256Hash { get; set; } = string.Empty;
    }

    public sealed class ProcessModuleAuditResult
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string ImagePath { get; set; } = string.Empty;
        public bool Is64Bit { get; set; }
        public string CompanyName { get; set; } = string.Empty;
        public string Publisher { get; set; } = string.Empty;
        public bool IsSigned { get; set; }
        public DateTime AuditTimeUtc { get; set; } = DateTime.UtcNow;

        public int TotalModules { get; set; }
        public int SignedModules { get; set; }
        public int UnsignedModules { get; set; }
        public int AllowedModules { get; set; }
        public int SuspiciousModules { get; set; }
        public int MemoryAnomalyCount { get; set; }

        public List<ModuleAuditEntry> Modules { get; set; } = new();
        public List<MemoryAnomalyEntry> MemoryAnomalies { get; set; } = new();
    }

    public sealed class ProcessSummaryEntry
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string ImagePath { get; set; } = string.Empty;
        public int ModuleCount { get; set; }
        public bool IsProtected { get; set; }
    }

    /// <summary>
    /// Audits process modules and in-memory executable regions.
    /// Provides accurate triage and classification without the false positives of crude heuristics.
    /// </summary>
    public static class ProcessModuleAuditor
    {
        /// <summary>
        /// Audits all loaded modules and memory regions for a specific process ID.
        /// </summary>
        public static ProcessModuleAuditResult AuditProcess(int processId, SignerTrustService? signerTrust = null)
        {
            var result = new ProcessModuleAuditResult
            {
                ProcessId = processId,
                AuditTimeUtc = DateTime.UtcNow
            };

            if (processId <= 4)
            {
                result.ProcessName = processId == 0 ? "Idle" : "System";
                return result;
            }

            string? imagePath = null;
            try
            {
                imagePath = SecurityValidation.GetProcessImagePath(processId);
                result.ImagePath = imagePath ?? string.Empty;

                using var proc = Process.GetProcessById(processId);
                result.ProcessName = proc.ProcessName;

                if (!string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
                {
                    var vi = FileVersionInfo.GetVersionInfo(imagePath);
                    result.CompanyName = vi.CompanyName ?? string.Empty;
                }
            }
            catch { /* best effort */ }

            if (!NativeProcessMemory.CanInspect(processId, imagePath))
            {
                result.ProcessName = string.IsNullOrEmpty(result.ProcessName) ? $"PID_{processId}" : result.ProcessName;
                return result;
            }

            // Check signature of main process image
            if (!string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
            {
                var nonNullImagePath = imagePath!;
                if (signerTrust != null)
                {
                    result.IsSigned = signerTrust.IsSignedFile(nonNullImagePath);
                    result.Publisher = signerTrust.GetSignerName(nonNullImagePath) ?? string.Empty;
                }
                else
                {
                    var sigInfo = QuerySignature(nonNullImagePath);
                    result.IsSigned = sigInfo.IsSigned;
                    result.Publisher = sigInfo.Signer;
                }
            }

            // 1. Enumerate mapped modules
            var rawModules = NativeProcessMemory.EnumModules(processId);
            var procDir = string.IsNullOrEmpty(imagePath) ? string.Empty : (Path.GetDirectoryName(imagePath) ?? string.Empty);

            foreach (var mod in rawModules)
            {
                var entry = new ModuleAuditEntry
                {
                    Name = mod.Name,
                    Path = mod.Path,
                    BaseAddress = mod.Base.ToInt64(),
                    BaseAddressHex = $"0x{mod.Base.ToInt64():X16}",
                    Size = mod.Size,
                    SizeFormatted = FormatFileSize(mod.Size)
                };

                if (!string.IsNullOrEmpty(mod.Path) && File.Exists(mod.Path))
                {
                    // Signature check
                    if (signerTrust != null)
                    {
                        entry.IsSigned = signerTrust.IsSignedFile(mod.Path);
                        entry.Publisher = signerTrust.GetSignerName(mod.Path) ?? string.Empty;
                    }
                    else
                    {
                        var sigInfo = QuerySignature(mod.Path);
                        entry.IsSigned = sigInfo.IsSigned;
                        entry.Publisher = sigInfo.Signer;
                    }

                    entry.IsMicrosoftSigned = entry.IsSigned &&
                        (entry.Publisher.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0);

                    // Path trees
                    entry.IsKeepTree = ModuleIdentity.IsKeepTree(mod.Path);
                    entry.IsUserWritableDrop = ModuleIdentity.IsUserWritableDrop(mod.Path);
                    entry.IsAppDirectory = !string.IsNullOrEmpty(procDir) &&
                        ModuleIdentity.IsUnderDirectory(Path.GetDirectoryName(mod.Path), procDir);

                    // Sentinel verdict
                    var verdict = ModuleIdentity.Evaluate(imagePath, mod.Path, path =>
                    {
                        if (signerTrust != null)
                            return signerTrust.IsMicrosoftSigned(path);
                        return QuerySignature(path).IsMicrosoft;
                    });

                    entry.Allowed = verdict.Allowed;
                    entry.VerdictReason = verdict.Reason;

                    // Compute hashes for foreign/suspicious modules or upon request
                    if (!verdict.Allowed || entry.IsUserWritableDrop)
                    {
                        try
                        {
                            ComputeHashes(mod.Path, out string md5, out string sha256);
                            entry.Md5Hash = md5;
                            entry.Sha256Hash = sha256;
                        }
                        catch { }
                    }
                }
                else
                {
                    // Phantom module or empty path
                    entry.Allowed = false;
                    entry.VerdictReason = string.IsNullOrEmpty(mod.Path) ? "empty-path" : "file-not-found";
                }

                result.Modules.Add(entry);
            }

            // 2. Scan virtual memory for in-memory anomalies
            result.MemoryAnomalies = MemoryAnomalyScanner.ScanProcess(processId, imagePath);

            // 3. Compute statistics
            result.TotalModules = result.Modules.Count;
            result.SignedModules = result.Modules.Count(m => m.IsSigned);
            result.UnsignedModules = result.Modules.Count(m => !m.IsSigned);
            result.AllowedModules = result.Modules.Count(m => m.Allowed);
            result.SuspiciousModules = result.Modules.Count(m => !m.Allowed);
            result.MemoryAnomalyCount = result.MemoryAnomalies.Count;

            return result;
        }

        /// <summary>
        /// Retrieves a fast list of active processes for explorer selection.
        /// </summary>
        public static List<ProcessSummaryEntry> GetActiveProcesses()
        {
            var list = new List<ProcessSummaryEntry>();
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (p.Id <= 4) continue;
                    string name = p.ProcessName;
                    string path = SecurityValidation.GetProcessImagePath(p.Id) ?? string.Empty;
                    bool inspectable = NativeProcessMemory.CanInspect(p.Id, path);

                    list.Add(new ProcessSummaryEntry
                    {
                        ProcessId = p.Id,
                        ProcessName = name,
                        ImagePath = path,
                        IsProtected = !inspectable,
                        ModuleCount = 0
                    });
                }
                catch { }
                finally
                {
                    p.Dispose();
                }
            }

            return list.OrderBy(p => p.ProcessName, StringComparer.OrdinalIgnoreCase).ToList();
        }

        private static (bool IsSigned, bool IsMicrosoft, string Signer) QuerySignature(string path)
        {
            try
            {
                if (!File.Exists(path)) return (false, false, string.Empty);
                var cert = X509Certificate.CreateFromSignedFile(path);
                using var cert2 = new X509Certificate2(cert);
                string subject = cert2.Subject ?? string.Empty;
                string signer = cert2.GetNameInfo(X509NameType.SimpleName, false) ?? subject;
                bool isMs = signer.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            subject.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;
                return (true, isMs, signer);
            }
            catch
            {
                return (false, false, string.Empty);
            }
        }

        private static void ComputeHashes(string path, out string md5, out string sha256)
        {
            using var stream = File.OpenRead(path);
            using var md5Alg = MD5.Create();
            using var sha256Alg = SHA256.Create();

            byte[] md5Bytes = md5Alg.ComputeHash(stream);
            md5 = BitConverter.ToString(md5Bytes).Replace("-", "").ToLowerInvariant();

            stream.Position = 0;
            byte[] sha256Bytes = sha256Alg.ComputeHash(stream);
            sha256 = BitConverter.ToString(sha256Bytes).Replace("-", "").ToLowerInvariant();
        }

        private static string FormatFileSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes / (1024.0 * 1024.0):F2} MB";
        }
    }
}
