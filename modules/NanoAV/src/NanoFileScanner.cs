using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NanoAV
{
    // File-level helpers: Get-FileHashSafe, Get-AuthenticodeSignature,
    // Test-ShouldExclude, Test-SuspiciousUnsignedDll, Test-FileLocked,
    // Set-FileOwnership, Move-ToQuarantine, Stop-ProcessesUsingFile.
    internal static class FileScanner
    {
        public static bool ShouldExclude(string filePath)
        {
            if (SentinelCoexistence.IsProtectedFile(filePath)) return true;
            string lower = filePath.ToLowerInvariant();
            if (lower.Contains(@"\assembly\")) return true;
            if (lower.Contains(@"\winsxs\")) return true;
            if (lower.Contains(@"\microsoft.net\")) return true;
            if (lower.Contains(@"\windows\system32\config\")) return true;
            if (lower.Contains("ctfmon") || lower.EndsWith("msctf.dll") || lower.EndsWith("msutb.dll"))
                return true;
            return false;
        }

        public static string GetFileHash(string filePath)
        {
            if (!File.Exists(filePath)) return null;
            try
            {
                using (var sha = SHA256.Create())
                using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] hash = sha.ComputeHash(fs);
                    var sb = new StringBuilder(hash.Length * 2);
                    foreach (byte b in hash) sb.Append(b.ToString("x2"));
                    return sb.ToString();
                }
            }
            catch { return null; }
        }

        public enum SignatureStatus { Valid, NotSigned, Invalid, Unknown }

        public sealed class SignatureInfo
        {
            public string Hash;
            public SignatureStatus Status;
            public string SignerName;
        }

        // Authenticode check without WinVerifyTrust pinvoke: load the embedded
        // cert and validate the chain, approximating Get-AuthenticodeSignature's
        // Valid/NotSigned/Invalid verdicts well enough for the heuristics here.
        public static SignatureStatus GetSignatureStatus(string filePath)
        {
            try
            {
                X509Certificate cert = X509Certificate.CreateFromSignedFile(filePath);
                var cert2 = new X509Certificate2(cert);
                var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                bool ok = chain.Build(cert2);
                return ok ? SignatureStatus.Valid : SignatureStatus.Invalid;
            }
            catch (CryptographicException)
            {
                // No embedded signature present.
                return SignatureStatus.NotSigned;
            }
            catch
            {
                return SignatureStatus.Unknown;
            }
        }

        public static SignatureInfo GetSignatureInfo(string filePath)
        {
            if (!File.Exists(filePath)) return null;
            try
            {
                var info = new SignatureInfo { Hash = GetFileHash(filePath) };
                try
                {
                    X509Certificate cert = X509Certificate.CreateFromSignedFile(filePath);
                    var cert2 = new X509Certificate2(cert);
                    info.SignerName = cert2.Subject;
                    var chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    info.Status = chain.Build(cert2) ? SignatureStatus.Valid : SignatureStatus.Invalid;
                }
                catch (CryptographicException) { info.Status = SignatureStatus.NotSigned; }
                return info;
            }
            catch { return null; }
        }

        public static bool IsSuspiciousUnsignedDll(string filePath)
        {
            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (ext != ".dll" && ext != ".winmd") return false;

            if (GetSignatureStatus(filePath) == SignatureStatus.Valid) return false;

            FileInfo fi;
            try { fi = new FileInfo(filePath); if (!fi.Exists) return false; }
            catch { return false; }

            double sizeKB = fi.Length / 1024.0;
            string pathLower = filePath.ToLowerInvariant();

            foreach (string risky in Config.RiskyPaths)
            {
                if (pathLower.Contains(risky) && sizeKB < Config.SuspiciousFileSizeKB)
                    return true;
            }

            if (pathLower.Contains(@"\appdata\roaming\") && sizeKB < 800)
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(
                        fi.Name, @"^[a-z0-9]{4,12}\.(dll|winmd)$",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                    return true;
            }
            return false;
        }

        public static bool IsFileLocked(string filePath)
        {
            try
            {
                using (File.Open(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
                return false;
            }
            catch { return true; }
        }

        public static void StopProcessesUsingFile(string filePath)
        {
            string fileName = Path.GetFileName(filePath);
            try
            {
                foreach (Process p in Process.GetProcesses())
                {
                    if (SentinelCoexistence.IsProtectedProcess(p)) { p.Dispose(); continue; }
                    bool uses = false;
                    try
                    {
                        foreach (ProcessModule m in p.Modules)
                        {
                            if (string.Equals(m.FileName, filePath, StringComparison.OrdinalIgnoreCase))
                            { uses = true; break; }
                        }
                    }
                    catch { }

                    if (uses && !Config.ProtectedProcesses.Contains(p.ProcessName))
                    {
                        Logger.Log("Stopping process " + p.ProcessName + " (PID: " + p.Id +
                            ") using file: " + filePath);
                        try
                        {
                            p.CloseMainWindow();
                            System.Threading.Thread.Sleep(500);
                            if (!p.HasExited) SentinelCoexistence.KillUnlessSentinel(p);
                        }
                        catch { }
                    }
                    try { p.Dispose(); } catch { }
                }
            }
            catch
            {
                // A module-name-wide taskkill could include Sentinel. Individual
                // targets above are checked; no uncheckable bulk-kill fallback.
                Logger.Log("Bulk module-name kill skipped to preserve Sentinel coexistence.");
            }
        }

        public static bool SetFileOwnership(string filePath)
        {
            if (SentinelCoexistence.IsProtectedFile(filePath)) return false;
            try
            {
                ProcessHelper.Run("takeown", "/F \"" + filePath + "\" /A");
                ProcessHelper.Run("icacls", "\"" + filePath + "\" /reset");
                ProcessHelper.Run("icacls", "\"" + filePath + "\" /grant \"Administrators:F\" /inheritance:d");
                Logger.Log("Set ownership and permissions for: " + filePath);
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to set ownership: " + ex.Message);
                return false;
            }
        }

        public static void MoveToQuarantine(string filePath, string reason)
        {
            if (SentinelCoexistence.IsProtectedFile(filePath)) return;
            if (!File.Exists(filePath))
            {
                Logger.Log("Cannot quarantine - file not found: " + filePath);
                return;
            }

            if (IsFileLocked(filePath))
            {
                StopProcessesUsingFile(filePath);
                System.Threading.Thread.Sleep(500);
            }

            string fileName = Path.GetFileName(filePath);
            string ts = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string backupPath = Path.Combine(Config.BackupDirectory, fileName + "_" + ts + ".bak");
            string quarantinePath = Path.Combine(Config.QuarantineDirectory, fileName + "_" + ts);

            try
            {
                File.Copy(filePath, backupPath, true);
                File.Move(filePath, quarantinePath);
                Logger.Log("QUARANTINED [" + reason + "]: " + filePath + " -> " + quarantinePath);
                Alerts.Send("HIGH", "File quarantined: " + reason, filePath);
            }
            catch (Exception ex)
            {
                Logger.Log("Quarantine failed for " + filePath + " : " + ex.Message);
                if (SetFileOwnership(filePath))
                {
                    try
                    {
                        File.Copy(filePath, backupPath, true);
                        File.Move(filePath, quarantinePath);
                        Logger.Log("QUARANTINED (after ownership fix) [" + reason + "]: " + filePath);
                    }
                    catch (Exception ex2)
                    {
                        Logger.Log("Quarantine still failed after ownership fix: " + ex2.Message);
                    }
                }
            }
        }
    }
}
