using System;
using System.IO;

namespace NanoAV
{
    // Invoke-ThreatAnalysis + Block-FileExecution.
    internal static class ThreatAnalysis
    {
        public static void Analyze(string filePath)
        {
            if (SentinelCoexistence.IsProtectedFile(filePath)) return;
            try
            {
                if (!File.Exists(filePath)) return;
            }
            catch { return; }

            if (FileScanner.ShouldExclude(filePath)) return;

            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (!Config.MonitoredExtensions.Contains(ext)) return;

            string fileHash = FileScanner.GetFileHash(filePath);
            if (fileHash == null) return;

            bool isSafe;
            if (Database.TryGet(fileHash, out isSafe))
            {
                if (!isSafe && File.Exists(filePath))
                {
                    Logger.Log("Known bad file re-detected - HARD DELETING: " + filePath +
                        " (hash: " + fileHash + ")");
                    try
                    {
                        File.Delete(filePath);
                        Logger.Log("Successfully deleted known-bad file: " + filePath);
                        Alerts.Send("HIGH", "Known-bad file auto-deleted", filePath);
                    }
                    catch (Exception ex)
                    {
                        Logger.Log("Delete failed - falling back to quarantine: " + ex.Message);
                        FileScanner.MoveToQuarantine(filePath, "Known threat (delete failed)");
                    }
                }
                return;
            }

            if (ThreatIntel.CirclHashLookup(fileHash))
            {
                Database.SNanoAVe(fileHash, true);
                Logger.Log("ALLOWED (CIRCL known-good): " + filePath);
                return;
            }

            if (ThreatIntel.CymruMalwareHash(fileHash))
            {
                Database.SNanoAVe(fileHash, false);
                FileScanner.MoveToQuarantine(filePath,
                    "Cymru MHR malware match (>= " + Config.CymruDetectionThreshold + "% detection)");
                return;
            }

            if (ThreatIntel.MalwareBazaarHash(fileHash))
            {
                Database.SNanoAVe(fileHash, false);
                FileScanner.MoveToQuarantine(filePath, "MalwareBazaar malware match");
                return;
            }

            if (FileScanner.IsSuspiciousUnsignedDll(filePath))
            {
                Database.SNanoAVe(fileHash, false);
                FileScanner.MoveToQuarantine(filePath,
                    "Suspicious unsigned DLL/WINMD in risky location");
                return;
            }

            FileScanner.SignatureInfo sig = FileScanner.GetSignatureInfo(filePath);
            if (sig != null)
            {
                bool valid = sig.Status == FileScanner.SignatureStatus.Valid;
                Database.SNanoAVe(fileHash, valid);
                if (valid)
                    Logger.Log("ALLOWED (digitally signed): " + filePath);
                else
                    Logger.Log("ALLOWED (unsigned but no threat indicators): " + filePath);
            }
        }

        public static void BlockFileExecution(string filePath, int processId, string type)
        {
            if (SentinelCoexistence.IsProtectedFile(filePath)) return;
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string blockEntry = timestamp + " | BLOCKED " + type + " | " + filePath + " | PID " + processId;
            try { File.AppendAllText(Config.BlockedLogFile, blockEntry + Environment.NewLine); }
            catch { }

            Logger.Log("BLOCKED " + type + " | " + filePath + " | PID " + processId);

            try
            {
                var p = System.Diagnostics.Process.GetProcessById(processId);
                if (p != null && !Config.ProtectedProcesses.Contains(p.ProcessName))
                {
                    SentinelCoexistence.KillUnlessSentinel(p);
                    Logger.Log("Killed process PID " + processId);
                }
            }
            catch { }

            if (File.Exists(filePath))
                FileScanner.MoveToQuarantine(filePath, "Real-time " + type + " block");
        }
    }
}
