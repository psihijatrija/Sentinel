using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Plants multiple dummy credentials in Windows Credential Manager and monitors them.
    /// Any unauthorized access/modification indicates active credential harvesting.
    /// Purely behavioral honeypot - no tool names or signatures.
    /// 
    /// HARDENING: Uses randomized target names from a pool of realistic-looking templates.
    /// A credential dumping tool cannot trivially filter these by name since the names
    /// change every boot and look like legitimate service credentials.
    /// </summary>
    public sealed class CredentialCanaryMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CredentialCanaryMonitor> _logger;
        private readonly System.Threading.Timer _timer;

        // HARDENING: Randomized canary names from realistic service templates.
        // Previously used a fixed name ("WindowsBackup_AutoSync_Token") that any
        // credential dumper could be patched to skip in 30 seconds.
        private static readonly (string TargetTemplate, string Username, string Comment)[] CanaryTemplates = new[]
        {
            ("Exchange_SMTP_Relay_{0}", "svc_mail_relay", "Exchange SMTP relay service credential"),
            ("VPN_AutoConnect_{0}", "vpn_service", "Corporate VPN auto-connect token"),
            ("SharePoint_Sync_{0}", "sp_crawler", "SharePoint document sync credential"),
            ("Azure_DevOps_PAT_{0}", "devops_agent", "Azure DevOps build agent token"),
            ("SQL_Replication_{0}", "sql_repl_svc", "SQL Server replication service account"),
            ("SCCM_Client_Auth_{0}", "sccm_client", "SCCM client authentication credential"),
            ("Backup_Exec_Agent_{0}", "bkup_agent", "Backup Exec remote agent credential"),
            ("Print_Spooler_Svc_{0}", "print_svc", "Network print spooler service token"),
        };

        private readonly List<string> _plantedCanaryTargets = new();
        private readonly object _canaryLock = new();

        private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(15);

        public CredentialCanaryMonitor(
            DetectionEngine detectionEngine,
            ILogger<CredentialCanaryMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            PlantCanaries();
            _timer = new System.Threading.Timer(CheckCanaries, null, CheckInterval, CheckInterval);
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredWrite(ref CREDENTIAL credential, uint flags);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credential);

        [DllImport("advapi32.dll")]
        private static extern void CredFree(IntPtr buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public int Flags;
            public int Type;
            public string TargetName;
            public string Comment;
            public long LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        private const int CRED_TYPE_GENERIC = 1;
        private const int CRED_PERSIST_LOCAL_MACHINE = 2;

        private void PlantCanaries()
        {
            // Plant 3-5 randomized canaries from the template pool
            var rng = new Random();
            int count = 3 + rng.Next(3); // 3 to 5 canaries
            var shuffled = CanaryTemplates.OrderBy(_ => rng.Next()).Take(count).ToArray();

            foreach (var (targetTemplate, username, comment) in shuffled)
            {
                var suffix = Guid.NewGuid().ToString("N")[..6];
                var target = string.Format(targetTemplate, suffix);
                if (PlantSingleCanary(target, username, comment))
                {
                    lock (_canaryLock)
                    {
                        _plantedCanaryTargets.Add(target);
                    }
                }
            }

            _logger.LogDebug("[CredentialCanaryMonitor] Planted {Count} canary credentials", _plantedCanaryTargets.Count);
        }

        private bool PlantSingleCanary(string target, string username, string comment)
        {
            try
            {
                var password = "Svc_" + Guid.NewGuid().ToString("N")[..12] + "!";
                var passBytes = System.Text.Encoding.Unicode.GetBytes(password);
                var passPtr = Marshal.AllocHGlobal(passBytes.Length);
                Marshal.Copy(passBytes, 0, passPtr, passBytes.Length);

                var cred = new CREDENTIAL
                {
                    Type = CRED_TYPE_GENERIC,
                    TargetName = target,
                    UserName = username,
                    CredentialBlob = passPtr,
                    CredentialBlobSize = passBytes.Length,
                    Persist = CRED_PERSIST_LOCAL_MACHINE,
                    Comment = comment
                };

                bool success = CredWrite(ref cred, 0);
                Marshal.FreeHGlobal(passPtr);

                if (!success)
                {
                    _logger.LogDebug("[CredentialCanaryMonitor] CredWrite failed for '{Target}': {Error}",
                        target, Marshal.GetLastWin32Error());
                }
                return success;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[CredentialCanaryMonitor] Failed to plant canary '{Target}'", target);
                return false;
            }
        }

        private void CheckCanaries(object? state)
        {
            List<string> targets;
            lock (_canaryLock)
            {
                if (_plantedCanaryTargets.Count == 0) return;
                targets = new List<string>(_plantedCanaryTargets);
            }

            foreach (var target in targets)
            {
                try
                {
                    if (!CredRead(target, CRED_TYPE_GENERIC, 0, out var credPtr))
                    {
                        // Canary was deleted - credential harvester detected
                        _ = _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Credential Theft: Canary Credential Deleted",
                            Evidence = $"Honeypot credential '{target}' was removed from Windows Credential Manager",
                            Reasoning = "A canary credential planted by Sentinel was deleted, indicating active " +
                                        "credential harvesting. Legitimate tools do not interact with this credential. " +
                                        "Multiple canaries with randomized names are planted - deletion of any one " +
                                        "indicates bulk credential enumeration/deletion by a harvesting tool.",
                            Confidence = 0.88, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0,
                            Metadata = new Dictionary<string, string>
                            {
                                ["DeletedTarget"] = target,
                                ["TotalCanaries"] = _plantedCanaryTargets.Count.ToString()
                            }
                        });

                        // Remove from tracking and re-plant a replacement with a new random name
                        lock (_canaryLock)
                        {
                            _plantedCanaryTargets.Remove(target);
                        }
                        ReplantSingleCanary();
                    }
                    else
                    {
                        CredFree(credPtr);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[CredentialCanaryMonitor] Check error for '{Target}'", target);
                }
            }
        }

        private void ReplantSingleCanary()
        {
            var rng = new Random();
            var template = CanaryTemplates[rng.Next(CanaryTemplates.Length)];
            var suffix = Guid.NewGuid().ToString("N")[..6];
            var target = string.Format(template.TargetTemplate, suffix);
            if (PlantSingleCanary(target, template.Username, template.Comment))
            {
                lock (_canaryLock)
                {
                    _plantedCanaryTargets.Add(target);
                }
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
