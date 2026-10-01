using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Sentinel.Core
{
    public static class HardeningModule
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool SetDllDirectory(string lpPathName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetDefaultDllDirectories(uint DirectoryFlags);

        private const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;

        /// <summary>
        /// v2.5.5: Hardening is now unconditional - always active.
        /// The setter is retained for compatibility but is a no-op.
        /// IPSec port lockdown, ASR Block rules, RPC/DCOM firewall, remote session guard,
        /// registry hardening, credential hardening, browser hardening, and LGPO security
        /// policy run on every Sentinel startup with no config gate.
        /// </summary>
        public static bool RestrictivePortHardeningEnabled
        {
            get => true;
            set { } // No-op: hardening is always-on as of v2.5.5
        }

        public static bool ApplyOrFail()
        {
            try
            {
                // v1.5.5: Removed FIPS disable (RT-HIGH-1). An EDR must not weaken system
                // cryptographic posture. If internal code throws under FIPS, fix the algorithm
                // usage rather than disabling FIPS system-wide.

                // Self-only: protect Sentinel process / install - never the user's tools.
                bool res1 = SetDllDirectory(string.Empty);
                bool res2 = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
                RegisterForSafeMode();

                // v2.5.5: Hardening is now unconditional - always active.
                // IPSec, RPC firewall, and setup-scripts hardening run on every startup.
                ApplyIPSecPolicy();
                BlockRemoteRpcEphemeralPorts();
                ApplyUserSetupScriptsHardening();

                return res1 && res2;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// v1.9.7 / v2.0.4: Tear down proactive host lockdowns from prior Sentinel versions
        /// so normal work (NTLite, RDP, RPC/DISM, File/Print, Office, USB tools, installers)
        /// is not blocked.
        ///
        /// v2.0.4 HIGH-5: ONLY removes rules/policies that Sentinel itself created (identified
        /// by Sentinel-specific naming conventions). Never modifies RemoteRegistry or other
        /// system service states that may have been set by the organization's sysadmin.
        /// </summary>
        public static void ReleaseUserWorkSurface()
        {
            try
            {
                // IPSec GSecurity - Sentinel-created policy (identified by name "GSecurity")
                RemoveIPSecPolicyIfPresent();

                // Inbound RPC ephemeral block - Sentinel-created (identified by prefix "Sentinel-")
                RemoveFirewallRuleByName("Sentinel-Block-Remote-RPC-Ephemeral");

                // ASR Block rules Sentinel wrote under Policy hive (identified by known GUIDs)
                ReleaseAsrBlockPolicy();

                // v2.0.4 HIGH-5: Removed RemoteRegistry re-enablement. Sentinel must not
                // modify system service states it didn't set. If an admin disabled RemoteRegistry,
                // Sentinel should not override that decision. Only Sentinel-created artifacts
                // (IPSec "GSecurity", "Sentinel-*" firewall rules, known ASR GUIDs) are removed.

                // Keep install-dir exclusions only (safe for upgrades)
                ApplyAsrOnlyExclusions();
            }
            catch { /* best effort */ }
        }

        /// <summary>Remove a Windows Firewall rule by name if present (fail-soft).</summary>
        public static void RemoveFirewallRuleByName(string ruleName)
        {
            if (string.IsNullOrWhiteSpace(ruleName)) return;
            try
            {
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return;
                dynamic? policy = Activator.CreateInstance(policyType);
                if (policy == null) return;

                // Copy names first - cannot modify collection while enumerating
                var toRemove = new List<dynamic>();
                foreach (dynamic rule in policy.Rules)
                {
                    try
                    {
                        if (string.Equals((string)rule.Name, ruleName, StringComparison.OrdinalIgnoreCase))
                            toRemove.Add(rule);
                    }
                    catch { /* skip bad rule */ }
                }

                foreach (var rule in toRemove)
                {
                    try { policy.Rules.Remove(rule.Name); } catch { /* ignore */ }
                }
            }
            catch { /* barebone / no firewall COM */ }
        }

        /// <summary>
        /// Delete ASR Policy Rules Sentinel previously forced to Block.
        /// Leaves machine ASR as user/Windows configured (no continuous re-arm).
        /// </summary>
        public static void ReleaseAsrBlockPolicy()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(AsrPolicyRulesKey, writable: true);
                if (key == null) return;

                foreach (var (guid, _) in AsrRules)
                {
                    try { key.DeleteValue(guid, throwOnMissingValue: false); } catch { }
                }

                foreach (var bad in AsrRulesNeverBlock)
                {
                    try { key.DeleteValue(bad, throwOnMissingValue: false); } catch { }
                }
            }
            catch { /* ignore */ }
        }

        private struct PortDef
        {
            public int Port;
            public string Name;
            public string Protocol; // "TCP", "UDP", or "TCPUDP"
        }

        /// <summary>
        /// v1.8.3 DEFAULT IPSec set: ports normal users never need, attackers do.
        /// Does NOT include SSH, RDP, SMB, VNC, WinRM, FTP, databases, SOCKS, Docker, torrents.
        /// </summary>
        private static readonly PortDef[] AttackOnlyPortDefinitions =
        {
            // Legacy remote shells (superseded by SSH; pure attack surface)
            new PortDef { Port = 23, Name = "Telnet", Protocol = "TCP" },
            new PortDef { Port = 512, Name = "rexec", Protocol = "TCP" },
            new PortDef { Port = 513, Name = "rlogin", Protocol = "TCP" },
            new PortDef { Port = 514, Name = "rsh", Protocol = "TCP" },
            // Rarely used, high-abuse discovery/transfer
            new PortDef { Port = 69, Name = "TFTP", Protocol = "UDP" },
            new PortDef { Port = 111, Name = "RPCBind", Protocol = "TCPUDP" },
            // Classic malware / RAT / implant defaults (not legitimate apps)
            new PortDef { Port = 666, Name = "Trojan_666", Protocol = "TCP" },
            new PortDef { Port = 1234, Name = "RAT_1234", Protocol = "TCP" },
            new PortDef { Port = 1337, Name = "Backdoor_1337", Protocol = "TCP" },
            new PortDef { Port = 4444, Name = "Meterpreter_4444", Protocol = "TCP" },
            new PortDef { Port = 7777, Name = "Backdoor_7777", Protocol = "TCP" },
            new PortDef { Port = 12345, Name = "NetBus", Protocol = "TCP" },
            new PortDef { Port = 31337, Name = "BackOrifice", Protocol = "TCPUDP" },
            new PortDef { Port = 54321, Name = "BackOrifice2K", Protocol = "TCP" },
        };

        /// <summary>
        /// Extra ports only when RestrictivePortHardening=true (locked-down host).
        /// These are services real users may run (SSH, RDP, SMB, DBs, proxies, Docker...).
        /// </summary>
        private static readonly PortDef[] RestrictiveExtraPortDefinitions =
        {
            new PortDef { Port = 21, Name = "FTP", Protocol = "TCP" },
            new PortDef { Port = 22, Name = "SSH", Protocol = "TCP" },
            new PortDef { Port = 135, Name = "RPC_DCOM", Protocol = "TCPUDP" },
            new PortDef { Port = 137, Name = "NetBIOS_NS", Protocol = "TCPUDP" },
            new PortDef { Port = 138, Name = "NetBIOS_DGM", Protocol = "UDP" },
            new PortDef { Port = 139, Name = "NetBIOS_SSN", Protocol = "TCP" },
            new PortDef { Port = 161, Name = "SNMP", Protocol = "UDP" },
            new PortDef { Port = 162, Name = "SNMP_Trap", Protocol = "UDP" },
            new PortDef { Port = 389, Name = "LDAP", Protocol = "TCPUDP" },
            new PortDef { Port = 445, Name = "SMB", Protocol = "TCP" },
            new PortDef { Port = 548, Name = "AFP", Protocol = "TCP" },
            new PortDef { Port = 636, Name = "LDAPS", Protocol = "TCP" },
            new PortDef { Port = 873, Name = "rsync", Protocol = "TCP" },
            new PortDef { Port = 1080, Name = "SOCKS", Protocol = "TCP" },
            new PortDef { Port = 1099, Name = "Java_RMI", Protocol = "TCP" },
            new PortDef { Port = 1433, Name = "MSSQL", Protocol = "TCP" },
            new PortDef { Port = 1434, Name = "MSSQL_Browser", Protocol = "UDP" },
            new PortDef { Port = 1521, Name = "OracleDB", Protocol = "TCP" },
            new PortDef { Port = 1900, Name = "SSDP", Protocol = "UDP" },
            new PortDef { Port = 2049, Name = "NFS", Protocol = "TCPUDP" },
            new PortDef { Port = 2375, Name = "Docker_Unenc", Protocol = "TCP" },
            new PortDef { Port = 2376, Name = "Docker_TLS", Protocol = "TCP" },
            new PortDef { Port = 2869, Name = "UPnP", Protocol = "TCP" },
            new PortDef { Port = 3306, Name = "MySQL", Protocol = "TCP" },
            new PortDef { Port = 3389, Name = "RDP", Protocol = "TCPUDP" },
            new PortDef { Port = 5000, Name = "DockerRegistry", Protocol = "TCP" },
            new PortDef { Port = 5040, Name = "CDP_UserSvc", Protocol = "TCP" },
            new PortDef { Port = 5353, Name = "mDNS", Protocol = "UDP" },
            new PortDef { Port = 5355, Name = "LLMNR", Protocol = "UDP" },
            new PortDef { Port = 5432, Name = "PostgreSQL", Protocol = "TCP" },
            new PortDef { Port = 5555, Name = "Android_ADB", Protocol = "TCP" },
            new PortDef { Port = 5601, Name = "Kibana", Protocol = "TCP" },
            new PortDef { Port = 5900, Name = "VNC", Protocol = "TCP" },
            new PortDef { Port = 5985, Name = "WinRM_HTTP", Protocol = "TCP" },
            new PortDef { Port = 5986, Name = "WinRM_HTTPS", Protocol = "TCP" },
            new PortDef { Port = 6379, Name = "Redis", Protocol = "TCP" },
            new PortDef { Port = 6666, Name = "IRC_6666", Protocol = "TCP" },
            new PortDef { Port = 6667, Name = "IRC_6667", Protocol = "TCP" },
            new PortDef { Port = 8291, Name = "MikroTik_Winbox", Protocol = "TCP" },
            new PortDef { Port = 8888, Name = "Jupyter", Protocol = "TCP" },
            new PortDef { Port = 9042, Name = "Cassandra", Protocol = "TCP" },
            new PortDef { Port = 9090, Name = "Prometheus", Protocol = "TCP" },
            new PortDef { Port = 9200, Name = "Elasticsearch", Protocol = "TCP" },
            new PortDef { Port = 11211, Name = "Memcached", Protocol = "TCPUDP" },
            new PortDef { Port = 27017, Name = "MongoDB", Protocol = "TCP" },
            new PortDef { Port = 50070, Name = "Hadoop_HDFS", Protocol = "TCP" },
        };

        /// <summary>Ports currently enforced by IPSec (always the combined attack + restrictive set).</summary>
        private static PortDef[] GetActivePortDefinitions()
        {
            // v2.5.5: Hardening is always-on - always return the full combined set.
            var list = new List<PortDef>(AttackOnlyPortDefinitions.Length + RestrictiveExtraPortDefinitions.Length);
            list.AddRange(AttackOnlyPortDefinitions);
            list.AddRange(RestrictiveExtraPortDefinitions);
            return list.ToArray();
        }

        /// <summary>True if this port is in the default attack-only block set (public for monitors).</summary>
        public static bool IsAttackOnlyBlockedPort(int port)
        {
            foreach (var def in AttackOnlyPortDefinitions)
                if (def.Port == port) return true;
            return false;
        }

        private static void RunNetsh(string args)
        {
            try
            {
                var psi = new ProcessStartInfo("netsh.exe", args)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using var proc = Process.Start(psi);
                proc?.WaitForExit();
            }
            catch { }
        }

        /// <summary>
        /// Verifies the GSecurity IPSec policy is currently assigned and active.
        /// Returns true if the policy is confirmed active, false if missing/unassigned.
        /// Uses 'netsh ipsec static show policy name=GSecurity' - exit code 0 + "assigned: yes"
        /// means it's active. Anything else means it's been tampered with.
        /// </summary>
        public static bool IsIPSecPolicyActive()
        {
            try
            {
                var psi = new ProcessStartInfo("netsh.exe", "ipsec static show policy name=GSecurity")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return false;
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(5000);
                // Policy exists and is assigned if output contains "Assigned" and "Yes"
                return proc.ExitCode == 0 &&
                       output.Contains("Assign") &&
                       output.Contains("Yes");
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Re-applies the IPSec policy from scratch.
        /// v2.5.5: Hardening is always-on - always rebuilds the full restrictive policy.
        /// </summary>
        public static void ReapplyIPSecPolicy()
        {
            try
            {
                var ports = GetActivePortDefinitions();
                const string mode = "always-on hardening (v2.5.5+)";

                // Delete and recreate - handles partial corruption and profile changes
                RunNetsh("ipsec static delete policy name=GSecurity");
                RunNetsh($"ipsec static add policy name=GSecurity description=\"Sentinel IPSec: {mode}.\" assign=yes");
                RunNetsh("ipsec static add filteraction name=BlockAction action=block description=\"Block traffic\"");

                foreach (var def in ports)
                {
                    var protocols = new List<string>();
                    if (def.Protocol == "TCPUDP")
                    {
                        protocols.Add("TCP");
                        protocols.Add("UDP");
                    }
                    else
                    {
                        protocols.Add(def.Protocol);
                    }

                    foreach (var proto in protocols)
                    {
                        foreach (var direction in new[] { "Inbound", "Outbound" })
                        {
                            var filterListName = $"{direction}_{def.Name}_{proto}";
                            var ruleName = $"Block_{direction}_{def.Name}_{proto}";
                            string src = (direction == "Inbound") ? "Any" : "Me";
                            string dst = (direction == "Inbound") ? "Me" : "Any";
                            RunNetsh($"ipsec static add filterlist name={filterListName} description=\"{direction} {def.Name} port {def.Port} ({proto})\"");
                            RunNetsh($"ipsec static add filter filterlist={filterListName} srcaddr={src} dstaddr={dst} protocol={proto} dstport={def.Port} mirrored=no");
                            RunNetsh($"ipsec static add rule name={ruleName} policy=GSecurity filterlist={filterListName} filteraction=BlockAction");
                        }
                    }
                }

                RunNetsh("ipsec static set policy name=GSecurity assign=yes");
            }
            catch { }
        }

        /// <summary>
        /// v1.4.2: Registers the Sentinel service to run in both
        /// Safe Mode (Minimal) and Safe Mode with Networking.
        /// Without this, an attacker who triggers a Safe Mode reboot has
        /// unrestricted access because all non-registered services are stopped.
        /// </summary>
        /// <summary>SafeBoot Minimal+Network registration (also used by InstallBootstrap --install).</summary>
        public static void RegisterForSafeModePublic() => RegisterForSafeMode();

        private static void RegisterForSafeMode()
        {
            try
            {
                const string serviceName = "Sentinel";

                // Minimal Safe Mode
                using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    $@"SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\{serviceName}"))
                {
                    key?.SetValue("", "Service", Microsoft.Win32.RegistryValueKind.String);
                }

                // Safe Mode with Networking
                using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                    $@"SYSTEM\CurrentControlSet\Control\SafeBoot\Network\{serviceName}"))
                {
                    key?.SetValue("", "Service", Microsoft.Win32.RegistryValueKind.String);
                }
            }
            catch { }
        }

        /// <summary>
        /// v1.4.2: Blocks inbound access to RPC dynamic endpoint ports (49664-49675)
        /// from non-localhost sources via Windows Firewall.
        /// v2.5.5: Hardening is always-on - always enforced.
        /// Self-healing: checks for rule existence on every call.
        /// </summary>
        public static void BlockRemoteRpcEphemeralPorts()
        {
            try
            {
                const string ruleName = "Sentinel-Block-Remote-RPC-Ephemeral";

                // Check if rule already exists
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return;
                dynamic? policy = Activator.CreateInstance(policyType);
                if (policy == null) return;

                bool exists = false;
                foreach (dynamic rule in policy.Rules)
                {
                    if ((string)rule.Name == ruleName) { exists = true; break; }
                }

                if (!exists)
                {
                    var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                    if (ruleType == null) return;
                    dynamic? newRule = Activator.CreateInstance(ruleType);
                    if (newRule == null) return;

                    newRule.Name = ruleName;
                    newRule.Description = "Sentinel: Blocks remote access to RPC dynamic endpoint ports. " +
                                          "Prevents lateral movement via DCOM/WMI/Task Scheduler RPC.";
                    newRule.Protocol = 6; // TCP
                    newRule.LocalPorts = "49664-49675";
                    newRule.Direction = 1; // Inbound
                    newRule.Action = 0; // Block
                    newRule.Enabled = true;
                    newRule.Profiles = 0x7FFFFFFF; // All profiles
                    // Allow localhost (loopback) - only block external
                    newRule.RemoteAddresses = "LocalSubnet,DNS,DHCP,WINS,DefaultGateway";
                    // Actually we need to BLOCK from everywhere except local - invert logic:
                    // Block all remote, which is the default when no RemoteAddresses filter is set
                    newRule.RemoteAddresses = "*";
                    // Exclude local loopback by setting LocalAddresses (can't exclude in block rule)
                    // The simpler approach: block from "LocalSubnet" which covers LAN attacks
                    newRule.RemoteAddresses = "LocalSubnet";

                    policy.Rules.Add(newRule);
                }
            }
            catch { }
        }

        private static void ApplyIPSecPolicy()
        {
            try
            {
                // Always rebuild on startup so upgrades shrink the block list
                // (old installs blocked SSH/RDP; default is now attack-only).
                ReapplyIPSecPolicy();
            }
            catch
            {
                // Non-fatal
            }
        }

        /// <summary>
        /// Tear down GSecurity entirely (lab/uninstall). Normal operation uses ReapplyIPSecPolicy.
        /// </summary>
        public static void RemoveIPSecPolicyIfPresent()
        {
            try
            {
                RunNetsh("ipsec static delete policy name=GSecurity");
            }
            catch
            {
                // Non-fatal
            }
        }

        public static void SafeKillProcessTree(int processId)
        {
            if (processId <= 4) return; // Never target System/Idle

            // CRITICAL: Never kill our own process or our Agent sibling
            if (processId == System.Net48Environment.ProcessId) return;

            // HARDENING v1.3.8 / v2.0.8: Never kill verified Sentinel product binaries.
            // v2.0.8 RT: Do NOT exclude every PE under the install directory - that let an
            // attacker plant malware during the installer ACL window and become unkillable.
            // SelfPathGuard requires known Sentinel binary names under the install final path
            // (hardlink-aware). Arbitrary files under Program Files\Sentinel are fair game.
            try
            {
                var targetImagePath = SecurityValidation.GetProcessImagePath(processId);
                if (targetImagePath != null && SelfPathGuard.IsSentinelSelfBinary(targetImagePath))
                {
                    Debug.WriteLine($"SafeKillProcessTree: REFUSED to kill Sentinel self binary PID {processId} at '{targetImagePath}'");
                    return;
                }
            }
            catch { /* process may have already exited - continue with kill attempt */ }

            try
            {
                using var proc = Process.GetProcessById(processId);

                // Final safeguard: never kill BSOD-critical processes or user shells regardless of what triggered the kill
                var name = proc.ProcessName;
                if (IsCriticalProcessName(name))
                {
                    // HARDENING: Verify the binary actually resides in a system directory.
                    // An attacker can manipulate the PEB ProcessName field to masquerade as
                    // "csrss" or "explorer" - but they cannot move their binary into System32
                    // without triggering FileActivityMonitor's System32 write detection.
                    var imagePath = SecurityValidation.GetProcessImagePath(processId);
                    if (imagePath != null && IsInSystemDirectory(imagePath))
                    {
                        Debug.WriteLine($"SafeKillProcessTree: REFUSED to kill critical process {name} (PID {processId}) at verified system path");
                        return;
                    }
                    // Name matches critical process but path is NOT in system directory -
                    // this is masquerading. Allow the kill to proceed.
                    Debug.WriteLine($"SafeKillProcessTree: Process claims to be '{name}' but path is '{imagePath}' - masquerading detected, allowing kill");
                }

                proc.KillTree();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to kill process tree for PID {processId}: {ex.Message}");
            }
        }

        /// <summary>
        /// Returns true for processes whose termination would cause BSOD or system instability.
        /// v1.5.5: Removed cmd, powershell, and pwsh from this list (RT-HIGH-2/5).
        /// These are NOT BSOD-critical - they are the most common LOLBin attack vectors.
        /// Sentinel's detection rules (ReverseShellRule, AttackToolsRule) authorize killing
        /// them, and the safety guard must not contradict the response engine.
        /// explorer.exe is retained because killing it destabilizes the user session
        /// (taskbar, Start menu, desktop icons all disappear).
        /// </summary>
        private static bool IsCriticalProcessName(string name)
        {
            return string.Equals(name, "csrss") ||
                   string.Equals(name, "wininit") ||
                   string.Equals(name, "services") ||
                   string.Equals(name, "smss") ||
                   string.Equals(name, "lsass") ||
                   string.Equals(name, "winlogon") ||
                   string.Equals(name, "dwm") ||
                   string.Equals(name, "explorer") ||
                   string.Equals(name, "System") ||
                   // v1.4.0: svchost hosts hundreds of critical Windows services - killing it can
                   // BSOD or leave the system in an unrecoverable state. Protect all instances
                   // that reside in System32 (the path check below verifies legitimacy).
                   string.Equals(name, "svchost") ||
                   // v1.6.0: Core security products - path verified below (system or Program Files)
                   string.Equals(name, "MsMpEng") ||
                   string.Equals(name, "NisSrv") ||
                   string.Equals(name, "SecurityHealthService") ||
                   string.Equals(name, "Sense") ||
                   string.Equals(name, "MpDefenderCoreService") ||
                   string.Equals(name, "smartscreen") ||
                   string.Equals(name, "SgrmBroker");
        }

        private static bool IsInSystemDirectory(string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return false;
            try
            {
                var normalized = Path.GetFullPath(imagePath);
                var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                var winDirTrailing = winDir.EndsWith("\\") ? winDir : winDir + '\\';
                if (normalized.StartsWith(winDirTrailing))
                    return true;

                // v1.6.0: Also treat Program Files\Windows Defender* as protected paths
                var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
                foreach (var root in new[] { pf, pf86 })
                {
                    if (string.IsNullOrEmpty(root)) continue;
                    var defender = Path.Combine(root, "Windows Defender") + Path.DirectorySeparatorChar;
                    var defenderAdv = Path.Combine(root, "Windows Defender Advanced Threat Protection") + Path.DirectorySeparatorChar;
                    if (normalized.StartsWith(defender) ||
                        normalized.StartsWith(defenderAdv))
                        return true;
                }
            }
            catch { }
            return false;
        }

        public static void SecureInstallationDirectory()
        {
            // Harden installation directory: remove write for non-admin users
            // but preserve read/execute for Administrators and Users (needed by Agent)
            // Best-effort; non-fatal if it fails
            try
            {
                var exeDir = AppContext.BaseDirectory;
                if (string.IsNullOrEmpty(exeDir)) return;

                var dirInfo = new System.IO.DirectoryInfo(exeDir);
                if (!dirInfo.Exists) return;

                var security = dirInfo.GetAccessControl();

                // Keep inheritance - do NOT call SetAccessRuleProtection(true, false)
                // which strips all inherited ACEs and locks out non-SYSTEM users.
                // Instead, add a deny-write rule for regular Users to prevent tampering
                // while keeping read+execute intact.
                var usersIdentity = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    usersIdentity,
                    System.Security.AccessControl.FileSystemRights.Write |
                    System.Security.AccessControl.FileSystemRights.Delete |
                    System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                    System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Deny));

                dirInfo.SetAccessControl(security);

                // Exclude uninstaller files from the Deny rule by disabling inheritance and removing the Deny rule on them
                foreach (var file in Directory.GetFiles(exeDir, "unins*"))
                {
                    ExcludeUninstallerFromDeny(file);
                }
            }
            catch
            {
                // Non-fatal
            }
        }

        private static void ExcludeUninstallerFromDeny(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return;
                var fileInfo = new FileInfo(filePath);
                var security = fileInfo.GetAccessControl();

                // Disable inheritance and copy existing rules (marks them as explicit on disk)
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: true);
                fileInfo.SetAccessControl(security);

                // Re-read the security descriptor so that the copied rules are loaded as explicit rules
                security = fileInfo.GetAccessControl();

                // Find and remove any Deny rules for BUILTIN\Users
                var usersSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);

                var rules = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(System.Security.Principal.SecurityIdentifier));
                foreach (System.Security.AccessControl.FileSystemAccessRule rule in rules)
                {
                    if (rule.AccessControlType == System.Security.AccessControl.AccessControlType.Deny &&
                        rule.IdentityReference.Value == usersSid.Value)
                    {
                        security.RemoveAccessRule(rule);
                    }
                }

                fileInfo.SetAccessControl(security);
            }
            catch
            {
                // Non-fatal
            }
        }

        /// <summary>
        /// Inverse of <see cref="SecureInstallationDirectory"/> for upgrades.
        /// Removes the Users Deny-Write (admin accounts are in Users, so it blocks Inno)
        /// and grants Administrators full control, including Inno <c>unins000.*</c> stubs
        /// that have inheritance disabled. Called from <c>--prepare-upgrade</c>.
        /// </summary>
        public static void UnlockInstallationDirectoryForUpgrade(string? dir)
        {
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
                return;

            try
            {
                var dirInfo = new DirectoryInfo(dir);
                var security = dirInfo.GetAccessControl();
                var usersSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
                var adminsSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);

                var rules = security.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                foreach (System.Security.AccessControl.FileSystemAccessRule rule in rules)
                {
                    if (rule.AccessControlType == System.Security.AccessControl.AccessControlType.Deny &&
                        rule.IdentityReference.Value == usersSid.Value)
                    {
                        security.RemoveAccessRule(rule);
                    }
                }

                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    adminsSid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                    System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));

                dirInfo.SetAccessControl(security);
            }
            catch
            {
                // Non-fatal - Setup also unlocks via icacls for older installed binaries.
            }

            try
            {
                foreach (var file in Directory.GetFiles(dir, "unins*"))
                    UnlockUninstallerStubForUpgrade(file);
            }
            catch { }
        }

        private static void UnlockUninstallerStubForUpgrade(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return;
                var fileInfo = new FileInfo(filePath);
                var security = fileInfo.GetAccessControl();
                security.SetAccessRuleProtection(isProtected: false, preserveInheritance: true);

                var usersSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
                var adminsSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);

                var rules = security.GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier));
                foreach (System.Security.AccessControl.FileSystemAccessRule rule in rules)
                {
                    if (rule.AccessControlType == System.Security.AccessControl.AccessControlType.Deny &&
                        rule.IdentityReference.Value == usersSid.Value)
                    {
                        security.RemoveAccessRule(rule);
                    }
                }

                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    adminsSid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow));

                fileInfo.SetAccessControl(security);
            }
            catch { }
        }

        /// <summary>
        /// v1.5.7: Native C# system hardening - no scripts, no shell-outs for logic.
        /// 
        /// Each hardening action is:
        ///   - Documented with its security purpose
        ///   - Implemented via direct registry API or ServiceController
        ///   - Idempotent and safe to re-run
        ///   - Non-fatal on failure (logs debug, continues)
        ///
        /// Actions performed:
        ///   1. Disable dangerous remote access services (attack surface reduction)
        ///   2. Apply security-relevant registry hardening (LSA, TLS, mitigations)
        ///   3. Enforce DEP/NX via bcdedit (exploit mitigation)
        ///   4. Apply LGPO security policy baseline (if LGPO.exe is embedded)
        /// 
        /// NOT performed (removed from legacy GSecurity.bat):
        ///   - ACL stripping from system binaries (dangerous, breaks updates)
        ///   - Volume labeling (cosmetic)
        ///   - User deletion (opinionated)
        ///   - TCP autotuninglevel restriction (performance, not security)
        ///   - Blanket .reg file imports (unauditable, can contain non-security tweaks)
        /// </summary>
        private static void ApplyUserSetupScriptsHardening()
        {
            // Entire block is restrictive/kiosk only (caller already gates).
            try
            {
                DisableRemoteAccessServices();
                ApplyRegistryHardening();
                EnforceDepAlwaysOn();
                ApplyLgpoSecurityPolicy();
                ApplyAsrRules();
                ApplyCredentialHardening();
                ApplyBrowserHardening();
            }
            catch { /* Non-fatal: hardening is best-effort */ }
        }

        #region Hardening: Service Disablement

        /// <summary>
        /// v1.8.3: Default disables only services users almost never run that attackers abuse.
        /// Does NOT disable RDP, SSH, WinRM, FTP, UPnP, TeamViewer/AnyDesk, etc.
        /// Full lockdown list applies only when RestrictivePortHardeningEnabled is true.
        /// </summary>
        private static void DisableRemoteAccessServices()
        {
            // Always: pure attack surface / legacy, not normal desktop use
            var attackOnlyServices = new[]
            {
                ("TlntSvr",         "Telnet Server"),
                ("RemoteRegistry",  "Remote Registry"), // lateral movement; rare legitimate use
            };

            // Restrictive lockdown only - users may want these
            var restrictiveServices = new[]
            {
                ("TermService",      "Remote Desktop Services"),
                ("WinRM",            "Windows Remote Management"),
                ("sshd",             "OpenSSH Server"),
                ("SNMP",             "SNMP Service"),
                ("ftpsvc",           "FTP Publishing Service"),
                ("SsdpSrv",          "SSDP Discovery (UPnP)"),
                ("upnphost",         "UPnP Device Host"),
                ("TeamViewer",       "TeamViewer"),
                ("AnyDesk",          "AnyDesk"),
                ("LogMeIn",          "LogMeIn"),
                ("VNC",              "VNC Server"),
                ("Radmin",           "Radmin Server"),
                ("FileZilla Server", "FileZilla FTP Server"),
            };

            foreach (var (name, _) in attackOnlyServices)
                DisableServiceSafe(name);

            if (RestrictivePortHardeningEnabled)
            {
                foreach (var (name, _) in restrictiveServices)
                    DisableServiceSafe(name);
            }
        }

        private static void DisableServiceSafe(string serviceName)
        {
            try
            {
                using var sc = new System.ServiceProcess.ServiceController(serviceName);
                // Check if service exists by reading its status
                _ = sc.Status;

                // Stop if running
                if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Running ||
                    sc.Status == System.ServiceProcess.ServiceControllerStatus.StartPending)
                {
                    try { sc.Stop(); } catch { }
                }

                // Set to disabled via registry (ServiceController doesn't expose StartType setter)
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{serviceName}", writable: true);
                if (key != null)
                {
                    key.SetValue("Start", 4, Microsoft.Win32.RegistryValueKind.DWord); // 4 = Disabled
                }
            }
            catch (InvalidOperationException) { } // Service doesn't exist - expected
            catch { } // Access denied or other - non-fatal
        }

        #endregion

        #region Hardening: Registry Security Settings

        /// <summary>
        /// Applies security-relevant registry settings directly via .NET Registry API.
        /// Each setting is documented with its MITRE ATT&CK mitigation or CIS benchmark reference.
        /// </summary>
        private static void ApplyRegistryHardening()
        {
            // --- LSA Hardening (Credential Protection) ---
            // Restrict anonymous access to SAM/LSA (CIS 2.3.10.2, MITRE T1003)
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\LSA", "restrictanonymous", 1);
            // Prevent LM hash storage (CIS 2.3.11.7, MITRE T1003.001)
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\LSA", "NoLMHash", 1);

            // --- Remote Access Restrictions (restrictive lockdown only) ---
            // v1.8.3: Do not break remote WMI/WinRM for admins by default.
            if (RestrictivePortHardeningEnabled)
            {
                SetRegistryDword(@"SOFTWARE\Microsoft\Wbem", "EnableRemoteWmi", 0);
                SetRegistryDword(@"Software\Microsoft\Windows\CurrentVersion\WSMAN\Service", "allow_remote_requests", 0);
            }

            // --- TLS Hardening ---
            // Enable TLS 1.3 client support
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client", "Enabled", 1);
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client", "DisabledByDefault", 0);
            // Force .NET Framework to use system default TLS (prevents downgrade to TLS 1.0/1.1)
            SetRegistryDword(@"SOFTWARE\Microsoft\.NETFramework\v4.0.30319", "SystemDefaultTlsVersions", 1);
            SetRegistryDword(@"SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319", "SystemDefaultTlsVersions", 1);

            // --- Exploit Mitigations ---
            // Enable SEHOP - Structured Exception Handler Overwrite Protection (CIS 18.3.4)
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "DisableExceptionChainValidation", 0);
            // Spectre/Meltdown mitigations (FeatureSettingsOverride/Mask)
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "FeatureSettingsOverride", 0x40);
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "FeatureSettingsOverrideMask", 3);
            // Hyper-V CPU mitigations for VMs
            SetRegistryString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization", "MinVmVersionForCpuBasedMitigations", "1.0");

            // --- Privilege Escalation Prevention ---
            // Disable AlwaysInstallElevated (MITRE T1548.002 - MSI privilege escalation)
            SetRegistryDword(@"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", 0);
            // Disable COM auto-approval for UAC bypass (MITRE T1548.002)
            SetRegistryDword(@"Software\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList", "{ca8c87c1-929d-45ba-94db-ef8e6cb346ad}", 0);

            // --- Information Disclosure Prevention ---
            // Disable lock screen camera (physical access data leak)
            SetRegistryDword(@"SOFTWARE\Policies\Microsoft\Windows\Personalization", "NoLockScreenCamera", 1);
            // Disable cloud clipboard sync (data exfiltration vector)
            SetRegistryDwordCurrentUser(@"Software\Microsoft\Clipboard", "CloudClipboardAutomaticUpload", 0);
            SetRegistryDwordCurrentUser(@"Software\Microsoft\Clipboard", "EnableClipboardHistory", 0);
            // Disable crash dumps (can contain credentials in memory)
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\CrashControl", "CrashDumpEnabled", 0);

            // --- Network Hardening ---
            // Disable WCN (Windows Connect Now) registrars - prevents UPnP/WPS provisioning attacks
            SetRegistryDword(@"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars", "EnableRegistrars", 0);
            SetRegistryDword(@"Software\Policies\Microsoft\Windows\WCN\UI", "DisableWcnUi", 1);
            // Disable QUIC protocol in browsers (can bypass network inspection)
            SetRegistryDword(@"Software\Policies\Google\Chrome", "QuicAllowed", 0);
            SetRegistryDword(@"Software\Policies\Microsoft\Edge", "QuicAllowed", 0);
            SetRegistryDword(@"Software\Policies\BraveSoftware\Brave", "QuicAllowed", 0);

            // --- Firewall Enforcement ---
            // Ensure Windows Firewall is enabled on all profiles
            SetRegistryDword(@"System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", 1);
            SetRegistryDword(@"System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile", "EnableFirewall", 1);
            SetRegistryDword(@"System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", 1);
            // Disable Remote Admin, Remote Desktop, File/Print, and UPnP through firewall (all profiles)
            foreach (var profile in new[] { "DomainProfile", "PrivateProfile", "PublicProfile" })
            {
                string basePath = $@"System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}";
                SetRegistryDword($@"{basePath}\RemoteAdminSettings", "Enabled", 0);
                SetRegistryDword($@"{basePath}\Services\FileAndPrint", "Enabled", 0);
                SetRegistryDword($@"{basePath}\Services\RemoteDesktop", "Enabled", 0);
                SetRegistryDword($@"{basePath}\Services\UPnPFramework", "Enabled", 0);
            }
        }

        private static void SetRegistryDword(string subKey, string valueName, int value)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(subKey, writable: true);
                key?.SetValue(valueName, value, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { } // Non-fatal: may lack admin rights
        }

        private static void SetRegistryString(string subKey, string valueName, string value)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(subKey, writable: true);
                key?.SetValue(valueName, value, Microsoft.Win32.RegistryValueKind.String);
            }
            catch { }
        }

        private static void SetRegistryDwordCurrentUser(string subKey, string valueName, int value)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(subKey, writable: true);
                key?.SetValue(valueName, value, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { }
        }

        #endregion

        #region Hardening: DEP Enforcement

        /// <summary>
        /// Enforces DEP (Data Execution Prevention) AlwaysOn via bcdedit.
        /// This is a one-time boot configuration that survives reboots.
        /// No .NET API exists for BCD store manipulation - bcdedit is required.
        /// </summary>
        private static void EnforceDepAlwaysOn()
        {
            try
            {
                var psi = new ProcessStartInfo("bcdedit.exe", "/set nx AlwaysOn")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(5000);
            }
            catch { }
        }

        #endregion

        #region Hardening: LGPO Security Policy

        /// <summary>
        /// Applies the embedded GSecurity.inf security policy via LGPO.exe.
        /// LGPO.exe is Microsoft's Local Group Policy Object utility - it's the only
        /// <summary>
        /// Applies the GSecurity.inf security policy via LGPO.exe.
        /// LGPO.exe is Microsoft's Local Group Policy Object utility - it's the only
        /// supported way to apply .inf security templates programmatically without
        /// Active Directory. No .NET equivalent exists.
        ///
        /// LGPO.exe and GSecurity.inf are shipped as standalone files in the installation
        /// directory (not embedded in the assembly) so they remain inspectable and
        /// auditable by security scanners.
        /// </summary>
        private static void ApplyLgpoSecurityPolicy()
        {
            try
            {
                // Look for LGPO.exe and GSecurity.inf in the same directory as the running assembly.
                // These are shipped as plain files in the installation directory.
                string baseDir = AppContext.BaseDirectory;
                string lgpoPath = Path.Combine(baseDir, "LGPO.exe");
                string infPath = Path.Combine(baseDir, "GSecurity.inf");

                if (!File.Exists(lgpoPath) || !File.Exists(infPath))
                    return;

                var psi = new ProcessStartInfo(lgpoPath, $"/s \"{infPath}\"")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WorkingDirectory = baseDir
                };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(30000);
            }
            catch { }
        }


        #endregion

        #region Hardening: Defender ASR Rules

        /// <summary>
        /// Microsoft Defender Attack Surface Reduction rules enforced in Block mode (value 1).
        /// Written to the Policy hive so they survive Defender UI toggles and re-apply via AsrPolicyGuard.
        /// Sourced from GEDR_ASR_Rules.ps1 + high-value workstation rules.
        ///
        /// NOT included: c1db55ab ("Use advanced protection against ransomware") - that rule blocks
        /// unsigned/low-prevalence executables launched from %TEMP% (classic Inno Setup extract path)
        /// and was observed blocking SentinelSetup-*.exe upgrades (Defender Event 1121).
        /// NOT included: pure prevalence "block unknown PE" rules for the same reason.
        /// </summary>
        internal static readonly (string Guid, string Name)[] AsrRules =
        {
            ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from lsass"),
            ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block Office apps from creating child processes"),
            ("3b576869-a4ec-4529-8536-b80a7769e899", "Block Office apps from creating executable content"),
            ("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office apps from injecting code into other processes"),
            ("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros"),
            ("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail"),
            ("d3e037e1-3eb8-44c8-a917-57927947596d", "Block JS/VBS from launching downloaded executables"),
            ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts"),
            ("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted/unsigned processes from USB"),
            ("d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations from PSExec and WMI"),
            ("e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription"),
            ("56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers"),
            ("26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication apps from creating child processes"),
        };

        /// <summary>
        /// Rules that must NOT stay in Block if previously applied (self-upgrade / installer safety).
        /// Deleted on every ApplyAsrRules so AsrPolicyGuard cannot re-arm them.
        /// </summary>
        internal static readonly string[] AsrRulesNeverBlock =
        {
            // Blocks Inno Setup / low-prevalence EXEs from %TEMP% (SentinelSetup Error 5).
            "c1db55ab-c21a-4637-bb3f-a12568109d35",
        };

        private const string AsrPolicyRoot =
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR";
        private const string AsrPolicyRulesKey = AsrPolicyRoot + @"\Rules";

        /// <summary>Apply all ASR rules in Block mode (1). Restrictive/kiosk only.</summary>
        public static void ApplyAsrRules()
        {
            try
            {
                if (!RestrictivePortHardeningEnabled)
                {
                    ReleaseAsrBlockPolicy();
                    ApplyAsrOnlyExclusions();
                    return;
                }

                // Ensure policy tree exists
                SetRegistryDword(AsrPolicyRoot, "ExploitGuard_ASR_Rules", 1);

                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(AsrPolicyRulesKey, writable: true);
                if (key == null) return;

                foreach (var (guid, _) in AsrRules)
                {
                    key.SetValue(guid, "1", Microsoft.Win32.RegistryValueKind.String);
                }

                // Drop rules that break our own (and most) installers if an older Sentinel applied them.
                foreach (var bad in AsrRulesNeverBlock)
                {
                    try { key.DeleteValue(bad, throwOnMissingValue: false); } catch { /* ignore */ }
                }

                ApplyAsrOnlyExclusions();
            }
            catch { /* Non-fatal */ }
        }

        /// <summary>
        /// ASR path exclusions so Sentinel binaries and Setup are not treated as ransomware staging.
        /// Policy multi-sz: ASROnlyExclusions under the ASR policy root.
        /// </summary>
        public static void ApplyAsrOnlyExclusions()
        {
            try
            {
                var paths = new List<string>();
                void Add(string? p)
                {
                    if (string.IsNullOrWhiteSpace(p)) return;
                    try
                    {
                        p = Path.GetFullPath(p!.Trim().TrimEnd('\\'));
                    }
                    catch { return; }
                    if (!paths.Exists(x => string.Equals(x, p, StringComparison.OrdinalIgnoreCase)))
                        paths.Add(p);
                }

                var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
                var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                if (!string.IsNullOrEmpty(pf86)) Add(Path.Combine(pf86, "Sentinel"));
                if (!string.IsNullOrEmpty(pf)) Add(Path.Combine(pf, "Sentinel"));

                // Running service / agent location (covers non-default install dir)
                try
                {
                    var baseDir = AppContext.BaseDirectory;
                    if (!string.IsNullOrEmpty(baseDir))
                        Add(baseDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                }
                catch { /* ignore */ }

                if (paths.Count == 0) return;

                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(AsrPolicyRoot, writable: true);
                if (key == null) return;

                // Merge with existing exclusions
                var existing = key.GetValue("ASROnlyExclusions") as string[];
                if (existing != null)
                {
                    foreach (var e in existing)
                        Add(e);
                }

                key.SetValue("ASROnlyExclusions", paths.ToArray(), Microsoft.Win32.RegistryValueKind.MultiString);
            }
            catch { /* Non-fatal - barebone / locked policy hives */ }
        }

        /// <summary>
        /// Returns true when every required ASR rule is present and set to Block ("1").
        /// Missing key or any non-block value = not intact.
        /// </summary>
        public static bool IsAsrPolicyIntact()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(AsrPolicyRulesKey, writable: false);
                if (key == null) return false;

                foreach (var (guid, _) in AsrRules)
                {
                    var val = key.GetValue(guid)?.ToString();
                    if (val != "1") return false;
                }

                // Intact also means hostile self-block rules are gone
                foreach (var bad in AsrRulesNeverBlock)
                {
                    if (key.GetValue(bad) != null)
                        return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Re-apply ASR rules (called by AsrPolicyGuard on drift/tamper).</summary>
        public static void ReapplyAsrRules() => ApplyAsrRules();

        #endregion

        #region Hardening: Credential residual (Creds.ps1)

        /// <summary>
        /// LSASS PPL + reduce credential caching. RunAsPPL requires reboot to fully activate.
        /// </summary>
        public static void ApplyCredentialHardening()
        {
            // RunAsPPL = 1 enables LSASS as a Protected Process Light (MITRE T1003.001 mitigation)
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 1);
            // Do not allow storage of passwords/credentials for network authentication
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\Lsa", "DisableDomainCreds", 1);
            // Limit cached domain logons (workstations still need a few for offline logon)
            SetRegistryDword(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount", 2);
            // WDigest cleartext passwords off (legacy)
            SetRegistryDword(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 0);
        }

        #endregion

        #region Hardening: Browser residual (Browsers.ps1)

        /// <summary>
        /// Policy-only browser hardening. No Preferences JSON mutation (corrupts profiles),
        /// no mass browser process kills (AV/heuristic + UX risk).
        /// </summary>
        public static void ApplyBrowserHardening()
        {
            // WebRTC: prevent local-IP leakage via enterprise policies
            // Edge policy WebRtcLocalhostIpHandling = disable_non_proxied_udp
            SetRegistryString(
                @"SOFTWARE\Policies\Microsoft\Edge",
                "WebRtcLocalhostIpHandling",
                "disable_non_proxied_udp");
            SetRegistryString(
                @"SOFTWARE\Policies\Google\Chrome",
                "WebRtcLocalhostIpHandling",
                "disable_non_proxied_udp");
            SetRegistryString(
                @"SOFTWARE\Policies\BraveSoftware\Brave",
                "WebRtcLocalhostIpHandling",
                "disable_non_proxied_udp");

            // Disable Chrome Remote Desktop relay / firewall traversal policies when CRD is installed
            SetRegistryDword(@"SOFTWARE\Policies\Google\Chrome", "RemoteAccessHostFirewallTraversal", 0);
            SetRegistryDword(@"SOFTWARE\Policies\Google\Chrome", "RemoteAccessHostAllowRelayedConnection", 0);
            SetRegistryDword(@"SOFTWARE\Policies\Google\Chrome", "RemoteAccessHostAllowRemoteAccessConnections", 0);

            // Stop and disable Chrome Remote Desktop host service if present
            DisableServiceSafe("chrome-remote-desktop-host");
            DisableServiceSafe("chromoting");
        }

        #endregion
    }
}
