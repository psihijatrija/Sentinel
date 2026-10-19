using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public interface IWindowsFirewallPolicyBridge
    {
        Task<string> RunAsync(string operation, CancellationToken ct, string? store = null, string? ruleName = null);
    }

    /// <summary>Fixed, embedded NetSecurity management code; no caller-supplied script or domain store.</summary>
    public sealed class WindowsFirewallPolicyBridge : IWindowsFirewallPolicyBridge
    {
        private readonly string _installDirectory;
        private readonly ManagementChildRegistry? _managementChildren;
        public WindowsFirewallPolicyBridge(string? installDirectory = null, ManagementChildRegistry? managementChildren = null)
        {
            _installDirectory = Path.GetFullPath(installDirectory ?? AppDomain.CurrentDomain.BaseDirectory);
            _managementChildren = managementChildren;
        }

        public async Task<string> RunAsync(string operation, CancellationToken ct, string? store = null, string? ruleName = null)
        {
            if (operation != "Apply" && operation != "Restore" && operation != "Approve" && operation != "Revoke")
                throw new ArgumentException("Unsupported firewall operation", nameof(operation));
            if ((operation == "Approve" || operation == "Revoke") && (store != "PersistentStore" && store != "localhost"))
                throw new ArgumentException("Only local firewall stores can be changed", nameof(store));
            var semaphoreAcl = new SemaphoreSecurity();
            foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
                semaphoreAcl.AddAccessRule(new SemaphoreAccessRule(new SecurityIdentifier(sid, null), SemaphoreRights.FullControl, AccessControlType.Allow));
            using var gate = new Semaphore(1, 1, @"Global\Sentinel.FirewallPolicy", out _, semaphoreAcl);
            var acquired = await Task.Run(() => WaitHandle.WaitAny(new WaitHandle[] { gate, ct.WaitHandle }, TimeSpan.FromSeconds(30))).ConfigureAwait(false);
            if (acquired == 1) throw new OperationCanceledException(ct);
            if (acquired != 0) throw new TimeoutException("Another firewall policy operation is still running");
            try
            {
                if (ruleName != null && ruleName.Length > 1024) throw new ArgumentException("Firewall rule name is too long", nameof(ruleName));
                var stateDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel", "FirewallPolicy");
                for (var ancestor = new DirectoryInfo(stateDirectory); ancestor != null; ancestor = ancestor.Parent)
                    if (ancestor.Exists && (ancestor.Attributes & FileAttributes.ReparsePoint) != 0)
                        throw new IOException("Firewall journal path must not traverse a reparse point");
                var rootDirectory = Path.GetDirectoryName(stateDirectory)!;
                if (Directory.Exists(rootDirectory)) RequirePrivilegedOwner(new DirectoryInfo(rootDirectory).GetAccessControl(AccessControlSections.Owner));
                Directory.CreateDirectory(stateDirectory);
                RequirePrivilegedOwner(new DirectoryInfo(stateDirectory).GetAccessControl(AccessControlSections.Owner));
                if ((File.GetAttributes(stateDirectory) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Firewall journal directory must not be a reparse point");
                var acl = new DirectorySecurity();
                acl.SetAccessRuleProtection(true, false);
                foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
                    acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                new DirectoryInfo(stateDirectory).SetAccessControl(acl);
                var journal = Path.Combine(stateDirectory, "rollback.json");
                if (File.Exists(journal) && (File.GetAttributes(journal) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Firewall journal must not be a reparse point");
                if (File.Exists(journal)) RequirePrivilegedOwner(File.GetAccessControl(journal, AccessControlSections.Owner));
                if (operation == "Restore" && !File.Exists(journal))
                {
                    using var gpoRules = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules");
                    bool ownedGpoRules = gpoRules?.GetValueNames().Any(n => n.StartsWith("Sentinel-Offline-", StringComparison.Ordinal)) ?? false;
                    if (!ownedGpoRules) return JsonSerializer.Serialize(new { Restored = true, Changed = 0, Notes = new[] { "No baseline journal or owned GPO rules; no policy state to restore" } });
                    throw new InvalidOperationException("Owned GPO rules exist but the rollback journal is missing; retain Sentinel files for recovery");
                }
                var isolation = new SelfNetworkIsolation(new WindowsSelfNetworkFirewall(), _installDirectory);
                var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                var nativeSystemDirectory = Path.Combine(windowsDirectory, "System32");
                var launchSystemDirectory = Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess
                    ? Path.Combine(windowsDirectory, "Sysnative") : nativeSystemDirectory;
                var request = JsonSerializer.Serialize(new
                {
                    Operation = operation, Store = store, RuleName = ruleName,
                    StatePath = journal, SystemDirectory = nativeSystemDirectory,
                    SelfRules = isolation.Rules.ToArray(), RemoteAddresses = SelfNetworkBlockRule.RemoteAddresses
                });
                // Script goes over stdin to avoid Windows' command-line size limit. The short
                // bootstrap is constant; user/rule names are only JSON data in a child environment.
                const string bootstrap = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::InputEncoding=[Text.UTF8Encoding]::new($false); [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); try { $request=$env:SENTINEL_FIREWALL_REQUEST | ConvertFrom-Json; Remove-Item Env:SENTINEL_FIREWALL_REQUEST; Import-Module (Join-Path $request.SystemDirectory 'WindowsPowerShell\\v1.0\\Modules\\NetSecurity\\NetSecurity.psd1') -ErrorAction Stop; . ([ScriptBlock]::Create([Console]::In.ReadToEnd().TrimStart([char]0xFEFF))); Invoke-SentinelFirewallPolicy $request | ConvertTo-Json -Compress -Depth 8 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }";
                var start = new ProcessStartInfo
                {
                    FileName = Path.Combine(launchSystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
                    Arguments = "-NoLogo -NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(bootstrap)),
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
                };
                start.EnvironmentVariables["SENTINEL_FIREWALL_REQUEST"] = request;
                using var resource = typeof(WindowsFirewallPolicyBridge).Assembly.GetManifestResourceStream("Sentinel.Core.PolicyResources.LocalFirewallPolicy.ps1")
                    ?? throw new InvalidOperationException("Embedded firewall policy script is missing");
                using var scriptReader = new StreamReader(resource, Encoding.UTF8);
                var script = await scriptReader.ReadToEndAsync().ConfigureAwait(false);
                using var child = Process.Start(start) ?? throw new InvalidOperationException("Could not start Windows firewall management");
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                // Initial Windows inventories can contain hundreds of rules and CIM filter reads.
                // Keep cancellation effective while allowing journaled baseline creation to finish.
                timeout.CancelAfter(TimeSpan.FromMinutes(10));
                // Bound both streams and drain concurrently to avoid pipe deadlocks.
                var stdout = ReadBoundedAsync(child.StandardOutput, 1024 * 1024, timeout.Token);
                var stderr = ReadBoundedAsync(child.StandardError, 64 * 1024, timeout.Token);
                try
                {
                    _managementChildren?.Register(child, start.FileName);
                    var input = FeedScriptAsync(child.StandardInput, script);
                    var combined = Task.WhenAll(input, stdout, stderr, child.WaitForExitAsync(timeout.Token));
                    if (await Task.WhenAny(combined, Task.Delay(Timeout.Infinite, timeout.Token)).ConfigureAwait(false) != combined)
                        throw new OperationCanceledException("Firewall policy management timed out", timeout.Token);
                    await combined.ConfigureAwait(false);
                    if (child.ExitCode != 0) throw new InvalidOperationException("Windows firewall policy management failed: " + await stderr.ConfigureAwait(false));
                    var output = await stdout.ConfigureAwait(false);
                    using var document = JsonDocument.Parse(output); // Validate before callers inspect it.
                    return output;
                }
                finally
                {
                    _managementChildren?.Remove(child.Id);
                    if (!child.HasExited) child.Kill();
                }
            }
            finally { gate.Release(); }
        }

        private static async Task FeedScriptAsync(StreamWriter writer, string script)
        {
            await writer.WriteAsync(script).ConfigureAwait(false);
            writer.Close();
        }

        private static void RequirePrivilegedOwner(FileSystemSecurity security)
        {
            var owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
            if (!owner.IsWellKnown(WellKnownSidType.LocalSystemSid) && !owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
                throw new UnauthorizedAccessException("Firewall journal path must be owned by SYSTEM or Administrators; refusing untrusted policy state");
        }

        private static async Task<string> ReadBoundedAsync(TextReader reader, int maximum, CancellationToken ct)
        {
            var text = new StringBuilder();
            var buffer = new char[4096];
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var count = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                if (count == 0) return text.ToString();
                if (text.Length + count > maximum) throw new InvalidDataException("Firewall management output exceeded its size limit");
                text.Append(buffer, 0, count);
            }
        }
    }
}
