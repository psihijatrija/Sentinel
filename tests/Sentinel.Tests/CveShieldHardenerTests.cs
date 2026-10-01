using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Tests
{
    public class CveShieldHardenerTests : IDisposable
    {
        private readonly string _tempTestDir;
        private readonly string _rulesDir;
        private readonly string _logPath;
        private readonly string _feedPath;

        public CveShieldHardenerTests()
        {
            _tempTestDir = Path.Combine(Path.GetTempPath(), "cve_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_tempTestDir);
            _rulesDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules");
            if (!Directory.Exists(_rulesDir))
            {
                Directory.CreateDirectory(_rulesDir);
            }
            _logPath = Path.Combine(_tempTestDir, "sentinel.log");
            _feedPath = Path.Combine(_tempTestDir, "cisa_kev.json");
        }

        [Fact]
        public async Task RunShieldingCycle_DeploysRulesAndHashes_WhenVulnerabilityMatched()
        {
            // Arrange
            var config = new SentinelConfig();
            config.CveShield.Enabled = true;
            config.CveShield.CustomFeedPath = _feedPath;
            config.ActiveResponse = false; // LogOnly mode for testing

            // Mock a catalog that matches a process we know is running: "dotnet" (the test execution host)
            var mockCatalog = new CisaKevCatalog
            {
                Vulnerabilities = new System.Collections.Generic.List<CisaVulnerability>
                {
                    new()
                    {
                        CveId = "CVE-2026-9999",
                        VendorProject = "Microsoft",
                        Product = "dotnet",
                        VulnerabilityName = "Mock .NET Core Vulnerability",
                        ShortDescription = "A mock vulnerability for unit testing."
                    }
                }
            };

            var json = JsonSerializer.Serialize(mockCatalog);
            File.WriteAllText(_feedPath, json);

            var cache = new SecureCacheStore(_tempTestDir);
            var iocScanner = new IoCScanner(cache);
            var eventLogger = new JsonlEventLogger(_logPath);
            var toastLogger = NullLogger<ToastService>.Instance;
            var toastService = new ToastService(toastLogger);
            var hardenerLogger = NullLogger<CveShieldHardener>.Instance;

            var hardener = new CveShieldHardener(hardenerLogger, config, iocScanner, eventLogger, toastService);

            // Act
            await hardener.RunShieldingCycleAsync(CancellationToken.None);

            // Assert - rules are named CVE-Shield-{cve}-{parent}-{interpreter}.json
            var cmdRuleFile = Path.Combine(_rulesDir, "CVE-Shield-CVE-2026-9999-dotnet-cmd.exe.json");
            var psRuleFile = Path.Combine(_rulesDir, "CVE-Shield-CVE-2026-9999-dotnet-powershell.json");

            Assert.True(File.Exists(cmdRuleFile), $"Expected rule file not found: {cmdRuleFile}");
            Assert.True(File.Exists(psRuleFile), $"Expected rule file not found: {psRuleFile}");

            // Synthetic PoC salts are not registered (no fake hash theater)
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes("CVE-2026-9999-poc-salt");
            var hashBytes = sha256.ComputeHash(bytes);
            var dummyHash = string.Concat(System.Linq.Enumerable.Select(hashBytes, b => b.ToString("x2")));
            Assert.False(iocScanner.IsKnownBadHash(dummyHash), "CVE Shield must not register synthetic PoC salts.");

            Assert.True(File.Exists(_logPath), "Log file was not created.");
            await eventLogger.DisposeAsync();
            var logs = File.ReadAllText(_logPath);
            Assert.Contains("cve_shield_match", logs);
            Assert.Contains("CVE-2026-9999", logs);

            CleanupShieldRules("CVE-2026-9999");
        }

        [Fact]
        public async Task RunShieldingCycle_DoesNotDeploy_WhenNoMatchFound()
        {
            // Arrange
            var config = new SentinelConfig();
            config.CveShield.Enabled = true;
            config.CveShield.CustomFeedPath = _feedPath;

            // Mock a catalog that matches nothing
            var mockCatalog = new CisaKevCatalog
            {
                Vulnerabilities = new System.Collections.Generic.List<CisaVulnerability>
                {
                    new()
                    {
                        CveId = "CVE-2026-8888",
                        VendorProject = "NonExistentVendor",
                        Product = "NonExistentProductXYZ",
                        VulnerabilityName = "Mock Nonexistent Vulnerability",
                        ShortDescription = "A mock vulnerability that matches no local asset."
                    }
                }
            };

            var json = JsonSerializer.Serialize(mockCatalog);
            File.WriteAllText(_feedPath, json);

            var cache = new SecureCacheStore(_tempTestDir);
            var iocScanner = new IoCScanner(cache);
            var eventLogger = new JsonlEventLogger(_logPath);
            var toastService = new ToastService(NullLogger<ToastService>.Instance);
            var hardener = new CveShieldHardener(NullLogger<CveShieldHardener>.Instance, config, iocScanner, eventLogger, toastService);

            // Act
            await hardener.RunShieldingCycleAsync(CancellationToken.None);

            // Assert
            var cmdRuleFile = Path.Combine(_rulesDir, "CVE-Shield-CVE-2026-8888-cmd.exe.json");
            Assert.False(File.Exists(cmdRuleFile), "Rule should not be written for non-matched CVE.");

            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes("CVE-2026-8888-poc-salt");
            var hashBytes = sha256.ComputeHash(bytes);
            var expectedHash = string.Concat(System.Linq.Enumerable.Select(hashBytes, b => b.ToString("x2")));
            Assert.False(iocScanner.IsKnownBadHash(expectedHash), "PoC hash should not be registered.");
        }

        [Fact]
        public async Task RunShieldingCycle_WindowsOsKev_LogsMatch_DoesNotDeployProcessRules()
        {
            var config = new SentinelConfig();
            config.CveShield.Enabled = true;
            config.CveShield.CustomFeedPath = _feedPath;

            var mockCatalog = new CisaKevCatalog
            {
                Vulnerabilities = new System.Collections.Generic.List<CisaVulnerability>
                {
                    new()
                    {
                        CveId = "CVE-2026-61348",
                        VendorProject = "Microsoft",
                        Product = "Windows Ancillary Function Driver for WinSock",
                        VulnerabilityName = "Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability",
                        ShortDescription = "Local EoP in afd.sys"
                    }
                }
            };
            File.WriteAllText(_feedPath, JsonSerializer.Serialize(mockCatalog));

            var cache = new SecureCacheStore(_tempTestDir);
            var iocScanner = new IoCScanner(cache);
            var eventLogger = new JsonlEventLogger(_logPath);
            var hardener = new CveShieldHardener(
                NullLogger<CveShieldHardener>.Instance, config, iocScanner, eventLogger,
                new ToastService(NullLogger<ToastService>.Instance));

            await hardener.RunShieldingCycleAsync(CancellationToken.None);

            await eventLogger.DisposeAsync();
            var logs = File.ReadAllText(_logPath);
            Assert.Contains("cve_shield_match", logs);
            Assert.Contains("CVE-2026-61348", logs);
            Assert.Contains("WorkstationOs", logs);
            Assert.Contains("cve_shield_os_summary", logs);

            Assert.False(File.Exists(Path.Combine(_rulesDir, "CVE-Shield-CVE-2026-61348-Windows-cmd.exe.json")));
            CleanupShieldRules("CVE-2026-61348");
        }

        [Fact]
        public async Task RunShieldingCycle_SharePointAbsent_DoesNotMatchWorkstation()
        {
            var config = new SentinelConfig();
            config.CveShield.Enabled = true;
            config.CveShield.CustomFeedPath = _feedPath;

            var mockCatalog = new CisaKevCatalog
            {
                Vulnerabilities = new System.Collections.Generic.List<CisaVulnerability>
                {
                    new()
                    {
                        CveId = "CVE-2026-50522",
                        VendorProject = "Microsoft",
                        Product = "SharePoint Server",
                        VulnerabilityName = "Microsoft SharePoint Remote Code Execution Vulnerability",
                        ShortDescription = "Unauthenticated RCE"
                    }
                }
            };
            File.WriteAllText(_feedPath, JsonSerializer.Serialize(mockCatalog));

            var cache = new SecureCacheStore(_tempTestDir);
            var iocScanner = new IoCScanner(cache);
            var eventLogger = new JsonlEventLogger(_logPath);
            var hardener = new CveShieldHardener(
                NullLogger<CveShieldHardener>.Instance, config, iocScanner, eventLogger,
                new ToastService(NullLogger<ToastService>.Instance));

            await hardener.RunShieldingCycleAsync(CancellationToken.None);
            await eventLogger.DisposeAsync();

            if (File.Exists(_logPath))
            {
                var logs = File.ReadAllText(_logPath);
                Assert.DoesNotContain("cve_shield_match", logs);
            }
            CleanupShieldRules("CVE-2026-50522");
        }

        private void CleanupShieldRules(string cveId)
        {
            try
            {
                if (!Directory.Exists(_rulesDir)) return;
                foreach (var f in Directory.GetFiles(_rulesDir, $"CVE-Shield-{cveId}-*.json"))
                {
                    try { File.Delete(f); } catch { }
                }
            }
            catch { }
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_tempTestDir))
                {
                    Directory.Delete(_tempTestDir, true);
                }
            }
            catch { }
        }
    }
}
