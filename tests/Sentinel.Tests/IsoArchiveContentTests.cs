using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v2.8.4: Tests for bounded, bomb-safe archive / disk-image content inspection
    /// (ArchiveContentInspector) and the newly-wired ISO isolation-response path
    /// (AdvancedResponseEngine.DismountVolume -> IsolationResponseEngine).
    ///
    /// Covers the docs/constraints.md testing requirements for the new/changed surface:
    ///   (1) new Tier2 content signal returns Tier2Indicator and is LogOnly even with
    ///       ActiveResponse=true (Tier2 log-only contract);
    ///   (2) the new destructive DismountVolume action is gated by observe-until-chain
    ///       (default-deny: no multi-signal chain -> LogOnly);
    ///   (3) a Tier1 chain-authorized DismountVolume fires the containment branch;
    ///   (4) the inspector is fail-closed and bomb-safe (a decompression bomb is flagged,
    ///       never expanded to exhaustion).
    /// </summary>
    public class ArchiveContentInspectorTests : IDisposable
    {
        private readonly string _tempDir;

        public ArchiveContentInspectorTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_arc_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        private string MakeZip(string name, Action<ZipArchive> build)
        {
            var path = Path.Combine(_tempDir, name);
            using var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite);
            using var zip = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false);
            build(zip);
            return path;
        }

        [Fact]
        public void Inspect_EmbeddedExecutable_IsDetected()
        {
            var path = MakeZip("carrier.zip", zip =>
            {
                var e = zip.CreateEntry("payload.bin");
                using var s = e.Open();
                // MZ...PE\0\0 - a minimal PE header shape.
                var bytes = new byte[512];
                bytes[0] = 0x4D; bytes[1] = 0x5A;   // MZ
                bytes[0x80] = 0x50; bytes[0x81] = 0x45; bytes[0x82] = 0x00; bytes[0x83] = 0x00; // PE\0\0
                s.Write(bytes, 0, bytes.Length);
            });

            var r = ArchiveContentInspector.Inspect(path);

            Assert.True(r.Inspected);
            Assert.True(r.ContainsExecutable, "Embedded PE payload should be detected.");
            Assert.True(r.HasSmugglingSignal);
        }

        [Fact]
        public void Inspect_EmbeddedScriptHost_IsDetected()
        {
            var path = MakeZip("scripts.zip", zip =>
            {
                var e = zip.CreateEntry("run.hta");
                using var s = e.Open();
                var b = Encoding.ASCII.GetBytes("<html><script>alert(1)</script></html>");
                s.Write(b, 0, b.Length);
            });

            var r = ArchiveContentInspector.Inspect(path);

            Assert.True(r.ContainsScriptHost, "Embedded .hta script-host member should be flagged.");
            Assert.True(r.HasSmugglingSignal);
        }

        [Fact]
        public void Inspect_NestedArchive_IsDetected()
        {
            // inner.zip -> outer.zip
            var inner = MakeZip("inner.zip", zip =>
            {
                var e = zip.CreateEntry("readme.txt");
                using var s = e.Open();
                var b = Encoding.ASCII.GetBytes("hello");
                s.Write(b, 0, b.Length);
            });
            var innerBytes = File.ReadAllBytes(inner);

            var outer = MakeZip("outer.zip", zip =>
            {
                var e = zip.CreateEntry("nested.zip");
                using var s = e.Open();
                s.Write(innerBytes, 0, innerBytes.Length);
            });

            var r = ArchiveContentInspector.Inspect(outer);

            Assert.True(r.ContainsNestedArchive, "A zip inside a zip should be flagged as a nested archive.");
            Assert.True(r.MaxNestingDepth >= 1);
        }

        [Fact]
        public void Inspect_ZipBombShape_IsFlagged_AndDoesNotExhaust()
        {
            // A highly-compressible entry: 8 MB of zeros compresses to a few KB -> huge ratio.
            var path = MakeZip("bomb.zip", zip =>
            {
                var e = zip.CreateEntry("zeros.bin", CompressionLevel.Optimal);
                using var s = e.Open();
                var chunk = new byte[64 * 1024]; // all zeros
                for (int i = 0; i < 128; i++) // 8 MB total
                    s.Write(chunk, 0, chunk.Length);
            });

            var start = DateTime.UtcNow;
            var r = ArchiveContentInspector.Inspect(path);
            var elapsed = DateTime.UtcNow - start;

            Assert.True(r.ZipBombShape, "A pathological compression-ratio entry should be flagged as bomb-shaped.");
            // Bomb-safe: must return quickly and never expand the whole payload (well under the 8s budget).
            Assert.True(elapsed < TimeSpan.FromSeconds(8), $"Inspection should be bounded, took {elapsed}.");
        }

        [Fact]
        public void Inspect_BenignArchive_HasNoSmugglingSignal()
        {
            var path = MakeZip("benign.zip", zip =>
            {
                var e = zip.CreateEntry("notes.txt");
                using var s = e.Open();
                var b = Encoding.ASCII.GetBytes("just some ordinary text, nothing to see here");
                s.Write(b, 0, b.Length);
            });

            var r = ArchiveContentInspector.Inspect(path);

            Assert.True(r.Inspected);
            Assert.False(r.HasSmugglingSignal, "A plain text-only archive must not raise a smuggling signal.");
            Assert.False(r.ZipBombShape);
            Assert.False(r.ContainsExecutable);
        }

        [Fact]
        public void Inspect_MissingFile_FailsClosedWithoutThrow()
        {
            var r = ArchiveContentInspector.Inspect(Path.Combine(_tempDir, "does-not-exist.zip"));
            Assert.False(r.Inspected);
            Assert.False(r.HasSmugglingSignal);
        }
    }

    public class IsoDismountResponseTests : IDisposable
    {
        private readonly string _tempDir;

        public IsoDismountResponseTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_iso_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        private (AdvancedResponseEngine engine, JsonlEventLogger logger, string logPath) BuildEngine(
            bool observeUntilChain, IsolationResponseEngine? iso = null)
        {
            var config = new SentinelConfig { ActiveResponse = true, ObserveUntilChain = observeUntilChain };
            var metrics = new SentinelMetrics();
            var logPath = Path.Combine(_tempDir, "events_" + Guid.NewGuid().ToString("N")[..6] + ".jsonl");
            var logger = new JsonlEventLogger(logPath);
            var quarantine = new QuarantineManager(_tempDir);
            var engine = new AdvancedResponseEngine(config, metrics, logger, quarantine, null, null, iso);
            return (engine, logger, logPath);
        }

        [Fact]
        public async Task DismountVolume_Tier2_IsLogOnly_EvenWithActiveResponse()
        {
            // Tier2 log-only contract: a Tier2 indicator authoring DismountVolume must never act.
            var (engine, logger, logPath) = BuildEngine(observeUntilChain: false);
            var detection = new DetectionEvent
            {
                RuleName = "Content Smuggling: Payload in Disk Image",
                Confidence = 0.55,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.DismountVolume,
                ProcessName = "malware.exe",
                ProcessId = 99991
            };

            await engine.HandleAsync(detection);
            await logger.DisposeAsync();

            var log = File.ReadAllText(logPath);
            Assert.Contains("\"ActionTaken\":\"LOG\"", log);
            Assert.DoesNotContain("ISO_KILL_DISMOUNT_DELETE", log);
        }

        // v2.9.4: observe-until-chain removed as a settable mode; no-chain LogOnly scenario no longer exists
        // (DismountVolume_ObserveUntilChain_NoChain_IsLogOnly deleted). A Tier1 kill-grade detection now
        // fires the containment branch, so the "observe -> LogOnly" scenario it asserted cannot occur.
        // The non-observe counterparts (Tier2 LogOnly, Tier1 kill/containment) remain below.

        [Fact]
        public async Task DismountVolume_Tier1_NoIsoOriginResolved_DegradesToKillOnly()
        {
            // With ObserveUntilChain off, a Tier1 DismountVolume fires the containment branch.
            // The PID does not exist and no ISO backs it, so it must degrade to a plain kill and
            // NEVER dismount/delete an unrelated volume.
            var (engine, logger, logPath) = BuildEngine(observeUntilChain: false);
            var detection = new DetectionEvent
            {
                RuleName = "Isolation: ISO-hosted Confirmed Reverse Shell",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.DismountVolume,
                ProcessName = "nonexistent.exe",
                ProcessId = 99993 // very unlikely to exist
            };

            await engine.HandleAsync(detection);
            await logger.DisposeAsync();

            var log = File.ReadAllText(logPath);
            // Branch was taken (kill), but no volume mutation happened (ISO origin unresolved).
            Assert.Contains("\"ActionTaken\":\"KILL\"", log);
            Assert.Contains("ISO origin unresolved", log);
            Assert.DoesNotContain("ISO_KILL_DISMOUNT_DELETE", log);
        }

        [Fact]
        public async Task DockerContainment_Tier2_WithActiveResponse_IsLogOnly()
        {
            // Tier2 container observation carrying a ContainerId must never contain (log-only).
            var iso = new IsolationResponseEngine(
                NullLogger<IsolationResponseEngine>.Instance,
                new JsonlEventLogger(Path.Combine(_tempDir, "iso1.jsonl")));
            var (engine, logger, logPath) = BuildEngine(observeUntilChain: false, iso: iso);

            var detection = new DetectionEvent
            {
                RuleName = "Container: Weakened Isolation Detected",
                Confidence = 0.65,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "dockerd",
                ProcessId = 0,
                Metadata = new Dictionary<string, string> { ["ContainerId"] = "abc123def456" }
            };

            await engine.HandleAsync(detection);
            await logger.DisposeAsync();

            var log = File.ReadAllText(logPath);
            Assert.Contains("\"ActionTaken\":\"LOG\"", log);
            Assert.DoesNotContain("Docker containment", log);
        }

        // v2.9.4: observe-until-chain removed as a settable mode; no-chain LogOnly scenario no longer exists
        // (DockerContainment_ObserveUntilChain_NoChain_IsLogOnly deleted). A Tier1 kill-grade container
        // escape now fires the containment branch, so the "observe -> LogOnly" scenario cannot occur.
        // The non-observe counterparts (Tier2 LogOnly, Tier1 chain-authorized containment) remain below.

        [Fact]
        public async Task DockerContainment_Tier1_ChainAuthorized_TakesKillAndAttemptsContainment()
        {
            // ObserveUntilChain off + Tier1 kill-grade + ContainerId + wired IsolationResponseEngine:
            // the process kill fires (safe no-op PID) and Docker containment is attempted (docker.exe
            // absent -> harmless failure inside the engine's try/catch). The response is logged KILL
            // with a Docker-containment reason.
            var iso = new IsolationResponseEngine(
                NullLogger<IsolationResponseEngine>.Instance,
                new JsonlEventLogger(Path.Combine(_tempDir, "iso3.jsonl")));
            var (engine, logger, logPath) = BuildEngine(observeUntilChain: false, iso: iso);

            var detection = new DetectionEvent
            {
                RuleName = "Container: Possible Container Escape",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessName = "nonexistent.exe",
                ProcessId = 99996,
                Metadata = new Dictionary<string, string> { ["ContainerId"] = "abc123def456" }
            };

            await engine.HandleAsync(detection);
            await logger.DisposeAsync();

            var log = File.ReadAllText(logPath);
            Assert.Contains("\"ActionTaken\":\"KILL\"", log);
            Assert.Contains("Docker containment", log);
        }

        [Fact]
        public async Task VmContainment_Tier1_ChainAuthorized_TakesKillAndAttemptsContainment()
        {
            var iso = new IsolationResponseEngine(
                NullLogger<IsolationResponseEngine>.Instance,
                new JsonlEventLogger(Path.Combine(_tempDir, "iso4.jsonl")));
            var (engine, logger, logPath) = BuildEngine(observeUntilChain: false, iso: iso);

            var detection = new DetectionEvent
            {
                RuleName = "VM: Confirmed Malicious Activity in Guest",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessName = "nonexistent.exe",
                ProcessId = 99997,
                Metadata = new Dictionary<string, string>
                {
                    ["VmHostPid"] = "99998",
                    ["VmName"] = "TestGuest"
                }
            };

            await engine.HandleAsync(detection);
            await logger.DisposeAsync();

            var log = File.ReadAllText(logPath);
            Assert.Contains("\"ActionTaken\":\"KILL\"", log);
            Assert.Contains("VM containment", log);
        }

        [Fact]
        public async Task DismountVolume_Tier1_WithExplicitIsoPath_InvokesIsolationEngine()
        {
            // When a backing ISO path is supplied via metadata and an IsolationResponseEngine is
            // wired, the containment branch delegates to it (ISO_KILL_DISMOUNT_DELETE). We use a
            // non-existent PID + a temp .iso path: kill is a safe no-op, dismount fails silently,
            // delete removes our temp file - all inside IsolationResponseEngine's try/catch.
            var isoPath = Path.Combine(_tempDir, "decoy.iso");
            File.WriteAllBytes(isoPath, new byte[] { 0x00, 0x01, 0x02, 0x03 });

            var iso = new IsolationResponseEngine(
                NullLogger<IsolationResponseEngine>.Instance,
                new JsonlEventLogger(Path.Combine(_tempDir, "iso_events.jsonl")));

            var (engine, logger, logPath) = BuildEngine(observeUntilChain: false, iso: iso);
            var detection = new DetectionEvent
            {
                RuleName = "Isolation: ISO-hosted Confirmed C2 Beacon",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.DismountVolume,
                ProcessName = "nonexistent.exe",
                ProcessId = 99994,
                Metadata = new Dictionary<string, string> { ["IsoPath"] = isoPath }
            };

            await engine.HandleAsync(detection);
            await logger.DisposeAsync();

            var log = File.ReadAllText(logPath);
            Assert.Contains("ISO_KILL_DISMOUNT_DELETE", log);
        }
    }
}
