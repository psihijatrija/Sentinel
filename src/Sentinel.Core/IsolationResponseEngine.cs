using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Handles malicious activity detected in isolated environments such as
    /// mounted ISO images, Docker containers, and virtual machines (Hyper-V, VirtualBox, VMware).
    ///
    /// Isolation-based attacks are increasingly common because they bypass traditional
    /// file-based scanning - malware hides inside container images, ISOs, or VMs where
    /// the host AV cannot inspect it until execution begins. This engine provides
    /// immediate containment once malicious behavior is confirmed inside these environments.
    /// </summary>
    public interface IIsolationContainment
    {
        Task<bool> HandleIsoThreatAsync(int processId, string isoPath, DateTime? evidenceUtc = null, CancellationToken ct = default);
        Task HandleDockerThreatAsync(string containerId, CancellationToken ct = default);
        Task HandleVmThreatAsync(int vmHostProcessId, string vmName, DateTime? evidenceUtc = null, CancellationToken ct = default);
    }

    public sealed class IsolationResponseEngine : IIsolationContainment
    {
        private readonly ILogger<IsolationResponseEngine> _logger;
        private readonly JsonlEventLogger _eventLogger;

        public IsolationResponseEngine(
            ILogger<IsolationResponseEngine> logger,
            JsonlEventLogger eventLogger)
        {
            _logger = logger;
            _eventLogger = eventLogger;
        }

        /// <summary>
        /// Responds to a threat originating from a mounted ISO image.
        /// Kills the offending process, dismounts the ISO, and deletes the source .iso file.
        /// </summary>
        /// <param name="processId">PID of the malicious process running from the ISO mount.</param>
        /// <param name="isoPath">Full path to the .iso file on disk.</param>
        public async Task<bool> HandleIsoThreatAsync(int processId, string isoPath, DateTime? evidenceUtc = null, CancellationToken ct = default)
        {
            _logger.LogInformation("[IsolationResponse] Handling ISO threat - PID {ProcessId}, IsoPath {IsoPath}",
                processId, isoPath);

            var stopwatch = Stopwatch.StartNew();

            ct.ThrowIfCancellationRequested();
            if (!evidenceUtc.HasValue || !Path.IsPathRooted(isoPath) || isoPath.StartsWith(@"\\", StringComparison.Ordinal))
            {
                _logger.LogWarning("[IsolationResponse] ISO mutation refused: missing evidence or invalid local path");
                return false;
            }
            var origin = IsoOriginResolver.ResolveBackingImageForProcess(processId);
            if (origin == null || !string.Equals(Path.GetFullPath(origin), Path.GetFullPath(isoPath), StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("[IsolationResponse] ISO mutation refused: backing image could not be matched");
                return false;
            }
            await _eventLogger.LogEventAsync("response_intent", new { Action = "IsoContainment", ProcessId = processId, Image = origin });
            if (!VerifiedProcessTermination.TryTerminate(processId, evidenceUtc.Value, out var terminationReason))
            {
                _logger.LogWarning("[IsolationResponse] ISO mutation refused: {Reason}", terminationReason);
                return false;
            }
            bool dismounted = false, deleted = false;

            // 2. Dismount the ISO via PowerShell Dismount-DiskImage
            // SECURITY v1.4.4: Use -EncodedCommand to prevent command injection via crafted ISO filenames.
            // Previously interpolated isoPath directly into a PowerShell -Command string - a filename
            // containing embedded single quotes could break out and execute arbitrary commands as SYSTEM.
            try
            {
                var script = $"Dismount-DiskImage -ImagePath '{isoPath.Replace("'", "''")}' -ErrorAction Stop";
                var encodedScript = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));
                var dismountArgs = $"-NoProfile -NonInteractive -EncodedCommand {encodedScript}";
                using var dismount = new Process();
                dismount.StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = dismountArgs,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                await RunCheckedCommandAsync(dismount, ct).ConfigureAwait(false);
                dismounted = true;
                _logger.LogWarning("[IsolationResponse] Dismounted ISO {IsoPath}", isoPath);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[IsolationResponse] Exception during ISO dismount for {IsoPath}", isoPath);
            }

            // 3. Delete only after the backing image was matched and dismount completed.
            ct.ThrowIfCancellationRequested();
            try
            {
                if (dismounted && File.Exists(isoPath))
                {
                    File.Delete(isoPath);
                    deleted = !File.Exists(isoPath);
                    _logger.LogWarning("[IsolationResponse] Deleted ISO file {IsoPath}", isoPath);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[IsolationResponse] Failed to delete ISO file {IsoPath}", isoPath);
            }

            stopwatch.Stop();

            await _eventLogger.LogEventAsync("response", new ResponseEvent
            {
                ProcessId = processId,
                ProcessName = "ISO-hosted",
                ActionTaken = dismounted && deleted ? "IsoKillDismountDelete" : "IsoContainmentUnconfirmed",
                Outcome = dismounted && deleted ? ResponseExecutionOutcome.Confirmed : ResponseExecutionOutcome.Attempted,
                Reason = $"ISO response: process exit verified; dismounted={dismounted}; deleted={deleted}; path={isoPath}",
                Timestamp = DateTime.UtcNow,
                ExecutionTimeMs = stopwatch.ElapsedMilliseconds
            });
            return dismounted && deleted;
        }

        /// <summary>
        /// Responds to a threat originating from a Docker container.
        /// Stops the container, removes it, and removes the associated image.
        /// </summary>
        /// <param name="containerId">Docker container ID or name.</param>
        public async Task HandleDockerThreatAsync(string containerId, CancellationToken ct = default)
        {
            if (!IsolationIdentifiers.IsContainerReference(containerId))
            {
                _logger.LogWarning("[IsolationResponse] Invalid container reference refused");
                return;
            }
            var stopwatch = Stopwatch.StartNew();
            string? resolvedId = null, imageId = null;
            bool stopped = false, removed = false, imageRemoved = false;
            string? error = null;
            try
            {
                // Resolve a potentially reusable name to an immutable full container ID before mutation.
                resolvedId = (await RunDockerCommandAsync("inspect", "--format={{.Id}} " + containerId, ct)).Trim();
                if (!IsolationIdentifiers.IsContainerId(resolvedId)) throw new InvalidDataException("Invalid Docker container identity");
                imageId = (await RunDockerCommandAsync("inspect", "--format={{.Image}} " + resolvedId, ct)).Trim();
                if (!IsolationIdentifiers.IsImageId(imageId)) throw new InvalidDataException("Invalid Docker image identity");
                await _eventLogger.LogEventAsync("response_intent", new { Action = "DockerContainment", ContainerId = resolvedId, ImageId = imageId });
                await RunDockerCommandAsync("stop", resolvedId, ct);
                stopped = true;
                await RunDockerCommandAsync("rm", resolvedId, ct);
                removed = true;
                // Never force removal of a shared image: Docker must refuse an image still in use.
                await RunDockerCommandAsync("rmi", imageId, ct);
                imageRemoved = true;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                error = ex.GetType().Name;
                _logger.LogWarning(ex, "[IsolationResponse] Docker containment incomplete for {Container}", resolvedId ?? containerId);
            }
            stopwatch.Stop();
            await _eventLogger.LogEventAsync("response", new ResponseEvent
            {
                ProcessId = 0, ProcessName = "docker:" + (resolvedId ?? containerId),
                ActionTaken = removed && imageRemoved ? "DockerStopRemove" : "DockerContainmentUnconfirmed",
                Outcome = removed && imageRemoved ? ResponseExecutionOutcome.Confirmed : ResponseExecutionOutcome.Attempted,
                Reason = $"Docker stopped={stopped}; removed={removed}; imageRemoved={imageRemoved}; error={error ?? "none"}",
                ExecutionTimeMs = stopwatch.ElapsedMilliseconds
            });
        }

        /// <summary>
        /// Responds to a threat originating from a virtual machine (Hyper-V, VirtualBox, or VMware).
        /// Terminates the VM host process. Does not delete VM files (too destructive).
        /// </summary>
        /// <param name="vmHostProcessId">PID of the VM host process (vmware-vmx.exe, VBoxHeadless.exe, etc.).</param>
        /// <param name="vmName">Display name of the virtual machine for logging.</param>
        public async Task HandleVmThreatAsync(int vmHostProcessId, string vmName, DateTime? evidenceUtc = null, CancellationToken ct = default)
        {
            // HARDENING v1.3.0: Sanitize vmName
            if (!string.IsNullOrEmpty(vmName) && !IsValidVmName(vmName))
            {
                _logger.LogWarning("[IsolationResponse] Rejected invalid vmName: '{VmName}'", vmName);
                vmName = "SANITIZED";
            }

            _logger.LogInformation("[IsolationResponse] Handling VM threat - PID {VmHostProcessId}, VmName {VmName}",
                vmHostProcessId, vmName);

            var stopwatch = Stopwatch.StartNew();
            ct.ThrowIfCancellationRequested();
            if (evidenceUtc.HasValue)
                await _eventLogger.LogEventAsync("response_intent", new { Action = "VmHostTermination", ProcessId = vmHostProcessId });
            bool exited = evidenceUtc.HasValue && VerifiedProcessTermination.TryTerminate(
                vmHostProcessId, evidenceUtc.Value, out _, requiredImagePolicy: IsolationIdentifiers.IsDedicatedVmHostImage);
            string actionTaken = exited ? "VmKill" : "VmKillFailed";
            string processName = "VM-host";
            // A display name is not authority to stop another VM via Stop-VM.
            // Only the handle-verified host process is targeted; VM files are preserved.
            _logger.LogInformation("[IsolationResponse] VM host exit verified={Verified} for PID {Pid}", exited, vmHostProcessId);

            stopwatch.Stop();

            await _eventLogger.LogEventAsync("response", new ResponseEvent
            {
                ProcessId = vmHostProcessId,
                ProcessName = processName,
                ActionTaken = actionTaken,
                Outcome = exited ? ResponseExecutionOutcome.Confirmed : ResponseExecutionOutcome.Failed,
                Reason = $"VM host exit verified={exited}: {vmName} (files preserved)",
                Timestamp = DateTime.UtcNow,
                ExecutionTimeMs = stopwatch.ElapsedMilliseconds
            });
        }

        /// <summary>
        /// Validates a VM name - alphanumeric, spaces, hyphens, underscores only.
        /// </summary>
        private static bool IsValidVmName(string name)
        {
            if (name.Length > 256) return false;
            foreach (var c in name)
            {
                if (!char.IsLetterOrDigit(c) && c != ' ' && c != '-' && c != '_' && c != '.')
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Executes a docker command directly via docker.exe (no cmd.exe shell-out).
        /// </summary>
        private async Task<string> RunDockerCommandAsync(string command, string arguments, CancellationToken ct)
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = "docker.exe",
                Arguments = $"{command} {arguments}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            return await RunCheckedCommandAsync(process, ct).ConfigureAwait(false);
        }

        private static async Task<string> RunCheckedCommandAsync(Process process, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            process.Start();
            var output = ReadBoundedAsync(process.StandardOutput);
            var error = ReadBoundedAsync(process.StandardError);
            var completion = Task.WhenAll(process.WaitForExitAsync(), output, error);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var deadline = Task.Delay(TimeSpan.FromSeconds(15), timeout.Token);
            if (await Task.WhenAny(completion, deadline).ConfigureAwait(false) != completion)
            {
                try { if (!process.HasExited) process.Kill(); }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine("Response command cleanup failed: " + ex.Message); }
                process.StandardOutput.Close();
                process.StandardError.Close();
                // Observe any pipe-read error after cancellation without blocking indefinitely.
                _ = completion.ContinueWith(t => { _ = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
                ct.ThrowIfCancellationRequested();
                throw new TimeoutException("Response command exceeded its 15 second deadline");
            }
            timeout.Cancel();
            await completion.ConfigureAwait(false);
            if (process.ExitCode != 0) throw new InvalidOperationException("Response command failed with exit " + process.ExitCode);
            return await output.ConfigureAwait(false);
        }

        private static async Task<string> ReadBoundedAsync(StreamReader reader)
        {
            var text = new System.Text.StringBuilder();
            var buffer = new char[4096];
            int count;
            while ((count = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
            {
                if (text.Length + count > 1024 * 1024) throw new InvalidDataException("Response command output exceeded 1 MiB");
                text.Append(buffer, 0, count);
            }
            return text.ToString();
        }
    }
}
