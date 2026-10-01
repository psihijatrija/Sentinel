using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
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
    public sealed class IsolationResponseEngine
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
        public async Task HandleIsoThreatAsync(int processId, string isoPath)
        {
            _logger.LogInformation("[IsolationResponse] Handling ISO threat - PID {ProcessId}, IsoPath {IsoPath}",
                processId, isoPath);

            var stopwatch = Stopwatch.StartNew();

            // 1. Kill the process running from the ISO drive
            try
            {
                using var process = Process.GetProcessById(processId);
                var processName = process.ProcessName;
                process.KillTree();
                await process.WaitForExitAsync();

                _logger.LogWarning("[IsolationResponse] Killed ISO-hosted process {ProcessName} (PID {ProcessId})",
                    processName, processId);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[IsolationResponse] Failed to kill process PID {ProcessId}", processId);
            }

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

                dismount.Start();
                var stderr = await dismount.StandardError.ReadToEndAsync();
                await dismount.WaitForExitAsync();

                if (dismount.ExitCode == 0)
                {
                    _logger.LogWarning("[IsolationResponse] Dismounted ISO {IsoPath}", isoPath);
                }
                else
                {
                    _logger.LogDebug("[IsolationResponse] Dismount-DiskImage failed for {IsoPath}: {Error}",
                        isoPath, stderr);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[IsolationResponse] Exception during ISO dismount for {IsoPath}", isoPath);
            }

            // 3. Delete the .iso source file
            try
            {
                if (File.Exists(isoPath))
                {
                    File.Delete(isoPath);
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
                ActionTaken = "IsoKillDismountDelete",
                Reason = $"ISO threat neutralized: {isoPath}",
                Timestamp = DateTime.UtcNow,
                ExecutionTimeMs = stopwatch.ElapsedMilliseconds
            });
        }

        /// <summary>
        /// Responds to a threat originating from a Docker container.
        /// Stops the container, removes it, and removes the associated image.
        /// </summary>
        /// <param name="containerId">Docker container ID or name.</param>
        public async Task HandleDockerThreatAsync(string containerId)
        {
            // HARDENING v1.3.0: Sanitize containerId to prevent command injection.
            // Docker container IDs are hex strings (64 chars) or names matching [a-zA-Z0-9_.-]+
            if (string.IsNullOrWhiteSpace(containerId) || !IsValidDockerIdentifier(containerId))
            {
                _logger.LogWarning("[IsolationResponse] Rejected invalid containerId: '{ContainerId}'", containerId);
                return;
            }

            _logger.LogInformation("[IsolationResponse] Handling Docker threat - ContainerId {ContainerId}", containerId);

            var stopwatch = Stopwatch.StartNew();
            string? imageId = null;

            // Determine the image before stopping (inspect while running)
            try
            {
                var inspectOutput = await RunDockerCommandAsync("inspect", $"--format={{{{.Image}}}} {containerId}");
                if (!string.IsNullOrWhiteSpace(inspectOutput))
                {
                    imageId = inspectOutput.Trim();
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[IsolationResponse] Failed to inspect container {ContainerId}", containerId);
            }

            // 1. Stop the container
            try
            {
                await RunDockerCommandAsync("stop", containerId);
                _logger.LogWarning("[IsolationResponse] Stopped Docker container {ContainerId}", containerId);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[IsolationResponse] Failed to stop container {ContainerId}", containerId);
            }

            // 2. Remove the container
            try
            {
                await RunDockerCommandAsync("rm", $"--force {containerId}");
                _logger.LogWarning("[IsolationResponse] Removed Docker container {ContainerId}", containerId);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[IsolationResponse] Failed to remove container {ContainerId}", containerId);
            }

            // 3. Remove the image
            // SECURITY v1.4.4: Validate imageId from docker inspect output before use.
            // imageId comes from external process output, not our own validation - a malicious
            // container could craft its image reference to include shell metacharacters.
            if (!string.IsNullOrWhiteSpace(imageId) && IsValidDockerIdentifier(imageId!))
            {
                try
                {
                    await RunDockerCommandAsync("rmi", $"--force {imageId}");
                    _logger.LogWarning("[IsolationResponse] Removed Docker image {ImageId}", imageId);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[IsolationResponse] Failed to remove image {ImageId}", imageId);
                }
            }

            stopwatch.Stop();

            await _eventLogger.LogEventAsync("response", new ResponseEvent
            {
                ProcessId = 0,
                ProcessName = $"docker:{containerId}",
                ActionTaken = "DockerStopRemove",
                Reason = $"Docker threat neutralized: container={containerId}, image={imageId ?? "unknown"}",
                Timestamp = DateTime.UtcNow,
                ExecutionTimeMs = stopwatch.ElapsedMilliseconds
            });
        }

        /// <summary>
        /// Responds to a threat originating from a virtual machine (Hyper-V, VirtualBox, or VMware).
        /// Terminates the VM host process. Does not delete VM files (too destructive).
        /// </summary>
        /// <param name="vmHostProcessId">PID of the VM host process (vmware-vmx.exe, VBoxHeadless.exe, etc.).</param>
        /// <param name="vmName">Display name of the virtual machine for logging.</param>
        public async Task HandleVmThreatAsync(int vmHostProcessId, string vmName)
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
            string actionTaken = "VmKill";
            string processName = "unknown";

            try
            {
                using var process = Process.GetProcessById(vmHostProcessId);
                processName = process.ProcessName;

                var lowerName = processName.ToLowerInvariant();

                if (lowerName.Contains("vmwp") || lowerName.Contains("vmms"))
                {
                    // Hyper-V: attempt graceful stop via WMI (Msvm_ComputerSystem)
                    actionTaken = await TryStopHyperVVmAsync(vmName) ? "HyperV_WmiStop" : "HyperV_ProcessKill";
                }

                // Kill the VM host process regardless of hypervisor type
                // For VirtualBox (VBoxHeadless.exe, VirtualBoxVM.exe) and VMware (vmware-vmx.exe)
                // this is the primary kill mechanism. For Hyper-V it's the fallback.
                if (actionTaken != "HyperV_WmiStop")
                {
                    process.KillTree();
                    await process.WaitForExitAsync();
                }

                _logger.LogWarning("[IsolationResponse] Terminated VM {VmName} - process {ProcessName} (PID {VmHostProcessId}), action={ActionTaken}",
                    vmName, processName, vmHostProcessId, actionTaken);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[IsolationResponse] Failed to terminate VM process PID {VmHostProcessId} ({VmName})",
                    vmHostProcessId, vmName);
            }

            stopwatch.Stop();

            await _eventLogger.LogEventAsync("response", new ResponseEvent
            {
                ProcessId = vmHostProcessId,
                ProcessName = processName,
                ActionTaken = actionTaken,
                Reason = $"VM threat neutralized: {vmName} (files preserved)",
                Timestamp = DateTime.UtcNow,
                ExecutionTimeMs = stopwatch.ElapsedMilliseconds
            });
        }

        /// <summary>
        /// Attempts to stop a Hyper-V VM gracefully via WMI (Msvm_ComputerSystem).
        /// Returns true if the WMI call succeeded.
        /// </summary>
        private async Task<bool> TryStopHyperVVmAsync(string vmName)
        {
            try
            {
                // SECURITY v1.4.4: Use -EncodedCommand to prevent command injection via crafted VM names.
                // Previously interpolated vmName directly into a PowerShell -Command string.
                // While IsValidVmName() validates characters, -EncodedCommand eliminates the attack
                // surface entirely - no parsing of the command string by PowerShell's evaluator.
                var script = $"Stop-VM -Name '{vmName.Replace("'", "''")}' -TurnOff -Force -ErrorAction Stop";
                var encodedScript = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));
                var args = $"-NoProfile -NonInteractive -EncodedCommand {encodedScript}";
                using var ps = new Process();
                ps.StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = args,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                ps.Start();
                var stderr = await ps.StandardError.ReadToEndAsync();
                await ps.WaitForExitAsync();

                if (ps.ExitCode == 0)
                {
                    _logger.LogInformation("[IsolationResponse] Hyper-V VM {VmName} stopped via WMI/Stop-VM", vmName);
                    return true;
                }

                _logger.LogDebug("[IsolationResponse] Stop-VM failed for {VmName}: {Error}", vmName, stderr);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[IsolationResponse] Exception invoking Stop-VM for {VmName}", vmName);
            }

            return false;
        }

        /// <summary>
        /// Validates a Docker container ID or name. IDs are 64-char hex; names are [a-zA-Z0-9][a-zA-Z0-9_.-]*
        /// </summary>
        private static bool IsValidDockerIdentifier(string id)
        {
            if (id.Length > 128) return false;
            foreach (var c in id)
            {
                if (!char.IsLetterOrDigit(c) && c != '_' && c != '.' && c != '-' && c != ':')
                    return false;
            }
            return true;
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
        private async Task<string> RunDockerCommandAsync(string command, string arguments)
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

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            var error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (process.ExitCode != 0)
            {
                _logger.LogDebug("[IsolationResponse] docker {Command} failed (exit {ExitCode}): {Error}",
                    command, process.ExitCode, error);
            }

            return output;
        }
    }
}
