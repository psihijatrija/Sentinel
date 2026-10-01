using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    public sealed class WebcamHijackMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WebcamHijackMonitor> _logger;
        private int _baselineDeviceCount;

        private const string VideoDeviceClassPath = @"SYSTEM\CurrentControlSet\Control\DeviceClasses\{e5323777-f97a-4f0b-92a4-0e3062b86553}";

        public WebcamHijackMonitor(DetectionEngine de, ILogger<WebcamHijackMonitor> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WebcamHijackMonitor] Started");
            _baselineDeviceCount = CountVideoDevices();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(10000, ct);
                    var current = CountVideoDevices();
                    if (current > _baselineDeviceCount)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Webcam Hijack: New Video Capture Device Detected",
                            Evidence = $"Video capture devices increased from {_baselineDeviceCount} to {current}",
                            Reasoning = "A new video capture device was registered under the standard webcam device class at runtime, indicating potential hardware emulation or video stream hijacking.",
                            Confidence = 0.60,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0
                        });
                    }
                    _baselineDeviceCount = current;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[WebcamHijackMonitor] Error");
                }
            }
        }

        private static int CountVideoDevices()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(VideoDeviceClassPath);
                return key?.SubKeyCount ?? 0;
            }
            catch
            {
                return 0;
            }
        }
    }
}
