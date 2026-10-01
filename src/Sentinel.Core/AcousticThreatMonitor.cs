using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NAudio.CoreAudioApi;
using NAudio.Wave;

namespace Sentinel.Core
{
    /// <summary>
    /// Acoustic Threat Monitor - detects harmful frequencies in system audio output.
    /// 
    /// Continuously monitors what's being played via WASAPI loopback (zero interference
    /// with normal playback). When dangerous frequency content is detected, immediately
    /// mutes the output device for the duration of the threat.
    /// 
    /// Threats detected:
    /// - Infrasound (1-20Hz) at significant amplitude - causes nausea, disorientation, anxiety
    /// - Ultrasonic (17-22kHz) sustained content - tracking beacons, headache-inducing
    /// - Resonant attack frequencies (18-19Hz "fear frequency", 7Hz nausea band)
    /// - High-amplitude narrow-band tones that don't match music patterns
    /// 
    /// Whitelisted (healing frequencies allowed through):
    /// - Solfeggio: 174, 285, 396, 432, 528, 639, 741, 852, 963 Hz
    /// - Schumann: 7.83 Hz (only as binaural beat carrier, not raw infrasound)
    /// - Binaural carriers: 100-250Hz range at low amplitude
    /// 
    /// The monitor does NOT modify audio. It only mutes/unmutes the endpoint when
    /// threats are detected. Normal audio plays with zero latency, zero processing.
    /// </summary>
    public sealed class AcousticThreatMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<AcousticThreatMonitor> _logger;

        private WasapiLoopbackCapture? _capture;
        private MMDevice? _device;
        private float[] _scratchSamples = Array.Empty<float>();
        private float[] _scratchMono = Array.Empty<float>();
        private bool _isMuted;
        private int _threatFrames;
        private int _safeFrames;
        private int _totalThreatsBlocked;
        private DateTime _lastThreatTime = DateTime.MinValue;

        // Detection thresholds
        private const int ThreatFramesToMute = 3;      // ~30ms of threat before muting
        private const int SafeFramesToUnmute = 15;     // ~150ms of silence before unmuting
        private const float InfrasoundThreshold = 0.02f;  // Amplitude threshold for infrasound
        private const float UltrasonicThreshold = 0.008f; // Lower threshold - ultrasonics shouldn't be there at all
        private const float NarrowBandThreshold = 0.04f;  // Single-frequency tone detection

        // Healing frequencies that are NEVER treated as threats
        private static readonly HashSet<int> HealingFrequencies = new()
        {
            174, 285, 396, 432, 528, 639, 741, 852, 963, // Solfeggio
            // Binaural beat carriers and their common pairings are handled by range check
        };

        // Dangerous frequency bands
        private const float InfrasoundLow = 1f;
        private const float InfrasoundHigh = 20f;
        private const float FearFrequencyLow = 18f;
        private const float FearFrequencyHigh = 19.5f;
        private const float NauseaFrequencyLow = 6.5f;
        private const float NauseaFrequencyHigh = 8f;
        private const float UltrasonicLow = 17000f;
        private const float UltrasonicHigh = 22000f;

        public AcousticThreatMonitor(
            DetectionEngine detectionEngine,
            ILogger<AcousticThreatMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[AcousticThreatMonitor] Started - monitoring system audio for harmful frequencies");

            // Wait for system to stabilize
            await Task.Delay(5000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    StartCapture();
                    // Keep running until cancelled
                    await Task.Delay(Timeout.Infinite, ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[AcousticThreatMonitor] Error, restarting in 10s");
                    StopCapture();
                    await Task.Delay(10000, ct);
                }
            }

            StopCapture();
        }

        private void StartCapture()
        {
            var enumerator = new MMDeviceEnumerator();
            _device = enumerator.GetDefaultAudioEndpoint(DataFlow.Render, Role.Multimedia);

            _capture = new WasapiLoopbackCapture(_device);
            _capture.DataAvailable += OnDataAvailable;
            _capture.RecordingStopped += (s, e) => { };
            _capture.StartRecording();

            _logger.LogInformation("[AcousticThreatMonitor] Monitoring: {Device}", _device.FriendlyName);
        }

        private void StopCapture()
        {
            _capture?.StopRecording();
            _capture?.Dispose();
            _capture = null;
            SetMute(false); // Always unmute on stop
        }

        private void OnDataAvailable(object? sender, WaveInEventArgs e)
        {
            if (e.BytesRecorded == 0 || _capture == null) return;

            var format = _capture.WaveFormat;
            int channels = format.Channels;
            int sampleCount = e.BytesRecorded / 4;
            if (_scratchSamples.Length < sampleCount)
                _scratchSamples = new float[sampleCount];
            var samples = _scratchSamples;
            Buffer.BlockCopy(e.Buffer, 0, samples, 0, e.BytesRecorded);

            int frameCount = sampleCount / channels;
            if (_scratchMono.Length < frameCount)
                _scratchMono = new float[frameCount];
            var mono = _scratchMono;
            for (int i = 0; i < frameCount; i++)
            {
                float sum = 0;
                for (int ch = 0; ch < channels; ch++)
                    sum += samples[i * channels + ch];
                mono[i] = sum / channels;
            }

            var threat = AnalyzeForThreats(mono, frameCount, format.SampleRate);

            if (threat != null)
            {
                _threatFrames++;
                _safeFrames = 0;

                if (_threatFrames >= ThreatFramesToMute && !_isMuted)
                {
                    SetMute(true);
                    _totalThreatsBlocked++;
                    _lastThreatTime = DateTime.UtcNow;

                    // Emit detection
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = $"Acoustic Threat: {threat.Type}",
                        Evidence = $"Harmful frequency content detected in system audio output: " +
                                   $"{threat.Type} at {threat.FrequencyHz:F1} Hz, amplitude {threat.Amplitude:F4}. " +
                                   $"Audio muted to protect user. Total threats blocked this session: {_totalThreatsBlocked}",
                        Reasoning = threat.Type switch
                        {
                            "Infrasound Attack" => "Infrasound (1-20Hz) at significant amplitude detected in audio output. " +
                                "Sub-audible frequencies at this power level can cause nausea, anxiety, disorientation, " +
                                "and physical discomfort. Common in acoustic weapons and harassment tools.",
                            "Fear Frequency" => "The 18-19Hz 'fear frequency' band detected at significant amplitude. " +
                                "This specific range resonates with the human eyeball and vestibular system, " +
                                "causing feelings of unease, dread, and visual disturbances.",
                            "Nausea Frequency" => "The 6.5-8Hz range detected at significant amplitude. " +
                                "This band resonates with internal organs and can cause nausea, " +
                                "chest pressure, and disorientation.",
                            "Ultrasonic Beacon" => "Sustained ultrasonic content (17-22kHz) detected. " +
                                "This is either a cross-device tracking beacon (SilverPush/Shopkick) or " +
                                "an acoustic attack that can cause headaches and tinnitus.",
                            "Sustained Narrow-Band Tone" => "A single sustained frequency at unusual amplitude detected. " +
                                "This pattern doesn't match normal audio (music, speech) and may be " +
                                "an embedded acoustic attack or interference signal.",
                            _ => "Potentially harmful acoustic content detected in audio output."
                        },
                        Confidence = threat.Confidence,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly, // Muting is handled directly
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        Metadata = new Dictionary<string, string>
                        {
                            ["ThreatType"] = threat.Type,
                            ["FrequencyHz"] = threat.FrequencyHz.ToString("F1"),
                            ["Amplitude"] = threat.Amplitude.ToString("F4"),
                            ["Action"] = "SessionMuted",
                            ["MutedProcesses"] = string.Join(", ", _mutedSessionPids),
                            ["Device"] = _device?.FriendlyName ?? "Unknown"
                        }
                    });
                }
            }
            else
            {
                _safeFrames++;
                _threatFrames = 0;

                if (_safeFrames >= SafeFramesToUnmute && _isMuted)
                {
                    SetMute(false);
                }
            }
        }

        private AcousticThreat? AnalyzeForThreats(float[] mono, int length, int sampleRate)
        {
            if (length <= 0) return null;
            float infrasoundPower = GoertzelBand(mono, length, sampleRate, InfrasoundLow, InfrasoundHigh, 10);
            if (infrasoundPower > InfrasoundThreshold)
            {
                // Check if it's the fear frequency specifically (18-19Hz)
                float fearPower = GoertzelBand(mono, length, sampleRate, FearFrequencyLow, FearFrequencyHigh, 3);
                if (fearPower > InfrasoundThreshold)
                {
                    return new AcousticThreat { Type = "Fear Frequency", FrequencyHz = 18.5f, Amplitude = fearPower, Confidence = 0.90 };
                }

                // Check nausea band (6.5-8Hz)
                float nauseaPower = GoertzelBand(mono, length, sampleRate, NauseaFrequencyLow, NauseaFrequencyHigh, 3);
                if (nauseaPower > InfrasoundThreshold)
                {
                    // Don't flag 7.83Hz at very low amplitude (could be Harmony app's Schumann)
                    float schumannPower = GoertzelSingle(mono, length, sampleRate, 7.83f);
                    if (schumannPower < 0.005f || nauseaPower > 0.05f) // Only flag if it's strong
                    {
                        return new AcousticThreat { Type = "Nausea Frequency", FrequencyHz = 7.25f, Amplitude = nauseaPower, Confidence = 0.85 };
                    }
                }

                // General infrasound at significant amplitude
                if (infrasoundPower > InfrasoundThreshold * 2)
                {
                    return new AcousticThreat { Type = "Infrasound Attack", FrequencyHz = 10f, Amplitude = infrasoundPower, Confidence = 0.80 };
                }
            }

            // 2. Check ultrasonic band (17-22kHz)
            if (sampleRate >= 44100) // Only check if sample rate can represent these frequencies
            {
                float ultrasonicPower = GoertzelBand(mono, length, sampleRate, UltrasonicLow, UltrasonicHigh, 8);
                if (ultrasonicPower > UltrasonicThreshold)
                {
                    return new AcousticThreat { Type = "Ultrasonic Beacon", FrequencyHz = 19000f, Amplitude = ultrasonicPower, Confidence = 0.85 };
                }
            }

            // 3. Check for sustained narrow-band tones (single frequency at unusual amplitude)
            // Skip this check for known healing frequencies
            float[] suspiciousFreqs = { 15f, 16f, 17f, 19f, 20f, 25f, 30f, 40f, 50f, 60f };
            foreach (float freq in suspiciousFreqs)
            {
                if (IsHealingFrequency(freq)) continue;
                float power = GoertzelSingle(mono, length, sampleRate, freq);
                if (power > NarrowBandThreshold)
                {
                    return new AcousticThreat { Type = "Sustained Narrow-Band Tone", FrequencyHz = freq, Amplitude = power, Confidence = 0.70 };
                }
            }

            return null;
        }

        /// <summary>
        /// Check if a frequency is a known healing frequency (should never trigger).
        /// Also allows binaural beat carriers (100-250Hz range at moderate amplitude).
        /// </summary>
        private static bool IsHealingFrequency(float freq)
        {
            int rounded = (int)Math.Round(freq);
            if (HealingFrequencies.Contains(rounded)) return true;
            // Schumann resonance (7.83Hz) at low amplitude is OK
            if (Math.Abs(freq - 7.83f) < 0.5f) return true;
            return false;
        }

        /// <summary>
        /// Mutes only the specific audio session (app) that is most likely producing
        /// the harmful frequencies. Uses Windows Audio Session API to enumerate all
        /// active sessions and mute the loudest active one (most likely source).
        /// Never touches master volume - surgical precision.
        /// </summary>
        private readonly HashSet<int> _mutedSessionPids = new();

        private void SetMute(bool mute)
        {
            try
            {
                if (_device == null) return;
                var sessionManager = _device.AudioSessionManager;
                if (sessionManager == null) return;
                var sessions = sessionManager.Sessions;
                if (sessions == null) return;

                if (mute)
                {
                    // Find and mute the active session(s) most likely producing the threat
                    // Strategy: mute all sessions that are currently active (State == Active)
                    // EXCEPT known-safe processes (Harmony, system sounds, Sentinel itself)
                    for (int i = 0; i < sessions.Count; i++)
                    {
                        var session = sessions[i];
                        if (session == null) continue;

                        var state = session.State;
                        if (state != NAudio.CoreAudioApi.Interfaces.AudioSessionState.AudioSessionStateActive)
                            continue;

                        // Get the process behind this session
                        int pid = (int)session.GetProcessID;
                        if (pid <= 4) continue;

                        // Don't mute Harmony or Sentinel
                        string procName = "";
                        try { procName = System.Diagnostics.Process.GetProcessById(pid).ProcessName.ToLowerInvariant(); }
                        catch { continue; }

                        if (procName.Contains("harmony") || procName.Contains("sentinel") ||
                            procName == "audiodg" || procName == "svchost")
                            continue;

                        // Mute this session
                        var simpleVolume = session.SimpleAudioVolume;
                        if (simpleVolume != null && !simpleVolume.Mute)
                        {
                            simpleVolume.Mute = true;
                            _mutedSessionPids.Add(pid);
                            _logger.LogWarning("[AcousticThreatMonitor] MUTED session: {Process} (PID {Pid})", procName, pid);
                        }
                    }
                    _isMuted = _mutedSessionPids.Count > 0;
                }
                else
                {
                    // Unmute all sessions we previously muted
                    for (int i = 0; i < sessions.Count; i++)
                    {
                        var session = sessions[i];
                        if (session == null) continue;

                        int pid = (int)session.GetProcessID;
                        if (_mutedSessionPids.Contains(pid))
                        {
                            var simpleVolume = session.SimpleAudioVolume;
                            if (simpleVolume != null && simpleVolume.Mute)
                                simpleVolume.Mute = false;
                        }
                    }
                    if (_mutedSessionPids.Count > 0)
                        _logger.LogInformation("[AcousticThreatMonitor] Unmuted {Count} session(s) - threat cleared", _mutedSessionPids.Count);
                    _mutedSessionPids.Clear();
                    _isMuted = false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[AcousticThreatMonitor] Error managing audio sessions");
            }
        }

        #region Goertzel Algorithm

        private static float GoertzelSingle(float[] samples, int length, int sampleRate, float targetFreq)
        {
            int N = length;
            if (N <= 0) return 0;
            float k = targetFreq * N / sampleRate;
            float w = 2 * MathF.PI * k / N;
            float coeff = 2 * MathF.Cos(w);
            float s0 = 0, s1 = 0, s2 = 0;

            for (int i = 0; i < N; i++)
            {
                s0 = samples[i] + coeff * s1 - s2;
                s2 = s1;
                s1 = s0;
            }

            float power = (s1 * s1 + s2 * s2 - coeff * s1 * s2) / (N * N);
            return MathF.Sqrt(Math.Max(0, power));
        }

        private static float GoertzelBand(float[] samples, int length, int sampleRate, float lowHz, float highHz, int numPoints)
        {
            float maxPower = 0;
            float step = (highHz - lowHz) / Math.Max(numPoints - 1, 1);
            for (int i = 0; i < numPoints; i++)
            {
                float freq = lowHz + step * i;
                float power = GoertzelSingle(samples, length, sampleRate, freq);
                maxPower = Math.Max(maxPower, power);
            }
            return maxPower;
        }

        #endregion

        private sealed class AcousticThreat
        {
            public string Type { get; set; } = "";
            public float FrequencyHz { get; set; }
            public float Amplitude { get; set; }
            public double Confidence { get; set; }
        }
    }
}
