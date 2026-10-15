using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

var options = new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true, WriteIndented = true,
    Converters = { new JsonStringEnumConverter() }
};
using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancellation.Cancel(); };
try
{
    if (args.Length < 2) throw new ArgumentException(
        "Usage: verify-ledger FILE [TRUSTED_CHECKPOINT_JSON] | verify-pack DIRECTORY | replay EVENTS_JSONL [CONFIG_JSON] | compare-replays OLD_JSON NEW_JSON | inspect-restore JOURNAL | preview-export EVENTS_JSONL | export EVENTS_JSONL OUTPUT_ZIP");
    object result;
    switch (args[0])
    {
        case "verify-ledger" when args.Length is 2 or 3:
            using (var stream = OpenShared(args[1]))
            using (var reader = new StreamReader(stream))
                result = EvidenceLedger.Verify(reader, args.Length == 3 ?
                    JsonSerializer.Deserialize<LedgerCheckpoint>(ReadShared(args[2]), options) ?? throw new InvalidDataException("Null checkpoint") : null,
                    cancellation.Token);
            break;
        case "verify-pack" when args.Length == 2:
            result = new EvidencePackVerifier().Verify(args[1], cancellation.Token);
            break;
        case "replay" when args.Length is 2 or 3:
            var config = args.Length == 3 ? JsonSerializer.Deserialize<WeightedCorrelationConfig>(ReadShared(args[2]), options)
                ?? throw new InvalidDataException("Null replay configuration") : new WeightedCorrelationConfig();
            result = await new DetectionReplay().RunAsync(ReadDetections(args[1]), config, cancellation.Token);
            break;
        case "compare-replays" when args.Length == 3:
            result = ReplayComparison.Compare(
                JsonSerializer.Deserialize<DetectionReplayReport>(ReadShared(args[1]), options) ?? throw new InvalidDataException("Missing previous replay"),
                JsonSerializer.Deserialize<DetectionReplayReport>(ReadShared(args[2]), options) ?? throw new InvalidDataException("Missing current replay"));
            break;
        case "inspect-restore" when args.Length == 2:
            result = new RestoreTransaction().Inspect(args[1]);
            break;
        case "preview-export" when args.Length == 2:
            var preview = new InvestigationExport().Redact(ReadDetections(args[1]));
            result = new { EventCount = preview.Events.Count, preview.PrivacyScope,
                Fields = new[] { "Timestamp", "ProcessAlias", "Category", "Confidence", "Tier", "SignalType", "RequestedAction" } };
            break;
        case "export" when args.Length == 3:
            var redacted = new InvestigationExport().Redact(ReadDetections(args[1]));
            cancellation.Token.ThrowIfCancellationRequested();
            using (var file = new FileStream(args[2], FileMode.CreateNew, FileAccess.Write, FileShare.Read | FileShare.Delete))
            using (var zip = new ZipArchive(file, ZipArchiveMode.Create))
            {
                var report = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(redacted, options));
                using (var output = zip.CreateEntry("redacted_events.json").Open()) output.Write(report, 0, report.Length);
                using var sha = SHA256.Create();
                var hash = BitConverter.ToString(sha.ComputeHash(report)).Replace("-", "").ToLowerInvariant();
                using var manifest = new StreamWriter(zip.CreateEntry("MANIFEST.sha256").Open(), new UTF8Encoding(false));
                manifest.WriteLine($"{hash}  redacted_events.json");
            }
            result = new { ExportedEvents = redacted.Events.Count, DerivedRedactedCopy = true,
                OriginAuthenticated = false, redacted.PrivacyScope };
            break;
        default: throw new ArgumentException("Unknown command or invalid argument count.");
    }
    Console.WriteLine(JsonSerializer.Serialize(result, options));
    return 0;
}
catch (OperationCanceledException) { Console.Error.WriteLine("Cancelled."); return 130; }
catch (Exception ex) { Console.Error.WriteLine(ex.Message); return 1; }

FileStream OpenShared(string path) => new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
string ReadShared(string path) { using var stream = OpenShared(path); using var reader = new StreamReader(stream); return reader.ReadToEnd(); }

List<DetectionEvent> ReadDetections(string path)
{
    var result = new List<DetectionEvent>();
    using var stream = OpenShared(path);
    if (stream.Length > 64L * 1024 * 1024) throw new InvalidDataException("Maximum 64 MiB of input per offline run.");
    using var reader = new StreamReader(stream);
    string? line;
    while ((line = reader.ReadLine()) != null)
    {
        cancellation.Token.ThrowIfCancellationRequested();
        if (line.Length > 4 * 1024 * 1024) throw new InvalidDataException("Oversized detection record.");
        if (string.IsNullOrWhiteSpace(line)) continue;
        using var document = JsonDocument.Parse(line);
        var root = document.RootElement;
        if (root.TryGetProperty("type", out var type))
        {
            if (type.GetString() != "detection") continue;
            root = root.GetProperty("data");
        }
        if (!root.TryGetProperty("RuleName", out _) && !root.TryGetProperty("ruleName", out _))
            throw new InvalidDataException("Expected a detection record with RuleName.");
        var detection = root.Deserialize<DetectionEvent>(options) ?? throw new InvalidDataException("Null detection.");
        if (!root.TryGetProperty("Timestamp", out _) && !root.TryGetProperty("timestamp", out _))
            throw new InvalidDataException("Detection timestamp is required.");
        result.Add(detection);
        if (result.Count > 100000) throw new InvalidDataException("Maximum 100000 detections per offline run.");
    }
    if (result.Count == 0) throw new InvalidDataException("No detection records found.");
    return result;
}
