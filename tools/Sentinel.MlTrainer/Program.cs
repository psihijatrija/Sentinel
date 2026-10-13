using System.Globalization;
using System.IO.Compression;
using Microsoft.ML;
using Microsoft.ML.Data;
using Sentinel.Core.Ml;

namespace Sentinel.MlTrainer
{
    /// <summary>
    /// Trains PE + URL FastTree models from the CroatiaSecurity/C datasets and writes
    /// pe_model.zip / url_model.zip into src/Sentinel.Core/MlModels for packaging.
    ///
    /// Usage:
    ///   dotnet run --project tools/Sentinel.MlTrainer -- [datasetRoot] [outputDir]
    /// Defaults:
    ///   datasetRoot = D:\Gorstak\C  (or sibling ../../C relative to repo)
    ///   outputDir   = src/Sentinel.Core/MlModels
    /// </summary>
    internal static class Program
    {
        private static int Main(string[] args)
        {
            var repoRoot = FindRepoRoot();
            var datasetRoot = args.Length > 0
                ? Path.GetFullPath(args[0])
                : FirstExisting(
                    @"D:\Gorstak\C",
                    Path.Combine(repoRoot, "..", "C"),
                    Path.Combine(repoRoot, "C"));

            var outDir = args.Length > 1
                ? Path.GetFullPath(args[1])
                : Path.Combine(repoRoot, "src", "Sentinel.Core", "MlModels");

            Directory.CreateDirectory(outDir);

            Console.WriteLine($"Dataset root: {datasetRoot}");
            Console.WriteLine($"Output dir:   {outDir}");

            if (!Directory.Exists(datasetRoot))
            {
                Console.Error.WriteLine("Dataset root not found.");
                return 1;
            }

            var peZip = FirstExistingFile(
                Path.Combine(datasetRoot, "ModelTrainer", "Data", "MalwareDataSet.csv.zip"),
                Path.Combine(datasetRoot, "Datasets", "MalwareDataSet.zip"));
            var urlZip = FirstExistingFile(
                Path.Combine(datasetRoot, "ModelTrainer", "Data", "URLDataSet.csv.zip"),
                Path.Combine(datasetRoot, "Datasets", "URLDataSet.zip"));

            if (peZip == null || urlZip == null)
            {
                Console.Error.WriteLine($"Missing datasets. PE={peZip != null} URL={urlZip != null}");
                return 1;
            }

            var ml = new MLContext(seed: 42);

            Console.WriteLine("Training PE model...");
            var peMetrics = TrainPeModel(ml, peZip, Path.Combine(outDir, "pe_model.zip"));
            Console.WriteLine($"  PE Accuracy={peMetrics.Accuracy:P2} AUC={peMetrics.AreaUnderRocCurve:P2} F1={peMetrics.F1Score:P2}");

            Console.WriteLine("Training URL model...");
            var urlMetrics = TrainUrlModel(ml, urlZip, Path.Combine(outDir, "url_model.zip"));
            Console.WriteLine($"  URL Accuracy={urlMetrics.Accuracy:P2} AUC={urlMetrics.AreaUnderRocCurve:P2} F1={urlMetrics.F1Score:P2}");

            // Command-line obfuscation model (optional): trained only if a labeled dataset exists.
            // Expected CSV columns: commandline,label  (label = bad/1/obfuscated => malicious).
            var cmdZip = FirstExistingFile(
                Path.Combine(datasetRoot, "ModelTrainer", "Data", "CommandLineDataSet.csv.zip"),
                Path.Combine(datasetRoot, "Datasets", "CommandLineDataSet.zip"));
            var cmdCsv = FirstExistingFile(
                Path.Combine(datasetRoot, "ModelTrainer", "Data", "CommandLineDataSet.csv"),
                Path.Combine(datasetRoot, "Datasets", "CommandLineDataSet.csv"));

            if (cmdZip != null || cmdCsv != null)
            {
                Console.WriteLine("Training command-line model...");
                var cmdMetrics = TrainCommandLineModel(ml, cmdZip, cmdCsv, Path.Combine(outDir, "cmdline_model.zip"));
                Console.WriteLine($"  Cmd Accuracy={cmdMetrics.Accuracy:P2} AUC={cmdMetrics.AreaUnderRocCurve:P2} F1={cmdMetrics.F1Score:P2}");
            }
            else
            {
                Console.WriteLine("Command-line dataset not found - skipping cmdline_model.zip. " +
                                  "MlThreatScorer.ScoreCommandLine falls back to its deterministic heuristic.");
            }

            Console.WriteLine("Done.");
            return 0;
        }

        private static BinaryClassificationMetrics TrainPeModel(MLContext ml, string zipPath, string outPath)
        {
            string csvPath = ExtractCsv(zipPath);
            try
            {
                // Dataset uses '|' separator; last column "legitimate" (1=good, 0=malware).
                // Label=true means malware.
                var rows = LoadPeRows(csvPath);
                Console.WriteLine($"  PE rows: {rows.Count}");

                var data = ml.Data.LoadFromEnumerable(rows);
                var split = ml.Data.TrainTestSplit(data, testFraction: 0.2, seed: 42);
                var pipeline = ml.Transforms.Concatenate("Features", PeFeatureVector.FeatureNames)
                    .Append(ml.BinaryClassification.Trainers.FastTree(
                        labelColumnName: nameof(PeFeatureVector.Label),
                        featureColumnName: "Features",
                        numberOfLeaves: 32,
                        numberOfTrees: 100,
                        minimumExampleCountPerLeaf: 20));

                var model = pipeline.Fit(split.TrainSet);
                var predictions = model.Transform(split.TestSet);
                var metrics = ml.BinaryClassification.Evaluate(
                    predictions, labelColumnName: nameof(PeFeatureVector.Label));

                var fullModel = pipeline.Fit(data);
                using var fs = File.Create(outPath);
                ml.Model.Save(fullModel, data.Schema, fs);
                return metrics;
            }
            finally
            {
                try { File.Delete(csvPath); } catch { }
            }
        }

        private static List<PeFeatureVector> LoadPeRows(string csvPath)
        {
            var rows = new List<PeFeatureVector>(150_000);
            using var sr = new StreamReader(csvPath);
            string? header = sr.ReadLine();
            if (header == null) throw new InvalidOperationException("Empty PE dataset");

            // Expected: Name|md5|54 features|legitimate  => 57 columns
            string? line;
            while ((line = sr.ReadLine()) != null)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var parts = line.Split('|');
                if (parts.Length < 57) continue;

                var v = new PeFeatureVector();
                // parts[0]=Name, parts[1]=md5, parts[2..55]=features, parts[56]=legitimate
                int fi = 0;
                float F(int idx) =>
                    float.TryParse(parts[idx], NumberStyles.Float, CultureInfo.InvariantCulture, out var x) ? x : 0f;

                v.Machine = F(2 + fi++);
                v.SizeOfOptionalHeader = F(2 + fi++);
                v.Characteristics = F(2 + fi++);
                v.MajorLinkerVersion = F(2 + fi++);
                v.MinorLinkerVersion = F(2 + fi++);
                v.SizeOfCode = F(2 + fi++);
                v.SizeOfInitializedData = F(2 + fi++);
                v.SizeOfUninitializedData = F(2 + fi++);
                v.AddressOfEntryPoint = F(2 + fi++);
                v.BaseOfCode = F(2 + fi++);
                v.BaseOfData = F(2 + fi++);
                v.ImageBase = F(2 + fi++);
                v.SectionAlignment = F(2 + fi++);
                v.FileAlignment = F(2 + fi++);
                v.MajorOperatingSystemVersion = F(2 + fi++);
                v.MinorOperatingSystemVersion = F(2 + fi++);
                v.MajorImageVersion = F(2 + fi++);
                v.MinorImageVersion = F(2 + fi++);
                v.MajorSubsystemVersion = F(2 + fi++);
                v.MinorSubsystemVersion = F(2 + fi++);
                v.SizeOfImage = F(2 + fi++);
                v.SizeOfHeaders = F(2 + fi++);
                v.CheckSum = F(2 + fi++);
                v.Subsystem = F(2 + fi++);
                v.DllCharacteristics = F(2 + fi++);
                v.SizeOfStackReserve = F(2 + fi++);
                v.SizeOfStackCommit = F(2 + fi++);
                v.SizeOfHeapReserve = F(2 + fi++);
                v.SizeOfHeapCommit = F(2 + fi++);
                v.LoaderFlags = F(2 + fi++);
                v.NumberOfRvaAndSizes = F(2 + fi++);
                v.SectionsNb = F(2 + fi++);
                v.SectionsMeanEntropy = F(2 + fi++);
                v.SectionsMinEntropy = F(2 + fi++);
                v.SectionsMaxEntropy = F(2 + fi++);
                v.SectionsMeanRawsize = F(2 + fi++);
                v.SectionsMinRawsize = F(2 + fi++);
                v.SectionMaxRawsize = F(2 + fi++);
                v.SectionsMeanVirtualsize = F(2 + fi++);
                v.SectionsMinVirtualsize = F(2 + fi++);
                v.SectionMaxVirtualsize = F(2 + fi++);
                v.ImportsNbDLL = F(2 + fi++);
                v.ImportsNb = F(2 + fi++);
                v.ImportsNbOrdinal = F(2 + fi++);
                v.ExportNb = F(2 + fi++);
                v.ResourcesNb = F(2 + fi++);
                v.ResourcesMeanEntropy = F(2 + fi++);
                v.ResourcesMinEntropy = F(2 + fi++);
                v.ResourcesMaxEntropy = F(2 + fi++);
                v.ResourcesMeanSize = F(2 + fi++);
                v.ResourcesMinSize = F(2 + fi++);
                v.ResourcesMaxSize = F(2 + fi++);
                v.LoadConfigurationSize = F(2 + fi++);
                v.VersionInformationSize = F(2 + fi++);

                float legitimate = F(2 + fi); // index 56
                v.Label = Math.Abs(legitimate) < 0.5f; // 0 => malware
                rows.Add(v);
            }

            return rows;
        }

        private static BinaryClassificationMetrics TrainUrlModel(MLContext ml, string zipPath, string outPath)
        {
            string csvPath = ExtractCsv(zipPath);
            try
            {
                var rows = new List<UrlFeatureVector>(capacity: 100_000);
                using (var sr = new StreamReader(csvPath))
                {
                    string? header = sr.ReadLine();
                    if (header == null) throw new InvalidOperationException("Empty URL dataset");

                    string? line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        // url,label  - label is "bad" or "good" (label may contain commas rarely; take last comma)
                        int comma = line.LastIndexOf(',');
                        if (comma <= 0) continue;
                        string url = line[..comma].Trim().Trim('"');
                        string label = line[(comma + 1)..].Trim().Trim('"');
                        if (url.Length == 0) continue;

                        var fv = UrlFeatureExtractor.Extract(url);
                        fv.Label = label.Equals("bad", StringComparison.OrdinalIgnoreCase)
                                   || label.Equals("1", StringComparison.OrdinalIgnoreCase)
                                   || label.Equals("malware", StringComparison.OrdinalIgnoreCase);
                        rows.Add(fv);
                    }
                }

                Console.WriteLine($"  URL rows: {rows.Count}");
                var data = ml.Data.LoadFromEnumerable(rows);
                var split = ml.Data.TrainTestSplit(data, testFraction: 0.2, seed: 42);

                var pipeline = ml.Transforms.Concatenate("Features", UrlFeatureVector.FeatureNames)
                    .Append(ml.BinaryClassification.Trainers.FastTree(
                        labelColumnName: nameof(UrlFeatureVector.Label),
                        featureColumnName: "Features",
                        numberOfLeaves: 32,
                        numberOfTrees: 80,
                        minimumExampleCountPerLeaf: 15));

                var model = pipeline.Fit(split.TrainSet);
                var predictions = model.Transform(split.TestSet);
                var metrics = ml.BinaryClassification.Evaluate(
                    predictions, labelColumnName: nameof(UrlFeatureVector.Label));

                var fullModel = pipeline.Fit(data);
                using var fs = File.Create(outPath);
                ml.Model.Save(fullModel, data.Schema, fs);
                return metrics;
            }
            finally
            {
                try { File.Delete(csvPath); } catch { }
            }
        }

        private static BinaryClassificationMetrics TrainCommandLineModel(
            MLContext ml, string? zipPath, string? csvPathDirect, string outPath)
        {
            string csvPath = csvPathDirect ?? ExtractCsv(zipPath!);
            bool extracted = csvPathDirect == null;
            try
            {
                var rows = new List<CommandLineFeatureVector>(capacity: 100_000);
                using (var sr = new StreamReader(csvPath))
                {
                    string? header = sr.ReadLine();
                    if (header == null) throw new InvalidOperationException("Empty command-line dataset");

                    string? line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        // commandline,label - take the LAST comma as the label separator so command
                        // lines (which contain commas) are preserved intact.
                        int comma = line.LastIndexOf(',');
                        if (comma <= 0) continue;
                        string cmd = line[..comma].Trim().Trim('"');
                        string label = line[(comma + 1)..].Trim().Trim('"');
                        if (cmd.Length == 0) continue;

                        var fv = CommandLineFeatureExtractor.Extract(cmd);
                        fv.Label = label.Equals("bad", StringComparison.OrdinalIgnoreCase)
                                   || label.Equals("1", StringComparison.OrdinalIgnoreCase)
                                   || label.Equals("malicious", StringComparison.OrdinalIgnoreCase)
                                   || label.Equals("obfuscated", StringComparison.OrdinalIgnoreCase);
                        rows.Add(fv);
                    }
                }

                Console.WriteLine($"  Cmd rows: {rows.Count}");
                var data = ml.Data.LoadFromEnumerable(rows);
                var split = ml.Data.TrainTestSplit(data, testFraction: 0.2, seed: 42);

                var pipeline = ml.Transforms.Concatenate("Features", CommandLineFeatureVector.FeatureNames)
                    .Append(ml.BinaryClassification.Trainers.FastTree(
                        labelColumnName: nameof(CommandLineFeatureVector.Label),
                        featureColumnName: "Features",
                        numberOfLeaves: 32,
                        numberOfTrees: 100,
                        minimumExampleCountPerLeaf: 15));

                var model = pipeline.Fit(split.TrainSet);
                var predictions = model.Transform(split.TestSet);
                var metrics = ml.BinaryClassification.Evaluate(
                    predictions, labelColumnName: nameof(CommandLineFeatureVector.Label));

                var fullModel = pipeline.Fit(data);
                using var fs = File.Create(outPath);
                ml.Model.Save(fullModel, data.Schema, fs);
                return metrics;
            }
            finally
            {
                if (extracted) { try { File.Delete(csvPath); } catch { } }
            }
        }

        private static string ExtractCsv(string zipPath)
        {
            var temp = Path.Combine(Path.GetTempPath(), "sentinel_ml_" + Guid.NewGuid().ToString("N") + ".csv");
            using var zip = ZipFile.OpenRead(zipPath);
            var entry = zip.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidOperationException("No CSV in " + zipPath);
            entry.ExtractToFile(temp, overwrite: true);
            return temp;
        }

        private static string FindRepoRoot()
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "Sentinel.sln")))
                    return dir.FullName;
                dir = dir.Parent;
            }
            // tools/Sentinel.MlTrainer -> repo root is ../..
            return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        }

        private static string FirstExisting(params string[] paths)
        {
            foreach (var p in paths)
            {
                var full = Path.GetFullPath(p);
                if (Directory.Exists(full)) return full;
            }
            return Path.GetFullPath(paths[0]);
        }

        private static string? FirstExistingFile(params string[] paths)
        {
            foreach (var p in paths)
                if (File.Exists(p)) return p;
            return null;
        }

    }
}
