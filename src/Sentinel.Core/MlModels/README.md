# Offline ML models

Train from the CroatiaSecurity/C datasets:

```powershell
dotnet run -c Release --project tools/Sentinel.MlTrainer -- D:\Gorstak\C src\Sentinel.Core\MlModels
```

Produces:
- `pe_model.zip` - PE static malware classifier (FastTree)
- `url_model.zip` - lexical URL/host classifier (FastTree)

These are soft signals only (never sole kill). Installer/build copies them into `MlModels\` next to the service/agent.

Training now writes `<model>.training.json` with source/CSV/model SHA-256 values,
feature order, seed, split, trainer version and held-out metrics. It saves the exact
train-only model evaluated on the held-out partition; it does not silently refit on
the full dataset after reporting those metrics. These are internal random-split
metrics, not independent or temporal/family-separated protection evidence.

Runtime model loading verifies release-reviewed compiled integrity pins in
`Ml/ModelIntegrity.cs`, using the same stream for verification and loading. A model
update needs a reviewed pin change and its training report. A matching writable
sidecar alone grants no trust. An unavailable model does not disable the others.
The existing shipped models have byte-integrity pins; their original training
provenance is still unavailable and has not been fabricated or replaced here.
