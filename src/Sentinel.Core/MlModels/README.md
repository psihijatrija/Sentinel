# Offline ML models

Train from the CroatiaSecurity/C datasets:

```powershell
dotnet run -c Release --project tools/Sentinel.MlTrainer -- D:\Gorstak\C src\Sentinel.Core\MlModels
```

Produces:
- `pe_model.zip` - PE static malware classifier (FastTree)
- `url_model.zip` - lexical URL/host classifier (FastTree)

These are soft signals only (never sole kill). Installer/build copies them into `MlModels\` next to the service/agent.
