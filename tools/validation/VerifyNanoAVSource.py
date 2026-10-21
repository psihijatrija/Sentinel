"""Verify the exact original/coexistence source scope recorded for NanoAV."""

import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def main():
    root = Path(__file__).resolve().parents[2] / "modules" / "NanoAV"
    manifest = json.loads((root / "UPSTREAM.json").read_text(encoding="utf-8"))
    allowed = {
        "src/NanoC2Engine.cs", "src/NanoFileScanner.cs", "src/NanoMemoryScanner.cs",
        "src/NanoPidRegistry.cs", "src/NanoThreatAnalysis.cs",
    }
    changed = set()
    original_sources = set()
    entries = manifest["files"]
    if len(entries) != 22 or len({item["path"] for item in entries}) != 22:
        raise ValueError("Expected the 22 distinct supplied files")
    for item in entries:
        path = (root / item["path"]).resolve()
        if root.resolve() not in path.parents:
            raise ValueError("Manifest path escapes module")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != item["integrated_sha256"]:
            raise ValueError("Integrated source changed: " + item["path"])
        differs = item["original_sha256"] != actual
        if differs != item["changed_for_coexistence"]:
            raise ValueError("Original/integrated scope mismatch: " + item["path"])
        if differs:
            changed.add(item["path"])
        if path.suffix == ".cs":
            original_sources.add(path.name)
    if changed != allowed:
        raise ValueError("Changes exceed the five coexistence call-site files")
    expected_sources = original_sources | {"SentinelCoexistence.cs"}
    if {path.name for path in (root / "src").glob("*.cs")} != expected_sources:
        raise ValueError("Unexpected replacement source in NanoAV")
    project = ET.parse(root / "NanoAV.csproj").getroot()
    if list(project.iter("ProjectReference")) or list(project.iter("PackageReference")):
        raise ValueError("NanoAV must remain independent of Sentinel's engine")
    print("NanoAV source scope verified: 17 unchanged files, 5 coexistence-only files, separate helper.")


if __name__ == "__main__":
    main()
