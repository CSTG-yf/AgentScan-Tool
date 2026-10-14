"""Package the arena scanner and its rule file for the desktop installer."""
from pathlib import Path
from hashlib import sha256
import json
import tempfile
import yaml
import os
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
desktop = root / "desktop"
resources = desktop / "src-tauri/resources"
resources.mkdir(parents=True, exist_ok=True)
name = "tracebastion-arena-scan"
foreign = resources / (name if os.name == "nt" else name + ".exe")
foreign.unlink(missing_ok=True)
subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--name", name,
                "--paths", str(root), "--add-data", str(root / "integration/risk_taxonomy.yaml") + os.pathsep + "integration",
                "--distpath", str(resources), "--workpath", str(desktop / ".arena-build/work"),
                "--specpath", str(desktop / ".arena-build"), str(desktop / "scripts/arena_scan_sidecar.py")], check=True)
binary = resources / (name + ".exe" if os.name == "nt" else name)
subprocess.run([str(binary), "--help"], check=True)
with tempfile.TemporaryDirectory() as directory:
    output = Path(directory) / "scan.json"
    subprocess.run([str(binary), "--range-root", str(root / "task/AgentRange-player-full"), "--output", str(output)], check=True)
    measured = json.loads(output.read_text(encoding="utf-8"))
    truth = yaml.safe_load((root / "integration/agentrange_contracts/static-ground-truth-20261012.yaml").read_text(encoding="utf-8"))
    if {a["id"] for a in measured["assets"]} != set(truth["asset_ids"]):
        raise RuntimeError("packaged scanner asset smoke test failed")
    if {(f["rule_id"], f["asset_id"]) for f in measured["findings"]} != {tuple(p) for p in truth["risk_pairs"]}:
        raise RuntimeError("packaged scanner risk smoke test failed")
seed = root / "docs/evidence/20261013-static-mcp-tools/evaluation.json"
if seed.exists():
    shutil.copyfile(seed, resources / "evaluation-static-v0.2.4.json")
else:
    raise FileNotFoundError(f"verified static evaluation seed missing: {seed}")
seed = root / "docs/evidence/20261009-mac-full-pair/evaluation-action.json"
if not seed.exists():
    raise FileNotFoundError(f"verified runtime evaluation seed missing: {seed}")
runtime_report = json.loads(seed.read_text(encoding="utf-8"))
runtime_instances = runtime_report.get("instances", [])
runtime_artifacts = {artifact["id"]: artifact for artifact in runtime_report.get("artifacts", [])}
blocked = [row for row in runtime_instances if row.get("actually_blocked") is True]
if runtime_report.get("mode") != "action" or len(runtime_instances) != 5200 or len(blocked) != 80:
    raise RuntimeError("packaged runtime evaluation evidence is incomplete")
for artifact in runtime_artifacts.values():
    content = artifact.get("content", "")
    if sha256(content.encode("utf-8")).hexdigest() != artifact.get("sha256"):
        raise RuntimeError(f"packaged runtime evaluation evidence hash mismatch: {artifact['id']}")
    json.loads(content)
    if any(private_key in content for private_key in ('"request_body"', '"response_body"', '"prompt"')):
        raise RuntimeError("packaged runtime evaluation contains free-text request data")
for instance in runtime_instances:
    if any(ref not in runtime_artifacts for refs in instance.get("evidence", {}).values() for ref in refs):
        raise RuntimeError(f"packaged runtime evaluation has a missing artifact: {instance['id']}")
shutil.copyfile(seed, resources / "evaluation-runtime-action-v0.2.4.json")
