"""Package the arena scanner and its rule file for the desktop installer."""
from pathlib import Path
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
seed = root / "docs/evidence/20261013-static-mcp-tools/evaluation.json"
if seed.exists():
    shutil.copyfile(seed, resources / "evaluation-static-v0.2.3.json")
else:
    raise FileNotFoundError(f"verified static evaluation seed missing: {seed}")
