import importlib.util
import json
from pathlib import Path


def _load_sidecar():
    path = Path(__file__).resolve().parents[2] / "cli" / "defenseclaw" / "agentrange_sidecar.py"
    spec = importlib.util.spec_from_file_location("agentrange_sidecar_stack_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_sidecar_accepts_relative_application_frames_and_rejects_path_leaks():
    sidecar = _load_sidecar()
    rows = [
        {"file": "api/app.py", "function": "call_mcp", "line": 389},
        {"file": "/app/api/app.py", "function": "call_mcp", "line": 389},
        {"file": "api/../secrets.env", "function": "call_mcp", "line": 1},
        {"file": "api/app.py", "function": "bad-name", "line": 3},
    ]
    assert sidecar.parse_agent_stack_header(json.dumps(rows)) == [rows[0]]
    assert sidecar.parse_agent_stack_header("x" * 5000) == []
