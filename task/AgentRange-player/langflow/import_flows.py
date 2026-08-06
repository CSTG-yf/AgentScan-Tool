import json
import os
import pathlib
import sys

import httpx

BASE = os.getenv("LANGFLOW_BASE", "http://langflow:7860")
FLOWS_DIR = pathlib.Path(__file__).parent / "flows"


def fetch_token(client: httpx.Client) -> str:
    # AUTO_LOGIN 是配置风险，也是导入 flow 时获取 token 的入口。
    return client.get(f"{BASE}/api/v1/auto_login").json()["access_token"]


def import_all() -> list[str]:
    imported = []
    with httpx.Client(timeout=30) as client:
        headers = {"Authorization": f"Bearer {fetch_token(client)}"}
        # 真实 flow 由 pinned Langflow UI 导出；这里按目录批量导入。
        for path in sorted(FLOWS_DIR.glob("*.json")):
            flow = json.loads(path.read_text(encoding="utf-8"))
            response = client.post(f"{BASE}/api/v1/flows/", json=flow, headers=headers)
            response.raise_for_status()
            imported.append(flow["name"])
    return imported


if __name__ == "__main__":
    names = import_all()
    print("imported:", names)
    sys.exit(0 if names else 1)

