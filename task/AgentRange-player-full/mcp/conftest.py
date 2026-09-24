import pathlib
import sys

root = pathlib.Path(__file__).parent
# MCP 子模块按普通包名导入，方便 TestClient 直接加载 server.py。
sys.path.insert(0, str(root / "_base"))
sys.path.insert(0, str(root))

