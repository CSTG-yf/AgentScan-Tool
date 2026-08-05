import pathlib
import sys

# MCP 基座测试从当前目录导入 mcp_base 包，避免依赖安装步骤。
sys.path.insert(0, str(pathlib.Path(__file__).parent))

