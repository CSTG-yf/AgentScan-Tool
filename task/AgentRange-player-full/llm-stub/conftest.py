import pathlib
import sys

# 测试直接从 llm-stub 目录加载包，避免依赖安装步骤。
sys.path.insert(0, str(pathlib.Path(__file__).parent))
