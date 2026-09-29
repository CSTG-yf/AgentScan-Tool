import pathlib
import sys

# 测试从 opspilot-app 根目录加载 api/auth/policy 三个本地包。
sys.path.insert(0, str(pathlib.Path(__file__).parent))
