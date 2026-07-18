import pathlib
import sys

# 攻击载荷和 mock 服务按 cat1/cat2/c2_sink 普通包名导入。
sys.path.insert(0, str(pathlib.Path(__file__).parent))
