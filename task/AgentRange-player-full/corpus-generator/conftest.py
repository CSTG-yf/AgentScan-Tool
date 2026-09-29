import pathlib
import sys

root = pathlib.Path(__file__).parent
# 生成器测试需要同时导入本目录模块和计划二的 cat2 轨迹。
sys.path.insert(0, str(root))
sys.path.insert(0, str(root.parent / "attack"))

