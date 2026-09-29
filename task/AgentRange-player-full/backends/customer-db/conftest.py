import pathlib
import sys

# seed.py 作为该目录的运行脚本存在，测试时直接把当前目录加入导入路径。
sys.path.insert(0, str(pathlib.Path(__file__).parent))
