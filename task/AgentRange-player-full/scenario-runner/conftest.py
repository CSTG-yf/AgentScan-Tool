import pathlib
import sys

# runner 测试只导入本目录纯函数，不依赖启动 docker。
sys.path.insert(0, str(pathlib.Path(__file__).parent))

