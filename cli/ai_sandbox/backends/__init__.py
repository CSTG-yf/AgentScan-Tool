# -*- coding: utf-8 -*-
"""沙箱后端实现（轴 A）

bwrap        Linux：文件系统/进程命名空间隔离 + seccomp 系统调用黑名单（strong）
sandbox-exec macOS：Seatbelt SBPL 策略沙箱 + symlink farm（weak）
appcontainer Windows：AppContainer + Job Object 级联 + ACL 收紧（weak）
null         全平台兜底：直执不隔离（none；strict 画像下被启动门禁拦截）
"""
