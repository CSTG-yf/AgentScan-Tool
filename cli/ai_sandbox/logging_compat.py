# -*- coding: utf-8 -*-
"""日志适配层（可移植接缝之一）

原项目用 loguru（`from logger import log`）。为让沙箱层零第三方依赖，
这里用标准库 logging 提供同形态的 `log` 对象：支持
`log.info(msg)` / `log.info(msg, extra={...})` / warning / error / debug，
`extra` 以 JSON 追加到消息尾部（保持原项目「结构化字段」的可读性）。

接入方若已有自己的日志器：
    from ai_sandbox.logging_compat import set_logger
    set_logger(my_logger)          # 任何有 .log(level, msg) 的对象都可以
"""

import json as _json
import logging as _logging
import sys as _sys

__all__ = ["log", "set_logger", "get_logger", "configure"]

_LOGGER_NAME = "ai_sandbox"
_configured = False


def configure(level: str = "INFO", stream=None) -> _logging.Logger:
    """惰性装配一次基础 handler（幂等）。库使用者可完全不调用。"""
    global _configured
    logger = _logging.getLogger(_LOGGER_NAME)
    if not _configured:
        handler = _logging.StreamHandler(stream or _sys.stderr)
        handler.setFormatter(_logging.Formatter(
            "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(getattr(_logging, str(level).upper(), _logging.INFO))
        logger.propagate = False
        _configured = True
    return logger


class _CompatLog:
    """loguru 风格的最小日志门面（只暴露沙箱层实际用到的 level）。"""

    def __init__(self):
        self._logger = None

    # ---- 内部 ----
    def _target(self) -> _logging.Logger:
        if self._logger is not None:
            return self._logger
        return configure()

    @staticmethod
    def _merge(message, extra):
        if not extra:
            return message
        try:
            tail = _json.dumps(extra, ensure_ascii=False, default=str)
        except Exception:  # 兜底：extra 不可序列化
            tail = str(extra)
        return f"{message} | {tail}"

    # ---- 注入 ----
    def set_logger(self, logger):
        """替换底层日志器（需支持 .log(level:int, msg:str)）。"""
        self._logger = logger

    def get_logger(self):
        return self._target()

    # ---- 门面 ----
    def debug(self, message, extra=None):
        self._target().log(_logging.DEBUG, self._merge(message, extra))

    def info(self, message, extra=None):
        self._target().log(_logging.INFO, self._merge(message, extra))

    def warning(self, message, extra=None):
        self._target().log(_logging.WARNING, self._merge(message, extra))

    def error(self, message, extra=None):
        self._target().log(_logging.ERROR, self._merge(message, extra))

    def exception(self, message, extra=None):
        self._target().log(_logging.ERROR, self._merge(message, extra),
                           exc_info=True)


log = _CompatLog()


def set_logger(logger):
    """模块级便捷注入（等价 log.set_logger）。"""
    log.set_logger(logger)


def get_logger():
    return log.get_logger()
