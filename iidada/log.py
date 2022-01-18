# -*- coding: utf8 -*-

import logging

from iidada.version import PROG_NAME

CRITICAL = logging.CRITICAL
FATAL = logging.FATAL
ERROR = logging.ERROR
WARNING = logging.WARNING
WARN = logging.WARN
INFO = logging.INFO
DEBUG = logging.DEBUG
NOTSET = logging.NOTSET


def get_logger(name, log_level=logging.WARNING):
    log = logging.getLogger(name)
    log.setLevel(log_level)
    formatter = logging.Formatter(
        f'[{PROG_NAME}] %(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    if not log.hasHandlers():
        log.addHandler(handler)
    return log
