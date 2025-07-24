# xfd_django/logger_patch.py  (one per project)

import logging

class XfdLogger(logging.getLoggerClass()):
    def getChild(self, suffix: str):
        if suffix and not suffix.startswith("xfd."):
            suffix = f"xfd.{suffix}"
        return super().getChild(suffix)

def install_xfd_prefix():
    logging.setLoggerClass(XfdLogger)

    _orig_get_logger = logging.getLogger

    def prefixed_get_logger(name=None):
        if name and not name.startswith("xfd."):
            name = f"xfd.{name}"
        return _orig_get_logger(name)

    logging.getLogger = prefixed_get_logger
