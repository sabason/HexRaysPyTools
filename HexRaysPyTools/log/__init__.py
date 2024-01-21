import logging
from enum import IntEnum


class LogLevel(IntEnum):
    Debug = logging.DEBUG,
    Info = logging.INFO,
    Warning = logging.WARNING,
    Critical = logging.CRITICAL,
    Error = logging.ERROR,


class Log:
    __name = "HexRaysPyTools"
    
    __logger: logging.Logger = None
    __init: bool = False
    
    def __new__(cls):
        raise TypeError("Static classes cannot be instantiated")
    
    @classmethod
    def init(cls):
        if not cls.__init:
            cls.__logger = logging.getLogger(cls.__name)
            cls.__logger.handlers = list()
            
            stream = logging.StreamHandler()
            stream.setFormatter(logging.Formatter("[%(levelname)s] %(message)s\t(%(module)s:%(funcName)s)"))
            cls.__logger.addHandler(stream)
            cls.__logger.setLevel(logging.NOTSET)
            
            cls.__init = True
    
    @classmethod
    def get_logger(cls) -> logging.Logger:
        return cls.__logger
    
    @classmethod
    def set_root_log_level(cls, level: LogLevel):
        cls.__logger.setLevel(level)
    
    @classmethod
    def set_stream_log_level(cls, level: LogLevel):
        stream_handler = list(filter(lambda x: isinstance(x, logging.StreamHandler), cls.__logger.handlers))[0]
        stream_handler.setLevel(level)


Log.init()
