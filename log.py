"""
 author rufeng
 date 2021/11/12/12:13
 description 
"""
import logging
import sys

datefmt = "%Y-%m-%d %H:%M:%S"


def get_logger(name: str, log_level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s', datefmt=datefmt)

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setLevel(log_level)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)

    return logger
