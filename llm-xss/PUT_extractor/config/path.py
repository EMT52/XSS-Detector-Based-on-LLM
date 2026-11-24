import os
import json
import sys

__all__ = ["CONFIG_PATH",
           "DATABASE_PATH",
           "LOG_PATH",
           "STORAGE_PATH",
           "NEO4J_CONFIGURE_MAP_PATH",
           "PWD"
           ]

CONFIG_PATH = os.path.realpath(os.path.dirname(__file__))

PWD = os.path.realpath(".")

DATABASE_PATH = os.path.join(PWD, 'databases')
LOG_PATH = os.path.join(PWD, 'log')
STORAGE_PATH = os.path.join(PWD, "storage")
NEO4J_CONFIGURE_MAP_PATH = os.path.join(CONFIG_PATH, 'neo4j.json')


def __mkdir_if_not_exists(PATH: str or list):
    if isinstance(PATH, str):
        dir_path = PATH
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
    if isinstance(PATH, list):
        for _path in PATH:
            __mkdir_if_not_exists(_path)


__mkdir_if_not_exists([
        DATABASE_PATH,
        LOG_PATH,
        STORAGE_PATH,
])

