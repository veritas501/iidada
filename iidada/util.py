# -*- coding: utf8 -*-

import pickle
import zlib

import ida_nalt

DB_SUFFIX = ".iidada"

DB_HEADER = b"IIDADA_DATABASE".ljust(0x10, b'\x00')


def remove_prefix(s, prefix):
    if s.startswith(prefix):
        return s[len(prefix):]
    return s


class LoopBreaker(Exception):
    pass


def build_database(obj):
    flat_obj = pickle.dumps(obj)
    flat_obj = zlib.compress(flat_obj)
    return DB_HEADER + flat_obj


def load_database(data: bytes):
    if not data.startswith(DB_HEADER):
        return None
    data = data[len(DB_HEADER):]
    flat_obj = zlib.decompress(data)
    obj = pickle.loads(flat_obj)
    return obj


def check_rebase():
    pie_base = 0
    return ida_nalt.get_imagebase() != pie_base
