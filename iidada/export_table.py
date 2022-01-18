# -*- coding: utf8 -*-

import ida_entry


def dump_export_table():
    cnt = ida_entry.get_entry_qty()
    export_table = dict()
    for i in range(cnt):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        export_table[name] = ea
    return export_table
