# -*- coding: utf8 -*-

import ida_ida
import ida_nalt


def is_elf():
    return ida_ida.inf_get_filetype() == ida_ida.f_ELF


def get_filename():
    return ida_nalt.get_root_filename()


def set_loadidc_flag():
    """
    Set mode to `INFFL_LOADIDC`, which means "loading an idc file that
    contains database info".

    :return:
    """
    return ida_ida.inf_set_loading_idc(True)


def unset_loadidc_flag():
    return ida_ida.inf_set_loading_idc(False)
