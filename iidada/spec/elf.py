# -*- coding: utf8 -*-

import ida_auto
import ida_bytes
import ida_segment
import ida_xref
import idautils
import idc
import iidada.log
from ida_idaapi import BADADDR
from iidada.segment import get_segments_by_name, get_segm_ori_name
from iidada.util import remove_prefix

log = iidada.log.get_logger("spec.elf")


def elf_get_external_function():
    def get_xref_in_got(target_ea, first_ref_ea=0):
        if not first_ref_ea:
            tmp_ref_ea = ida_xref.get_first_dref_to(ea)
        else:
            tmp_ref_ea = ida_xref.get_next_dref_to(ea, first_ref_ea)
        if tmp_ref_ea == BADADDR:
            return None
        segm_ori_name = get_segm_ori_name(ida_segment.getseg(tmp_ref_ea))
        if segm_ori_name in ['.got', '.got.plt']:
            return tmp_ref_ea
        return get_xref_in_got(target_ea, tmp_ref_ea)  # find next ref

    def get_extern_name(_ea):
        _name = idc.get_func_name(_ea)
        # try to remove __imp_ prefix
        _name = remove_prefix(_name, '__imp_')
        # try to remove numerical suffix
        last_underscore = _name.rfind('_')
        if last_underscore != -1 and _name[last_underscore + 1:].isdecimal():
            _name = _name[:last_underscore]
        return _name

    # get all extern segments
    extern_segments = get_segments_by_name('extern')
    if not extern_segments:
        log.error("Can't find extern segment")
        return None

    extern_functions = dict()  # func_name: got_ea
    for extern_seg in extern_segments:
        log.debug("Extern segment: {}".format(
            hex(extern_seg.start_ea)
        ))
        # get extern functions
        extern_func_ea = idautils.Functions(
            extern_seg.start_ea,
            extern_seg.end_ea + 1
        )
        for ea in extern_func_ea:
            log.debug("Extern function: {}".format(
                hex(ea)
            ))
            if ref_ea := get_xref_in_got(ea):
                log.debug("Find extern symbol `{}` @ {}".format(
                    get_extern_name(ea), hex(ref_ea)
                ))
                extern_functions[ref_ea] = get_extern_name(ea)

    return extern_functions


def fix_elf_got(export_tbl):
    ida_auto.auto_wait()
    ext_functions = elf_get_external_function()
    for got_ea, name in ext_functions.items():
        if address := export_tbl.get(name):
            log.debug("Patch got `{}` @ {} to {}".format(
                name, hex(got_ea), hex(address)
            ))
            ida_bytes.patch_qword(got_ea, address)
            # some magic, so plt disassemble correctly
            ida_bytes.op_hex(got_ea, -1)
            ida_bytes.set_cmt(
                got_ea,
                "Patched by iidada, DON'T change it to `offset` type",
                True
            )
    return


def do_spec(db):
    if export_table := db.get('export_table'):
        # try to fix got table
        fix_elf_got(export_table)
    return
