# -*- coding: utf8 -*-

"""
Dump or load symbols
"""

from enum import Enum, auto

import ida_bytes
import ida_lines
import ida_nalt
import ida_name
import ida_offset
import ida_struct
import ida_ua
import idc
import iidada.log
from ida_idaapi import BADADDR

log = iidada.log.get_logger("name")


class NameOp(Enum):
    CMT = auto()  # comment
    CMT_EX = auto()  # extra comments
    TYP_BYTE = auto()  # create_byte
    TYP_WORD = auto()  # create_word
    TYP_DWORD = auto()  # create_dword
    TYP_QWORD = auto()  # create_qword
    TYP_TBYTE = auto()  # create_tbyte
    TYP_STRLIT = auto()  # create_strlit
    TYP_STRUCT = auto()  # create_struct
    TYP_OWORD = auto()  # create_oword
    TYP_FLOAT = auto()  # create_float
    TYP_DOUBLE = auto()  # create_double
    TYP_PACKREAL = auto()  # create_pack_real
    TYP_YWORD = auto()  # create_yword
    TYP_ZWORD = auto()  # create_zword
    TYP_INST = auto()  # create_inst
    ARRAY = auto()
    TOGGLE_SIGN = auto()  # toggle_sign
    TOGGLE_BNOT = auto()  # toggle_bnot
    OP_SEG = auto()  # op_seg
    OP_CHR = auto()  # op_chr
    OP_STKVAR = auto()  # op_stkvar
    OP_BIN = auto()  # op_bin
    OP_OCT = auto()  # op_oct
    OP_DEC = auto()  # op_dec
    OP_HEX = auto()  # op_hex
    OP_OFFSET = auto()  # op_offset
    OP_ENUM = auto()  # op_enum
    OP_STROFF = auto()  # op_stroff
    OP_MAN = auto()  # op_man
    SET_NAME = auto()


class IDANameInfo:
    def __init__(self, ea, item_length):
        self.ea = ea
        self.length = item_length
        self.op = list()


def dump_names():
    def matcher(typ):
        # 0x6C00 -> FF_COMM | FF_DATA | FF_LINE | FF_NAME
        return ida_bytes.has_cmt(typ) or \
               ida_bytes.is_data(typ) or \
               ida_bytes.has_extra_cmts(typ) or \
               ida_bytes.has_name(typ)

    name_infos = list()
    ea = 0
    while True:
        # find next ea that match the condition
        ea = ida_bytes.next_that(ea, BADADDR, matcher)
        if ea == BADADDR:
            # break loop
            break
        flags = ida_bytes.get_flags(ea)
        item_length = ida_bytes.get_item_end(ea) - ea
        inf = IDANameInfo(ea, item_length)
        if cmt := ida_bytes.get_cmt(ea, 0):
            tmp_op = (NameOp.CMT, cmt)
            inf.op.append(tmp_op)
        if ida_bytes.has_extra_cmts(flags):
            extra_cmt_idx = 0
            tmp_op = (NameOp.CMT_EX, list())
            while extra_cmt := ida_lines.get_extra_cmt(
                    ea, ida_lines.E_PREV + extra_cmt_idx):
                tmp_op[1].append((extra_cmt, ida_lines.E_PREV + extra_cmt_idx))
                extra_cmt_idx += 1
            extra_cmt_idx = 0
            while extra_cmt := ida_lines.get_extra_cmt(
                    ea, ida_lines.E_NEXT + extra_cmt_idx):
                tmp_op[1].append((extra_cmt, ida_lines.E_NEXT + extra_cmt_idx))
                extra_cmt_idx += 1
            inf.op.append(tmp_op)
        if ida_bytes.is_code(flags):
            if ida_bytes.is_flow(flags) or ida_bytes.is_func(flags):
                inf.op.append((NameOp.TYP_INST,))
        elif ida_bytes.is_data(flags):

            if ida_bytes.is_byte(flags):
                inf.op.append((NameOp.TYP_BYTE,))
            elif ida_bytes.is_word(flags):
                inf.op.append((NameOp.TYP_WORD,))
            elif ida_bytes.is_dword(flags):
                inf.op.append((NameOp.TYP_DWORD,))
            elif ida_bytes.is_qword(flags):
                inf.op.append((NameOp.TYP_QWORD,))
            elif ida_bytes.is_tbyte(flags):
                inf.op.append((NameOp.TYP_TBYTE,))
            elif ida_bytes.is_strlit(flags):
                str_type = ida_nalt.get_str_type(ea)
                inf.op.append((NameOp.TYP_STRLIT, str_type))
            elif ida_bytes.is_oword(flags):
                inf.op.append((NameOp.TYP_OWORD,))
            elif ida_bytes.is_float(flags):
                inf.op.append((NameOp.TYP_FLOAT,))
            elif ida_bytes.is_double(flags):
                inf.op.append((NameOp.TYP_DOUBLE,))
            elif ida_bytes.is_pack_real(flags):
                inf.op.append((NameOp.TYP_PACKREAL,))
            elif ida_bytes.is_yword(flags):
                inf.op.append((NameOp.TYP_YWORD,))
            elif ida_bytes.is_zword(flags):
                inf.op.append((NameOp.TYP_ZWORD,))
            elif ida_bytes.is_struct(flags):
                struc_id = ida_nalt.get_strid(ea)
                struc = ida_struct.get_struc(struc_id)
                struc_name = ida_struct.get_struc_name(struc_id)
                is_var_size = struc.is_varstr()
                var_size = item_length if not is_var_size else 0
                tmp_op = (NameOp.TYP_STRUCT, struc_name, is_var_size, var_size)
                inf.op.append(tmp_op)

            for op_idx in range(2):
                if ida_bytes.is_invsign(ea, flags, op_idx):
                    inf.op.append((NameOp.TOGGLE_SIGN, op_idx))
                if ida_bytes.is_bnot(ea, flags, op_idx):
                    inf.op.append((NameOp.TOGGLE_BNOT, op_idx))
                if not ida_bytes.is_defarg(flags, op_idx):
                    continue
                if ida_bytes.is_off(flags, op_idx):
                    indexes = [op_idx, op_idx | 0x80]
                    for index in indexes:
                        ref_info = ida_nalt.refinfo_t()
                        if ida_nalt.get_refinfo(ref_info, ea, index):
                            if ref_info.is_rvaoff():
                                # noinspection PyPropertyAccess
                                tmp_op = (
                                    NameOp.OP_OFFSET, True, index,
                                    ref_info.flags, ref_info.target,
                                    ref_info.base, ref_info.tdelta
                                )
                            else:
                                # noinspection PyPropertyAccess
                                tmp_op = (
                                    NameOp.OP_OFFSET, False, index,
                                    ref_info.base
                                )
                            inf.op.append(tmp_op)
                if ida_bytes.is_seg(flags, op_idx):
                    inf.op.append((NameOp.OP_SEG, op_idx))
                if ida_bytes.is_char(flags, op_idx):
                    inf.op.append((NameOp.OP_CHR, op_idx))
                if ida_bytes.is_enum(flags, op_idx):
                    # TODO: dump is_enum()
                    log.warn(f"TODO: dump OP_ENUM: {hex(ea)}")
                if ida_bytes.is_stroff(flags, op_idx):
                    # TODO: dump is_stroff()
                    log.warn(f"TODO: dump OP_STROFF: {hex(ea)}")
                if ida_bytes.is_stkvar(flags, op_idx):
                    inf.op.append((NameOp.OP_STKVAR, op_idx))
                if ida_bytes.is_numop(flags, op_idx):
                    radix = ida_bytes.get_radix(flags, op_idx)
                    if radix == 2:
                        inf.op.append((NameOp.OP_BIN, op_idx))
                    elif radix == 8:
                        inf.op.append((NameOp.OP_OCT, op_idx))
                    elif radix == 10:
                        inf.op.append((NameOp.OP_DEC, op_idx))
                    elif radix == 16:
                        inf.op.append((NameOp.OP_HEX, op_idx))
                    else:
                        # TODO: OP_MAN
                        log.warn(f"TODO: dump OP_MAN: {hex(ea)}")
        else:  # not is_data
            # TODO: not is_data(), OP_MAN
            log.warn(f"TODO: dump OP_MAN2: {hex(ea)}")
        if ida_bytes.has_name(flags):
            ea_name = ida_name.get_ea_name(ea)
            if ea_name:
                inf.op.append((NameOp.SET_NAME, ea_name))
        name_infos.append(inf)
    return name_infos


def load_names(name_infos, struct_rename_map):
    for inf in name_infos:
        ea = inf.ea
        length = inf.length
        for op in inf.op:
            op_type = op[0]
            op_arg = op[1:]
            if op_type == NameOp.CMT:
                ida_bytes.set_cmt(ea, op_arg[0], 0)
            elif op_type == NameOp.CMT_EX:
                for cmt, pos in op_arg[0]:
                    ida_lines.update_extra_cmt(ea, pos, cmt)
            elif op_type == NameOp.TYP_BYTE:
                ida_bytes.create_byte(ea, length)
            elif op_type == NameOp.TYP_WORD:
                ida_bytes.create_word(ea, length)
            elif op_type == NameOp.TYP_DWORD:
                ida_bytes.create_dword(ea, length)
            elif op_type == NameOp.TYP_QWORD:
                ida_bytes.create_qword(ea, length)
            elif op_type == NameOp.TYP_TBYTE:
                ida_bytes.create_tbyte(ea, length)
            elif op_type == NameOp.TYP_STRLIT:
                ida_bytes.create_strlit(ea, length, op_arg[0])
            elif op_type == NameOp.TYP_STRUCT:
                struc_name = op_arg[0]
                var_size = op_arg[2]
                if struc_name := struct_rename_map.get(struc_name):
                    sid = ida_struct.get_struc_id(struc_name)
                    ida_bytes.create_struct(ea, var_size, sid)
            elif op_type == NameOp.TYP_OWORD:
                ida_bytes.create_oword(ea, length)
            elif op_type == NameOp.TYP_FLOAT:
                ida_bytes.create_float(ea, length)
            elif op_type == NameOp.TYP_DOUBLE:
                ida_bytes.create_double(ea, length)
            elif op_type == NameOp.TYP_PACKREAL:
                ida_bytes.create_packed_real(ea, length)
            elif op_type == NameOp.TYP_YWORD:
                ida_bytes.create_yword(ea, length)
            elif op_type == NameOp.TYP_ZWORD:
                ida_bytes.create_zword(ea, length)
            elif op_type == NameOp.TYP_INST:
                ida_ua.create_insn(ea)
            elif op_type == NameOp.ARRAY:
                idc.make_array(ea, op_arg[0])
            elif op_type == NameOp.TOGGLE_SIGN:
                ida_bytes.toggle_sign(ea, op_arg[0])
            elif op_type == NameOp.TOGGLE_BNOT:
                ida_bytes.toggle_bnot(ea, op_arg[0])
            elif op_type == NameOp.OP_SEG:
                ida_bytes.op_seg(ea, op_arg[0])
            elif op_type == NameOp.OP_CHR:
                ida_bytes.op_chr(ea, op_arg[0])
            elif op_type == NameOp.OP_STKVAR:
                ida_bytes.op_stkvar(ea, op_arg[0])
            elif op_type == NameOp.OP_BIN:
                ida_bytes.op_bin(ea, op_arg[0])
            elif op_type == NameOp.OP_OCT:
                ida_bytes.op_oct(ea, op_arg[0])
            elif op_type == NameOp.OP_DEC:
                ida_bytes.op_dec(ea, op_arg[0])
            elif op_type == NameOp.OP_HEX:
                ida_bytes.op_hex(ea, op_arg[0])
            elif op_type == NameOp.OP_OFFSET:
                is_rvaoff = op_arg[0]
                if is_rvaoff:
                    op_idx = op_arg[1]
                    ref_flag = op_arg[2]
                    ref_target = op_arg[3]
                    ref_base = op_arg[4]
                    ref_tdelta = op_arg[5]
                    ida_offset.op_offset(ea, op_idx, ref_flag, ref_target,
                                         ref_base, ref_tdelta)
                else:
                    op_idx = op_arg[1]
                    ref_base = op_arg[2]
                    ida_offset.op_plain_offset(ea, op_idx, ref_base)
            elif op_type == NameOp.OP_ENUM:
                # TODO: op_type OP_ENUM
                log.warn(f"TODO: load OP_ENUM: {hex(ea)}")
            elif op_type == NameOp.OP_STROFF:
                # TODO: op_type OP_STROFF
                log.warn(f"TODO: load OP_STROFF: {hex(ea)}")
            elif op_type == NameOp.OP_MAN:
                # TODO: op_type OP_MAN
                log.warn(f"TODO: load OP_MAN: {hex(ea)}")
            elif op_type == NameOp.SET_NAME:
                name = op_arg[0]
                ans = ida_name.set_name(
                    ea, name, ida_name.SN_FORCE | ida_name.SN_NOWARN
                )
                if not ans:
                    log.error('Set name `{}` @ {} failed'.format(
                        name,
                        hex(ea),
                    ))
                else:
                    log.debug("Add name `{}` @ {}".format(name, hex(ea)))
    return True
