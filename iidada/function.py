# -*- coding: utf8 -*-

from enum import Enum, auto

import ida_frame
import ida_funcs
import ida_struct
import ida_typeinf
import ida_ua
import idc
import iidada.log

log = iidada.log.get_logger("function")


class FuncOP(Enum):
    SET_FLAGS = auto()
    SET_TYPE = auto()
    SET_CMT = auto()
    SET_FRAME_SIZE = auto()
    SET_LOCAL_VAR = auto()


class IDAFuncInfo:
    def __init__(self, start_ea, end_ea):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.op = list()


def dump_functions():
    func_cnt = ida_funcs.get_func_qty()
    function_infos = list()
    for i in range(func_cnt):
        func = ida_funcs.getn_func(i)
        start_ea = func.start_ea
        end_ea = func.end_ea
        inf = IDAFuncInfo(start_ea, end_ea)
        # function flags
        func_flags = func.flags
        inf.op.append((FuncOP.SET_FLAGS, func_flags))
        # function type
        func_type = ida_typeinf.print_type(start_ea, ida_typeinf.PRTYPE_SEMI)
        if func_type is not None:
            inf.op.append((FuncOP.SET_TYPE, func_type))
        # function comment
        for repeatable in [0, 1]:
            cmt = ida_funcs.get_func_cmt(func, repeatable)
            if cmt is not None:
                inf.op.append((FuncOP.SET_CMT, cmt, repeatable))
        # function frame size
        fr_size = func.frsize
        fr_regs = func.frregs
        arg_size = func.argsize
        inf.op.append((FuncOP.SET_FRAME_SIZE, fr_size, fr_regs, arg_size))
        # local variables
        if frame := ida_frame.get_frame(func):
            for member_idx in range(frame.memqty):
                member = frame.get_member(member_idx)
                member_name = ida_struct.get_member_name(member.id)
                if not member_name.startswith(' ') and \
                        not member_name.startswith('arg_') and \
                        not member_name.startswith('var_') and \
                        not member_name.startswith('anonymous'):
                    member_off = member.soff
                    is_neg = member_off - fr_size < 0
                    sign_str = '-' if is_neg else '+'
                    abs_member_off = abs(member_off - fr_size)
                    pos_str = "[bp{}{}]".format(sign_str, hex(abs_member_off))
                    inf.op.append((FuncOP.SET_LOCAL_VAR, pos_str, member_name))
        function_infos.append(inf)
    return function_infos


def load_functions(function_infos):
    for inf in function_infos:
        start_ea = inf.start_ea
        end_ea = inf.end_ea
        ea = start_ea
        if ida_funcs.get_func(ea):
            ida_funcs.del_func(ea)
        ida_ua.create_insn(ea)
        if not ida_funcs.add_func(start_ea, end_ea):
            log.error("Add function failed: {} - {}".format(
                hex(start_ea), hex(end_ea)
            ))
            continue
        else:
            log.debug("Add func: {} - {}".format(hex(start_ea), hex(end_ea)))
        for op in inf.op:
            op_type = op[0]
            op_arg = op[1:]
            if op_type == FuncOP.SET_FLAGS:
                idc.set_func_flags(ea, op_arg[0])
            elif op_type == FuncOP.SET_TYPE:
                # FIXME: if type contains struct, and struct has been renamed
                #  because name conflict, this should be a bug
                idc.SetType(ea, op_arg[0])
            elif op_type == FuncOP.SET_CMT:
                idc.set_func_cmt(ea, op_arg[0], op_arg[1])
                pass
            elif op_type == FuncOP.SET_FRAME_SIZE:
                idc.set_frame_size(ea, op_arg[0], op_arg[1], op_arg[2])
                pass
            elif op_type == FuncOP.SET_LOCAL_VAR:
                idc.define_local_var(start_ea, end_ea, op_arg[0], op_arg[1])
