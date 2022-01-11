# -*- coding: utf8 -*-
# Author: veritas501
# Version: v0.1

"""
IIDADA

Merge multi binaries into one IDA database
"""

import copy
import marshal
import os

import ida_bytes
import ida_funcs
import ida_ida
import ida_kernwin
import ida_nalt
import ida_name
import ida_segment
import ida_xref
import idaapi
import idautils
import idc
from ida_idaapi import BADADDR


def is_elf():
    return ida_ida.inf_get_filetype() == ida_ida.f_ELF


def elf_get_external_function():
    def get_xref_in_got(target_ea, first_ref_ea=0):
        if not first_ref_ea:
            tmp_ref_ea = ida_xref.get_first_dref_to(ea)
        else:
            tmp_ref_ea = ida_xref.get_next_dref_to(ea, first_ref_ea)
        if tmp_ref_ea == BADADDR:
            return None
        if got_seg.start_ea <= tmp_ref_ea < got_seg.end_ea:
            return tmp_ref_ea
        return get_xref_in_got(target_ea, tmp_ref_ea)

    # get extern segment
    extern_seg = ida_segment.get_segm_by_name('extern')
    if not extern_seg:
        print("[-] can't find extern segment")
        return None

    # get GOT segment
    got_seg = ida_segment.get_segm_by_name('.got')
    if not got_seg:
        print("[-] can't find .GOT segment")
        return None

    # get extern functions
    extern_func_ea = idautils.Functions(
        extern_seg.start_ea,
        extern_seg.end_ea + 1
    )
    extern_functions = dict()  # func_name: got_ea
    for ea in extern_func_ea:
        if ref_ea := get_xref_in_got(ea):
            extern_functions[idc.get_func_name(ea)] = ref_ea

    return extern_functions


def lock_all_segments():
    seg_cnt = ida_segment.get_segm_qty()
    for i in range(seg_cnt):
        seg = ida_segment.getnseg(i)
        if not ida_segment.is_segm_locked(seg):
            ida_segment.lock_segm(seg, True)


class IDASegInfo:
    def __init__(self, **kwargs) -> None:
        self.seg_name = None
        self.seg_class = None
        self.seg_start_ea = 0
        self.seg_end_ea = 0
        self.seg_align = 0
        self.seg_perm = 0
        self.seg_bits = 0
        self.seg_comb = 0
        self.seg_flags = 0
        self.seg_para = 0

        self._seg_data = None

        if val := kwargs.get('seg_name'):
            self.seg_name = val
        if val := kwargs.get('seg_class'):
            self.seg_class = val
        if val := kwargs.get('seg_start_ea'):
            self.seg_start_ea = val
        if val := kwargs.get('seg_end_ea'):
            self.seg_end_ea = val
        if val := kwargs.get('seg_align'):
            self.seg_align = val
        if val := kwargs.get('seg_perm'):
            self.seg_perm = val
        if val := kwargs.get('seg_bits'):
            self.seg_bits = val
        if val := kwargs.get('seg_comb'):
            self.seg_comb = val
        if val := kwargs.get('seg_flags'):
            self.seg_flags = val
        if val := kwargs.get('seg_para'):
            self.seg_para = val

    @property
    def seg_data(self):
        return self._seg_data

    @seg_data.setter
    def seg_data(self, data: bytes):
        self._seg_data = copy.copy(data)

    def dumps(self):
        return marshal.dumps({
            'seg_name': self.seg_name,
            'seg_class': self.seg_class,
            'seg_start_ea': self.seg_start_ea,
            'seg_end_ea': self.seg_end_ea,
            'seg_align': self.seg_align,
            'seg_perm': self.seg_perm,
            'seg_bits': self.seg_bits,
            'seg_comb': self.seg_comb,
            'seg_flags': self.seg_flags,
            'seg_para': self.seg_para,
            'seg_data': self._seg_data,
        })

    @staticmethod
    def loads(data: bytes):
        datas = marshal.loads(data)
        ida_segment_info = IDASegInfo(**datas)
        ida_segment_info.seg_data = datas.get('seg_data')
        return ida_segment_info

    # noinspection PyPropertyAccess
    def build_ida_segment(self):
        ida_seg = ida_segment.segment_t()
        ida_segment.set_segm_name(ida_seg, self.seg_name)
        ida_segment.set_segm_class(ida_seg, self.seg_class)
        ida_segment.set_segm_start(ida_seg, self.seg_start_ea)
        ida_segment.set_segm_end(ida_seg, self.seg_end_ea)
        ida_seg.align = self.seg_align
        ida_seg.perm = self.seg_perm
        ida_seg.comb = self.seg_comb
        ida_seg.flags = self.seg_flags
        return ida_seg


def dump_segments():
    seg_cnt = ida_segment.get_segm_qty()
    if not seg_cnt:
        print("[-] no segment found")
        return None

    lock_all_segments()
    seg_dumps = []

    for i in range(seg_cnt):
        seg = ida_segment.getnseg(i)
        seg_name = ida_segment.get_segm_name(seg)
        seg_class = ida_segment.get_segm_class(seg)
        seg_start_ea = seg.start_ea
        seg_end_ea = seg.end_ea
        seg_align = seg.align
        seg_perm = seg.perm
        seg_bits = seg.bitness
        seg_comb = seg.comb
        seg_flags = seg.flags
        seg_para = ida_segment.get_segm_para(seg)
        seg_size = seg_end_ea - seg_start_ea
        if seg_size > 0:
            seg_first_bit_loaded = ida_bytes.is_loaded(seg_start_ea)
        else:
            seg_first_bit_loaded = False
        if seg_first_bit_loaded:
            seg_data = ida_bytes.get_bytes(seg_start_ea, seg_size)
        else:
            seg_data = None

        ida_segment_info = IDASegInfo(
            seg_name=seg_name,
            seg_class=seg_class,
            seg_start_ea=seg_start_ea,
            seg_end_ea=seg_end_ea,
            seg_align=seg_align,
            seg_perm=seg_perm,
            seg_bits=seg_bits,
            seg_comb=seg_comb,
            seg_flags=seg_flags,
            seg_para=seg_para,
        )
        ida_segment_info.seg_data = seg_data
        dump_seg_info = ida_segment_info.dumps()
        seg_dumps.append(dump_seg_info)

    return seg_dumps


def dump_names():
    name_cnt = ida_name.get_nlist_size()
    names = []
    for i in range(name_cnt):
        address = ida_name.get_nlist_ea(i)
        name = ida_name.get_nlist_name(i)
        names.append((address, name))
    return names


def dump_functions():
    return list(idautils.Functions())


def load_segments(segments, root_filename):
    for seg in segments:
        ida_segment_info = IDASegInfo.loads(seg)
        ans = ida_segment.add_segm(
            0,
            ida_segment_info.seg_start_ea,
            ida_segment_info.seg_end_ea,
            root_filename + ':' + ida_segment_info.seg_name,
            ida_segment_info.seg_class,
        )
        if not ans:
            print('[-] add segment `{}` @ [{}, {}] failed'.format(
                root_filename + ':' + ida_segment_info.seg_name,
                hex(ida_segment_info.seg_start_ea),
                hex(ida_segment_info.seg_end_ea),
            ))
            return False
        ida_seg = ida_segment.getseg(ida_segment_info.seg_start_ea)
        ida_seg.align = ida_segment_info.seg_align
        ida_seg.perm = ida_segment_info.seg_perm
        ida_seg.bitness = ida_segment_info.seg_bits
        ida_seg.flags = ida_segment_info.seg_flags
        if ida_segment_info.seg_data:
            ida_bytes.put_bytes(
                ida_segment_info.seg_start_ea,
                ida_segment_info.seg_data
            )
    return True


def load_names(names):
    for address, name in names:
        ans = ida_name.set_name(
            address, name,
            ida_name.SN_FORCE | ida_name.SN_NOWARN
        )
        if not ans:
            print('[-] set name `{}` @ {} failed'.format(
                name,
                hex(address),
            ))


def load_functions(functions):
    for func_ea in functions:
        ida_funcs.add_func(func_ea)


def fix_elf_got(names):
    names_dict = {name: address for address, name in names}
    ext_functions = elf_get_external_function()
    for name, got_ea in ext_functions.items():
        if address := names_dict.get(name):
            ida_bytes.patch_qword(got_ea, address)
            # some magic, so plt disassemble correctly
            ida_bytes.op_hex(got_ea, -1)
            ida_bytes.set_cmt(
                got_ea,
                "Patched by iidada, DON'T change it to `offset` type",
                True
            )


def dump_all(fname):
    root_filename = ida_nalt.get_root_filename()
    segments = dump_segments()
    names = dump_names()
    functions = dump_functions()
    dump_data = marshal.dumps({
        'segment': segments,
        'name': names,
        'function': functions,
        'root_filename': root_filename,
    })
    with open(fname, 'wb') as fp:
        fp.write(dump_data)
    return True


def load_all(dump_file):
    with open(dump_file, 'rb') as fp:
        dump_data = marshal.loads(fp.read())

    root_filename = dump_data.get('root_filename')
    if segments := dump_data.get('segment'):
        load_segments(segments, root_filename)
    if names := dump_data.get('name'):
        load_names(names)
    if functions := dump_data.get('function'):
        load_functions(functions)
    if is_elf():
        # try to fix got table
        fix_elf_got(names)
    return True


def iidada_produce():
    fname = ida_kernwin.ask_file(1, "*.iidada", "Save database file as")
    if fname:
        if not fname.endswith('.iidada'):
            fname += ".iidada"
        if dump_all(fname):
            print("[+] IIDADA produce database success")
        else:
            print("[-] IIDADA produce database failed")


def iidada_load():
    fname = ida_kernwin.ask_file(0, "*.iidada", "Load database file")
    if fname:
        if load_all(fname):
            print("[+] IIDADA merge database success")
        else:
            print("[-] IIDADA merge database failed")


class ProduceIIDADAAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        iidada_produce()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class LoadIIDADAAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        iidada_load()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class IIDADAPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Merge multi binaries into one IDA database"
    help = ""
    wanted_name = "IIDADA"
    wanted_hotkey = ""
    produce_action_name = 'produce_iidada:action'
    load_action_name = 'load_iidada:action'
    menu_name = "IIDADA database file..."
    produce_tooltip = "Produce iidada database file."
    load_tooltip = "Load iidada signature file."
    menu_tab = 'File/'
    menu_context = []

    def init(self):
        produce_desc = idaapi.action_desc_t(
            self.produce_action_name,
            self.menu_name,
            ProduceIIDADAAction(),
            self.wanted_hotkey,
            self.produce_tooltip,
            199
        )

        load_desc = idaapi.action_desc_t(
            self.load_action_name,
            self.menu_name,
            LoadIIDADAAction(),
            self.wanted_hotkey,
            self.load_tooltip,
            199
        )

        idaapi.register_action(produce_desc)
        idaapi.register_action(load_desc)

        idaapi.attach_action_to_menu(
            os.path.join(self.menu_tab, 'Produce file/'),
            self.produce_action_name,
            idaapi.SETMENU_APP
        )
        idaapi.attach_action_to_menu(
            os.path.join(self.menu_tab, 'Load file/'),
            self.load_action_name,
            idaapi.SETMENU_APP
        )

        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.detach_action_from_menu(self.menu_tab, self.produce_action_name)
        idaapi.detach_action_from_menu(self.menu_tab, self.load_action_name)
        return None

    # noinspection PyUnusedLocal
    def run(self, arg):
        return None


# noinspection PyPep8Naming
def PLUGIN_ENTRY():
    return IIDADAPlugin()
