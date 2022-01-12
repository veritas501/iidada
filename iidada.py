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

import ida_auto
import ida_bytes
import ida_entry
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

DEBUG_MODE = False


def debug_print(s):
    if DEBUG_MODE:
        print(s)


def remove_prefix(s, prefix):
    if s.startswith(prefix):
        return s[len(prefix):]
    return s


def get_segm_ori_name(seg):
    name = ida_segment.get_segm_name(seg)
    name_list = name.split(':')
    if len(name_list) == 1:
        return name
    else:
        return ':'.join(name_list[1:])


def get_segments_by_name(name):
    segments = []
    seg_cnt = ida_segment.get_segm_qty()
    for i in range(seg_cnt):
        seg = ida_segment.getnseg(i)
        if get_segm_ori_name(seg) == name:
            ida_segment.lock_segm(seg, True)
            segments.append(seg)
    return segments


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
        print("[-] can't find extern segment")
        return None

    extern_functions = dict()  # func_name: got_ea
    for extern_seg in extern_segments:
        debug_print("[*] extern segment: {}".format(
            hex(extern_seg.start_ea)
        ))
        # get extern functions
        extern_func_ea = idautils.Functions(
            extern_seg.start_ea,
            extern_seg.end_ea + 1
        )
        for ea in extern_func_ea:
            debug_print("[*] extern function: {}".format(
                hex(ea)
            ))
            if ref_ea := get_xref_in_got(ea):
                debug_print("[*] find extern symbol `{}` @ {}".format(
                    get_extern_name(ea), hex(ref_ea)
                ))
                extern_functions[ref_ea] = get_extern_name(ea)

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
        self.seg_type = 0

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
        if val := kwargs.get('seg_type'):
            self.seg_type = val

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
            'seg_type': self.seg_type,
            'seg_data': self._seg_data,
        })

    @staticmethod
    def loads(data: bytes):
        datas = marshal.loads(data)
        ida_segment_info = IDASegInfo(**datas)
        ida_segment_info.seg_data = datas.get('seg_data')
        return ida_segment_info


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
        seg_type = seg.type
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
            seg_type=seg_type,
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


def dump_functions(start=None, end=None):
    # copied from idautils.Functions
    if start is None:
        start = ida_ida.cvar.inf.min_ea
        end = ida_ida.cvar.inf.max_ea

    # find first function head chunk in the range
    chunk = ida_funcs.get_fchunk(start)
    if not chunk:
        chunk = ida_funcs.get_next_fchunk(start)
    while chunk and chunk.start_ea < end and \
            (chunk.flags & ida_funcs.FUNC_TAIL) != 0:
        chunk = ida_funcs.get_next_fchunk(chunk.start_ea)
    func = chunk

    func_list = list()
    while func and func.start_ea < end:
        start_ea = func.start_ea
        end_ea = func.end_ea
        func_list.append((start_ea, end_ea))
        func = ida_funcs.get_next_func(start_ea)
    return func_list


def dump_export_table():
    cnt = ida_entry.get_entry_qty()
    export_table = dict()
    for i in range(cnt):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        export_table[name] = ea
    return export_table


def load_segments(segments, root_filename):
    ida_auto.auto_wait()
    for seg in segments:
        ida_segment_info = IDASegInfo.loads(seg)
        debug_print('[*] try to add segment `{}` @ [{}, {}]'.format(
            root_filename + ':' + ida_segment_info.seg_name,
            hex(ida_segment_info.seg_start_ea),
            hex(ida_segment_info.seg_end_ea),
        ))
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
        ida_seg.comb = ida_segment_info.seg_comb
        ida_seg.bitness = ida_segment_info.seg_bits
        ida_seg.flags = ida_segment_info.seg_flags
        ida_seg.type = ida_segment_info.seg_type
        if ida_segment_info.seg_data:
            ida_bytes.put_bytes(
                ida_segment_info.seg_start_ea,
                ida_segment_info.seg_data
            )
    return True


def load_names(names):
    ida_auto.auto_wait()
    for address, name in names:
        debug_print("[*] add name `{}` @ {}".format(name, hex(address), ))
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
    ida_auto.auto_wait()
    for start_ea, end_ea in functions:
        debug_print("[*] add func: {} - {}".format(hex(start_ea), hex(end_ea)))
        if not ida_funcs.add_func(start_ea):
            print("[-] add function failed: {} - {}".format(
                hex(start_ea), hex(end_ea)
            ))
            continue
        this_func = ida_funcs.get_func(start_ea)
        if this_func.end_ea == end_ea:
            continue
        elif this_func.end_ea > end_ea:
            ida_funcs.set_func_end(start_ea, end_ea)
        else:
            funcs = dump_functions(start_ea, end_ea)[1:]
            for func, _ in funcs:
                ida_funcs.del_func(func)
            ida_funcs.set_func_end(start_ea, end_ea)


def fix_elf_got(export_tbl):
    ida_auto.auto_wait()
    ext_functions = elf_get_external_function()
    for got_ea, name in ext_functions.items():
        if address := export_tbl.get(name):
            debug_print("[*] patch got `{}` @ {} to {}".format(
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


def dump_all(fname):
    root_filename = ida_nalt.get_root_filename()
    segments = dump_segments()
    names = dump_names()
    functions = dump_functions()
    export_table = dump_export_table()
    dump_data = marshal.dumps({
        'segment': segments,
        'name': names,
        'function': functions,
        'root_filename': root_filename,
        'export_table': export_table,
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
    if export_table := dump_data.get('export_table'):
        if is_elf():
            # try to fix got table
            fix_elf_got(export_table)
    return True


def iidada_produce():
    fname = ida_kernwin.ask_file(1, "*.iidada", "Save database file as")
    if fname:
        if not fname.endswith('.iidada'):
            fname += ".iidada"
        if dump_all(fname):
            print("[+] IIDADA produce database success. {}".format(fname))
        else:
            print("[-] IIDADA produce database failed. {}".format(fname))


def iidada_load():
    fname = ida_kernwin.ask_file(0, "*.iidada", "Load database file")
    if fname:
        if load_all(fname):
            print("[+] IIDADA merge database success. {}".format(fname))
        else:
            print("[-] IIDADA merge database failed. {}".format(fname))


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


def test():
    load_all("add.iidada")
    load_all("log.iidada")


if __name__ == '__main__':
    test()
