# -*- coding: utf8 -*-

"""
Dump or load segment info
"""

import copy

import ida_auto
import ida_bytes
import ida_idp
import ida_segment
import ida_segregs
import iidada.log

log = iidada.log.get_logger("segment")


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


def lock_all_segments():
    seg_cnt = ida_segment.get_segm_qty()
    for i in range(seg_cnt):
        seg = ida_segment.getnseg(i)
        if not ida_segment.is_segm_locked(seg):
            ida_segment.lock_segm(seg, True)


def get_max_selector_id():
    return max([
        ida_segment.getn_selector(i)[1] for i in  # type like: [True, 23, 0]
        range(ida_segment.get_selector_qty())
    ])


def dump_sreg(seg):
    first_sreg_id = ida_idp.ph_get_reg_first_sreg()
    last_sreg_id = ida_idp.ph_get_reg_last_sreg()
    sreg_width = ida_idp.ph_get_segreg_size()

    sreg_data = dict()
    for sreg_id in range(first_sreg_id, last_sreg_id + 1):
        sreg_name = ida_idp.get_reg_name(sreg_id, sreg_width)
        sreg_val = ida_segregs.get_sreg(seg.start_ea, sreg_id)
        sreg_data[sreg_name] = sreg_val
    return sreg_data


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
        self.seg_sreg = None

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
        if val := kwargs.get('seg_sreg'):
            self.seg_sreg = copy.copy(val)

    @property
    def seg_data(self):
        return self._seg_data

    @seg_data.setter
    def seg_data(self, data: bytes):
        self._seg_data = copy.copy(data)


def dump_segments():
    seg_cnt = ida_segment.get_segm_qty()
    if not seg_cnt:
        print("[-] no segment found")
        return None

    lock_all_segments()
    segment_infos = []

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
        seg_sreg = dump_sreg(seg)
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
            seg_sreg=seg_sreg,
        )
        ida_segment_info.seg_data = seg_data
        segment_infos.append(ida_segment_info)

    return segment_infos


# noinspection PyPropertyAccess
def load_segments(segment_infos, root_filename):
    ida_auto.auto_wait()
    max_sel_id = get_max_selector_id()
    next_sel_id = max_sel_id + 1

    for segment_info in segment_infos:
        log.debug('Try to add segment `{}` @ [{}, {}]'.format(
            root_filename + ':' + segment_info.seg_name,
            hex(segment_info.seg_start_ea),
            hex(segment_info.seg_end_ea),
        ))

        # recover selector, and give it a new id
        sel_id = next_sel_id
        next_sel_id += 1
        ida_segment.set_selector(
            sel_id, segment_info.seg_para)

        ida_seg = ida_segment.segment_t()
        ida_seg.start_ea = segment_info.seg_start_ea
        ida_seg.end_ea = segment_info.seg_end_ea
        ida_seg.sel = sel_id
        ida_seg.align = segment_info.seg_align
        ida_seg.perm = segment_info.seg_perm
        ida_seg.comb = segment_info.seg_comb
        ida_seg.bitness = segment_info.seg_bits
        ida_seg.flags = segment_info.seg_flags
        ida_seg.type = segment_info.seg_type
        ans = ida_segment.add_segm_ex(
            ida_seg,
            root_filename + ':' + segment_info.seg_name,
            segment_info.seg_class,
            ida_segment.ADDSEG_NOSREG
        )
        if not ans:
            log.error('Add segment `{}` @ [{}, {}] failed'.format(
                root_filename + ':' + segment_info.seg_name,
                hex(segment_info.seg_start_ea),
                hex(segment_info.seg_end_ea),
            ))
            return False
        # recover sreg
        for sreg_name, sreg_val in segment_info.seg_sreg.items():
            ida_segregs.set_default_sreg_value(
                ida_seg,
                ida_idp.str2reg(sreg_name),
                sreg_val
            )
        # recover segment bytes
        if segment_info.seg_data:
            ida_bytes.put_bytes(
                segment_info.seg_start_ea,
                segment_info.seg_data
            )
    return True
