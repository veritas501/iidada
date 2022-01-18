# -*- coding: utf8 -*-

import ida_bytes
import ida_nalt
import ida_struct
import ida_typeinf
import idc
import iidada.log
from ida_idaapi import BADADDR
from iidada.util import LoopBreaker

log = iidada.log.get_logger("structure")


class IDAMemberInfo:
    def __init__(
            self,
            m_name,
            m_soff,
            m_size,
            m_flag,
            m_typeid,
            m_ref_type,
            type_string,
    ):
        self.m_name = m_name
        self.m_soff = m_soff
        self.m_size = m_size
        self.m_flag = m_flag
        self.m_typeid = m_typeid
        self.m_ref_type = m_ref_type
        self.type_string = type_string


class IDAStructInfo:
    def __init__(
            self,
            struc_name,
            struc_align,
            members,
    ):
        self.struc_name = struc_name
        self.struc_align = struc_align
        self.members = members


# noinspection PyPropertyAccess
def dump_members(struc):
    m_cnt = struc.memqty
    log.debug(f"get m_cnt: {m_cnt}")
    members = list()
    for i in range(m_cnt):
        m = struc.get_member(i)
        m_name = ida_struct.get_member_name(m.id)
        log.debug(f"- member: {m_name}")
        m_flag = m.flag
        log.debug(f"- m_flag: {hex(m_flag)}")
        m_start_offset = m.soff
        m_end_offset = m.eoff
        m_size = m_end_offset - m_start_offset
        typeid = None
        ref_type = ida_nalt.REF_OFF32
        op_info = ida_nalt.opinfo_t()
        type_string = ida_typeinf.idc_get_type(m.id)
        if ida_struct.retrieve_member_info(op_info, m):  # contain op_info
            if ida_bytes.is_struct(m_flag):
                rel_sid = op_info.ri.target
                rel_sname = ida_struct.get_struc_name(rel_sid)
                typeid = rel_sname
            elif ida_bytes.is_off0(m_flag):
                typeid = op_info.ri.base
            elif ida_bytes.is_strlit(m_flag):
                log.warn("TODO is_strlit")
                # TODO
                typeid = None
            elif ida_bytes.is_stroff(m_flag, ida_bytes.OPND_ALL):
                log.warn("TODO is_stroff")
                # TODO
                typeid = None
            elif ida_bytes.is_enum(m_flag, ida_bytes.OPND_ALL):
                log.warn("TODO is_enum")
                # TODO
                typeid = None
            elif ida_bytes.is_custom(m_flag):
                log.warn("TODO is_custom")
                # TODO
                typeid = None
            if op_info.ri.type():
                ref_type = op_info.ri.type()

        m_info = IDAMemberInfo(
            m_name,
            m_start_offset,
            m_size,
            m_flag,
            typeid,
            ref_type,
            type_string
        )
        members.append(m_info)
    return members


def import_local_types():
    """
    try to import all structs from local types to idb

    :return:
    """
    ti = ida_typeinf.get_idati()
    ordinal_cnt = ida_typeinf.get_ordinal_qty(ti)
    for i in range(ordinal_cnt):
        if name := ida_typeinf.get_numbered_type_name(ti, i):
            # ignore import error
            ida_typeinf.import_type(ti, i, name, 0)


def dump_structure():
    import_local_types()

    struct_cnt = ida_struct.get_struc_qty()
    log.debug(f"get struct cnt: {struct_cnt}")
    struct_infos = list()
    for i in range(struct_cnt):
        struct_id = ida_struct.get_struc_by_idx(i)
        if struct_id == BADADDR:
            log.error(f"get_struc_by_idx failed: {i}")
            continue
        log.debug(f"get struct_id: {hex(struct_id)}")
        struct_name = ida_struct.get_struc_name(struct_id)
        log.debug(f"get struct_name: {struct_name}")
        struc = ida_struct.get_struc(struct_id)
        struct_align = struc.get_alignment()
        members = dump_members(struc)
        struct_info = IDAStructInfo(struct_name, struct_align, members)
        struct_infos.append(struct_info)
    return struct_infos


# noinspection PyPropertyAccess
def load_structure(struct_infos, struct_rename_map: dict):
    ida_typeinf.begin_type_updating(ida_typeinf.UTP_STRUCT)

    error_struct_names = list()

    # create empty struct
    for struct_info in struct_infos:
        ans = ida_struct.add_struc(
            BADADDR,
            struct_info.struc_name,
            0  # TODO: is_union, assume always False for now
        )
        if ans != BADADDR:
            struct_rename_map[struct_info.struc_name] = struct_info.struc_name
            log.debug("Structure `{}` added".format(struct_info.struc_name))
        elif ida_struct.get_struc_id(struct_info.struc_name) != BADADDR:
            # struct name conflict
            name_suffix = 0
            new_name = "{}_{}".format(struct_info.struc_name, name_suffix)
            while ida_struct.get_struc_id(new_name) != BADADDR:
                name_suffix += 1
                new_name = "{}_{}".format(struct_info.struc_name, name_suffix)
            ans = ida_struct.add_struc(
                BADADDR,
                new_name,
                0  # TODO: is_union, assume always False for now
            )
            if ans == BADADDR:
                log.error("Add struct `{}` failed [WTF]".format(
                    struct_info.struc_name))
                error_struct_names.append(struct_info.struc_name)
                continue
            else:
                log.debug("Structure `{}` -> `{}` added".format(
                    struct_info.struc_name, new_name))
                struct_rename_map[struct_info.struc_name] = new_name
        else:
            log.error("Add struct `{}` failed".format(struct_info.struc_name))
            error_struct_names.append(struct_info.struc_name)
            continue
            # TODO error handle

    # fill struct with members
    for struct_info in struct_infos:
        # skip failed struct
        if struct_info.struc_name in error_struct_names:
            continue
        struc_name = struct_rename_map.get(struct_info.struc_name)
        sid = ida_struct.get_struc_id(struc_name)
        if not sid:
            log.error("Struct `{}` not found".format(struc_name))
            continue
        struc = ida_struct.get_struc(sid)
        try:
            for m in struct_info.members:
                # first, give member a dummy type, because there may be
                # dependencies between structures and structures
                ans = ida_struct.add_struc_member(
                    struc,
                    m.m_name,
                    m.m_soff,
                    ida_bytes.FF_DATA | ida_bytes.FF_BYTE,
                    None,
                    m.m_size,
                )
                if ans:
                    log.error("Add member `{}` to struct `{}` failed".format(
                        m.m_name, struc_name))
                    raise LoopBreaker()
        except LoopBreaker:
            continue
        struc = ida_struct.get_struc(sid)
        ida_struct.set_struc_align(struc, struct_info.struc_align)

    # refresh struct
    ida_typeinf.end_type_updating(ida_typeinf.UTP_STRUCT)
    ida_typeinf.begin_type_updating(ida_typeinf.UTP_STRUCT)

    # set member types
    for struct_info in struct_infos:
        # skip failed struct
        if struct_info.struc_name in error_struct_names:
            continue
        struc_name = struct_rename_map.get(struct_info.struc_name)
        sid = ida_struct.get_struc_id(struc_name)
        if not sid:
            log.error("Struct `{}` not found".format(struc_name))
            continue
        struc = ida_struct.get_struc(sid)
        for m in struct_info.members:
            mid = ida_struct.get_member_id(struc, m.m_soff)
            op_info = ida_nalt.opinfo_t()
            if ida_bytes.is_struct(m.m_flag):
                op_info.ri.target = ida_struct.get_struc_id(m.m_typeid)
            elif ida_bytes.is_off0(m.m_flag):
                op_info.ri.base = m.m_typeid
            elif ida_bytes.is_strlit(m.m_flag):
                log.warn("TODO is_strlit")
                # TODO
            elif ida_bytes.is_stroff(m.m_flag, ida_bytes.OPND_ALL):
                log.warn("TODO is_stroff")
                # TODO
            elif ida_bytes.is_enum(m.m_flag, ida_bytes.OPND_ALL):
                log.warn("TODO is_enum")
                # TODO
            elif ida_bytes.is_custom(m.m_flag):
                log.warn("TODO is_custom")
                # TODO
            ida_struct.set_member_type(
                struc,
                m.m_soff,
                m.m_flag,
                op_info,
                m.m_size
            )
            idc.SetType(mid, m.type_string)
    ida_typeinf.end_type_updating(ida_typeinf.UTP_STRUCT)
    return True
