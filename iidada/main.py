# -*- coding: utf8 -*-

import iidada.export_table
import iidada.function
import iidada.inf
import iidada.log
import iidada.name
import iidada.segment
import iidada.spec
import iidada.structure
import iidada.util

log = iidada.log.get_logger("main")


def dump_all(fname):
    if not iidada.util.check_rebase():
        log.error("Please rebase the program to specific address first."
                  " (Just imagine this binary is loaded into memory)")
        return False
    root_filename = iidada.inf.get_filename()
    segment_infos = iidada.segment.dump_segments()
    struct_infos = iidada.structure.dump_structure()
    name_infos = iidada.name.dump_names()
    function_infos = iidada.function.dump_functions()
    export_table = iidada.export_table.dump_export_table()

    dump_db = iidada.util.build_database({
        'seg': segment_infos,
        'struc': struct_infos,
        'name': name_infos,
        'func': function_infos,
        'root_filename': root_filename,
        'export_table': export_table,
    })
    with open(fname, 'wb') as fp:
        fp.write(dump_db)
    return True


def load_all(dump_file):
    with open(dump_file, 'rb') as fp:
        data = fp.read()
        dump_db = iidada.util.load_database(data)
        if not dump_db:
            log.error("Load IIDADA database failed")
            return False

    root_filename = dump_db.get('root_filename')
    iidada.inf.set_loadidc_flag()
    if segment_infos := dump_db.get('seg'):
        iidada.segment.load_segments(segment_infos, root_filename)
    else:
        log.error("Load segment information from IIDADA database failed")
        return False
    struct_rename_map = dict()
    if struct_infos := dump_db.get('struc'):
        iidada.structure.load_structure(struct_infos, struct_rename_map)
    if name_infos := dump_db.get('name'):
        iidada.name.load_names(name_infos, struct_rename_map)
    if function_infos := dump_db.get('func'):
        iidada.function.load_functions(function_infos)
    if iidada.inf.is_elf():
        iidada.spec.elf.do_spec(dump_db)
    iidada.inf.unset_loadidc_flag()
    return True
