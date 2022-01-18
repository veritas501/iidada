# -*- coding: utf8 -*-
# Author: veritas501

"""
IIDADA

Merge multi binaries into one IDA database
"""

import os

import ida_kernwin
import idaapi
from iidada.main import dump_all, load_all
from iidada.inf import get_filename
from iidada.util import DB_SUFFIX
from iidada.version import PROG_NAME, VERSION
import iidada.log

log = iidada.log.get_logger("plugin", iidada.log.INFO)


def iidada_produce():
    default_name = "{}{}".format(get_filename(), DB_SUFFIX)
    fname = ida_kernwin.ask_file(1, default_name, "Save database file as")
    if fname:
        if not fname.endswith(DB_SUFFIX):
            fname += DB_SUFFIX
        if dump_all(fname):
            log.info("Produce database success. {}".format(fname))
        else:
            log.error("Produce database failed.")


def iidada_load():
    default_name = "*{}".format(DB_SUFFIX)
    fname = ida_kernwin.ask_file(0, default_name, "Load database file")
    if fname:
        if load_all(fname):
            log.info("Merge database success. {}".format(fname))
        else:
            log.error("Merge database failed.")


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
    wanted_name = PROG_NAME
    wanted_hotkey = ""
    produce_action_name = 'produce_iidada:action'
    load_action_name = 'load_iidada:action'
    menu_name = "IIDADA database file..."
    produce_tooltip = "Produce iidada database file."
    load_tooltip = "Load iidada signature file."
    menu_tab = 'File/'
    menu_context = []

    # noinspection PyPropertyAccess
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

        if idaapi.init_hexrays_plugin():
            addon = idaapi.addon_info_t()
            addon.id = "com.veritas501.iidada"
            addon.name = PROG_NAME
            addon.producer = "veritas501"
            addon.url = "https://github.com/veritas501/iidada"
            addon.version = VERSION
            idaapi.register_addon(addon)

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
