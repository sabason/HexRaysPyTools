from HexRaysPyTools.log import Log, LogLevel
logger = Log.get_logger()
import idaapi

import HexRaysPyTools.core.cache as cache
import HexRaysPyTools.core.const as const
import HexRaysPyTools.settings as settings
from HexRaysPyTools.callbacks import hx_callback_manager, action_manager
from HexRaysPyTools.core.struct_xrefs import XrefStorage
from HexRaysPyTools.core.temporary_structure import TemporaryStructureModel
from HexRaysPyTools.forms import StructureBuilder
from HexRaysPyTools.core.rename_hooks import rename_hook

fDebug = False
if fDebug:
    import pydevd_pycharm



class MyPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Plugin for automatic classes reconstruction"
    help = "See https://github.com/igogo-x86/HexRaysPyTools/blob/master/readme.md"
    wanted_name = "HexRaysPyTools"
    wanted_hotkey = ""

    @staticmethod
    def init():
        if not idaapi.init_hexrays_plugin():
            logger.error("Failed to initialize Hex-Rays SDK")
            return idaapi.PLUGIN_SKIP

        action_manager.initialize()
        hx_callback_manager.initialize()
        cache.temporary_structure = TemporaryStructureModel()
        const.init()
        if fDebug == True:
            pydevd_pycharm.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
        XrefStorage().open()
        rename_hook.hook()
        return idaapi.PLUGIN_KEEP

    @staticmethod
    def run(*args):
        tform = idaapi.find_widget("Structure Builder")
        if tform:
            idaapi.activate_widget(tform, True)
        else:
            StructureBuilder(cache.temporary_structure).Show()

    @staticmethod
    def term(*args):
        action_manager.finalize()
        hx_callback_manager.finalize()
        XrefStorage().close()
        rename_hook.unhook()
        idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    settings.load_settings()
    Log.set_root_log_level(LogLevel(settings.DEBUG_MESSAGE_LEVEL))
    Log.set_stream_log_level(LogLevel(settings.DEBUG_MESSAGE_LEVEL))
    # logging.basicConfig(format='[%(levelname)s] %(message)s\t(%(module)s:%(funcName)s)')
    # logging.root.setLevel(settings.DEBUG_MESSAGE_LEVEL)
    idaapi.notify_when(idaapi.NW_OPENIDB, cache.initialize_cache)
    return MyPlugin()
