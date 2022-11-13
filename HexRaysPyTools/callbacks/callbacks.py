from collections import defaultdict
import idaapi
import ida_hexrays

fDebug = False
if fDebug:
    import pydevd_pycharm

class HexRaysCallbackManager(object):
    def __init__(self):
        self.__hexrays_event_handlers = defaultdict(list)

    def initialize(self):
        idaapi.install_hexrays_callback(self.__handle)

    def finalize(self):
        idaapi.remove_hexrays_callback(self.__handle)

    def register(self, event, handler):
        self.__hexrays_event_handlers[event].append(handler)

    def __handle(self, event, *args):
        if fDebug == True:
            pydevd_pycharm.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
        rets = []
        for handler in self.__hexrays_event_handlers[event]:
            rets.append(handler.handle(event, *args))
        if len(rets) > 0 and 0 not in rets and None not in rets:
            return 1
        # IDA expects zero
        return 0


hx_callback_manager = HexRaysCallbackManager()


class HexRaysEventHandler(object):
    def __init__(self):
        super(HexRaysEventHandler, self).__init__()

    def handle(self, event, *args):
        raise NotImplementedError("This is an abstract class")
