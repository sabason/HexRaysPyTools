import os
import Actions
import Forms
import ConfigParser
import idc
import os.path
import ida_kernwin
import ida_diskio

hex_pytools_config = None

fDebug = False
if fDebug:
    import pydevd

import logging

CONFIG_FILE_PATH = os.path.join(idc.GetIdaDirectory(), 'cfg', 'HexRaysPyTools.cfg')

DEBUG_MESSAGE_LEVEL = logging.INFO
# Whether propagate names (Propagate name feature) through all names or only defaults like v11, a3, this, field_4
PROPAGATE_THROUGH_ALL_NAMES = False
# Store Xref information in database. I don't know how much size it consumes yet
STORE_XREFS = True
# There're some types that can be pointers to structures like int, PVOID etc and by default plugin scans only them
# Full list can be found in `Const.LEGAL_TYPES`.
# But if set this option to True than variable of every type could be possible to scan
SCAN_ANY_TYPE = False


def add_default_settings(config):
    updated = False
    if not config.has_option("DEFAULT", "DEBUG_MESSAGE_LEVEL"):
        print DEBUG_MESSAGE_LEVEL
        config.set(None, 'DEBUG_MESSAGE_LEVEL', str(DEBUG_MESSAGE_LEVEL))
        updated = True
    if not config.has_option("DEFAULT", "PROPAGATE_THROUGH_ALL_NAMES"):
        config.set(None, 'PROPAGATE_THROUGH_ALL_NAMES', str(PROPAGATE_THROUGH_ALL_NAMES))
        updated = True
    if not config.has_option("DEFAULT", "STORE_XREFS"):
        config.set(None, 'STORE_XREFS', str(STORE_XREFS))
        updated = True
    if not config.has_option("DEFAULT", "SCAN_ANY_TYPE"):
        config.set(None, 'SCAN_ANY_TYPE', str(SCAN_ANY_TYPE))
        updated = True

    if updated:
        try:
            with open(hex_pytools_config.file_path, "w") as f:
                config.write(f)
        except IOError:
            print "[ERROR] Failed to write or update config file at {}. Default settings will be used instead.\n" \
                  "Consider running IDA Pro under administrator once".format(CONFIG_FILE_PATH)


def load_settings():
    global DEBUG_MESSAGE_LEVEL, PROPAGATE_THROUGH_ALL_NAMES, STORE_XREFS, SCAN_ANY_TYPE

    config = ConfigParser.ConfigParser()
    config.optionxform = str
    if os.path.isfile(hex_pytools_config.file_path):
        config.read(hex_pytools_config.file_path)

    add_default_settings(config)

    DEBUG_MESSAGE_LEVEL = config.getint("DEFAULT", 'DEBUG_MESSAGE_LEVEL')
    PROPAGATE_THROUGH_ALL_NAMES = config.getboolean("DEFAULT", 'PROPAGATE_THROUGH_ALL_NAMES')
    STORE_XREFS = config.getboolean("DEFAULT", 'STORE_XREFS')
    SCAN_ANY_TYPE = config.getboolean("DEFAULT", 'SCAN_ANY_TYPE')



class Config(object):

    def __init__(self):
        global hex_pytools_config
        self.section = "HexRaysPyTools features"
        self.file_path = os.path.join(ida_diskio.idadir(""),"cfg", "HexRaysPyTools.cfg")
        self.reader = ConfigParser.SafeConfigParser()
        self.reader.optionxform = str
        self.actions, self.action_names = self.GetDefActions()
        self.actions_refs = self.GetActionsRefs()
        hex_pytools_config = self
        try:
            f = open(self.file_path, "ab")
            f.close()
        except:
            print("Cannot open config file.")
            self.file_path = os.path.join(os.environ["APPDATA"],"IDA Pro","cfg", "HexRaysPyTools.cfg")
            if not os.path.exists(os.path.join(os.environ["APPDATA"], "IDA Pro", "cfg")):
                os.makedirs(os.path.join(os.environ["APPDATA"], "IDA Pro", "cfg"))
            f = open(self.file_path, "ab")
            f.close()
        try:
            f = open(self.file_path, "rb")
            self.reader.readfp(f)
            f.close()
            fRewrite = False
            for ac in self.actions:
                if self.reader.has_option(self.section,ac):
                    self.actions[ac] = self.reader.getboolean(self.section,ac)
                else:
                    fRewrite = True
            if fRewrite:
                self.write_config()

        except ConfigParser.NoSectionError:
            self.actions, self.action_names = self.GetDefActions()
            del self.reader
            self.reader = ConfigParser.SafeConfigParser()
            self.reader.optionxform = str
            self.reader.add_section(self.section)
            for ac in self.actions:
                self.reader.set(self.section, ac, "true" if self.actions[ac] else "false")
            f = open(self.file_path, "wb")
            self.reader.write(f)
            f.close()

    def __getitem__(self, item):
        if item in self.action_names:
            return self.actions[self.action_names[item]]
        if item in self.actions:
            return self.actions[item]
        return False

    def write_config(self):
        for ac in self.actions:
            self.reader.set(self.section, ac, "true" if self.actions[ac] else "false")
        f = open(self.file_path, "wb")
        self.reader.write(f)
        f.close()

    def update(self, vals):
        for key in vals:
            if key in self.action_names:
                self.actions[self.action_names[key]] = vals[key]
            if key in self.actions:
                self.actions[key] = vals[key]
        self.write_config()

    def modify(self):
        if fDebug:
            pydevd.settrace('localhost', port=31337, stdoutToServer=True, stderrToServer=True,suspend=True)
        f = Forms.ConfigFeatures(self)
        f.Do()
        f.Free()

    def GetActionsRefs(self):
        ret = {}
        md = Actions.__dict__
        for c in md:
            if isinstance(md[c], type) and md[c].__module__ == Actions.__name__ and (md[c].__base__ == ida_kernwin.action_handler_t or md[c].__base__.__base__ == ida_kernwin.action_handler_t):
                ret[c] = md[c]
        return ret

    @staticmethod
    def GetDefActions():
        md = Actions.__dict__
        ret = {}
        ret2 = {}
        for c in md:
            if isinstance(md[c], type) and md[c].__module__ == Actions.__name__ and (md[c].__base__ == ida_kernwin.action_handler_t or md[c].__base__.__base__ == ida_kernwin.action_handler_t):
                ret[c] = True
                ret2[md[c].name] = c
        return (ret,ret2)