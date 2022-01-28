import os
import logging

import ida_diskio
import idc
import configparser

hex_pytools_config = None

def get_config():
    global hex_pytools_config
    if hex_pytools_config is None:
        hex_pytools_config = Config()
    return hex_pytools_config



from HexRaysPyTools import forms

CONFIG_FILE_PATH = os.path.join(idc.idadir(), 'cfg', 'HexRaysPyTools.cfg')
try:
    f = open(CONFIG_FILE_PATH, "ab")
    f.close()
except:
    print("Cannot open config file.")
    CONFIG_FILE_PATH = os.path.join(os.environ["APPDATA"], "IDA Pro", "cfg", "HexRaysPyTools.cfg")
    if not os.path.exists(os.path.join(os.environ["APPDATA"], "IDA Pro", "cfg")):
        os.makedirs(os.path.join(os.environ["APPDATA"], "IDA Pro", "cfg"))
    f = open(CONFIG_FILE_PATH, "ab")
    f.close()

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
            with open(CONFIG_FILE_PATH, "w") as f:
                config.write(f)
        except IOError:
            print("[ERROR] Failed to write or update config file at {}. Default settings will be used instead.\n" \
                  "Consider running IDA Pro under administrator once".format(CONFIG_FILE_PATH))


def load_settings():
    global DEBUG_MESSAGE_LEVEL, PROPAGATE_THROUGH_ALL_NAMES, STORE_XREFS, SCAN_ANY_TYPE, hex_pytools_config

    config = configparser.ConfigParser()
    if os.path.isfile(CONFIG_FILE_PATH):
        config.read(CONFIG_FILE_PATH)

    add_default_settings(config)

    DEBUG_MESSAGE_LEVEL = config.getint("DEFAULT", 'DEBUG_MESSAGE_LEVEL')
    PROPAGATE_THROUGH_ALL_NAMES = config.getboolean("DEFAULT", 'PROPAGATE_THROUGH_ALL_NAMES')
    STORE_XREFS = config.getboolean("DEFAULT", 'STORE_XREFS')
    SCAN_ANY_TYPE = config.getboolean("DEFAULT", 'SCAN_ANY_TYPE')


class Config(object):

    FeaturesListDef = { "Create struct":{"SimpleCreateStruct":True},
                        "Main plugins UI forms":{"ShowGraph":True, "ShowStructureBuilder":True},
                        "Function signature modifiers":{"ConvertToUsercall":True, "AddRemoveReturn":True,"RemoveArgument":True},
                        "Guess allocation":{"GuessAllocation":True},
                        "Member double click":{"MemberDoubleClick":True},
                        "Negative offsets":{"SelectContainingStructure":True},
                        "New field creation":{"CreateNewField":True},
                        "Recasts":{"RecastItemLeft":True,"RecastItemRight":True,"RecastStructMember":True},
                        "Renames":{"RenameOther":True,"RenameInside":True,"RenameOutside":True,"RenameUsingAssert":True,"PropagateName":True,"TakeTypeAsName":True},
                        "Scanners":{"ShallowScanVariable":True,"DeepScanVariable":True,"RecognizeShape":True,"DeepScanReturn":True,"DeepScanFunctions":True},
                        "Struct xref collector":{"StructXrefCollector":True},
                        "Struct xref representation":{"FindFieldXrefs":True},
                        "Structs by size":{"GetStructureBySize":True},
                        "Swap if":{"SilentIfSwapper":True, "SwapThenElse":True},
                        "Virtual table creation":{"CreateVtable":True,"DecompileCreateVtable":True}
                       }

    def __init__(self):
        # global hex_pytools_config
        self.section = "HexRaysPyTools features"
        self.file_path = os.path.join(ida_diskio.idadir(""),"cfg", "HexRaysPyTools.cfg")
        self.reader = configparser.ConfigParser()
        self.reader.optionxform = str
        # self.config_dict = {}
        # hex_pytools_config = self
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

        f = open(self.file_path, "r")
        self.reader.read_file(f)
        f.close()
        fRewrite = False
        for section in Config.FeaturesListDef:
            if not self.reader.has_section(section):
                self.reader.add_section(section)
                fRewrite = True
                for opt in Config.FeaturesListDef[section]:
                    self.reader.set(section,opt,str(Config.FeaturesListDef[section][opt]))
            else:
                for opt in Config.FeaturesListDef[section]:
                    if not self.reader.has_option(section,opt):
                        self.reader.set(section,opt,str(Config.FeaturesListDef[section][opt]))
                        fRewrite = True
        if fRewrite:
            self.write_config()

    def update(self, feature_list, fWrite=True):
        for section in feature_list:
            if not self.reader.has_section(section):
                self.reader.add_section(section)
            for opt in feature_list[section]:
                self.reader.set(section,opt,str(feature_list[section][opt]))
        if fWrite:
            self.write_config()


    def get_opt(self, section, option):
        return self.reader.getboolean(section,option)

    def write_config(self):
        f = open(self.file_path, "w")
        self.reader.write(f)
        f.close()

    def modify(self):
        f = forms.ConfigFeatures(self)
        f.Do()
        f.Free()
