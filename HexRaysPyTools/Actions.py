import ctypes
import sys
import re
import logging
import struct
import collections

import ida_hexrays
import idaapi
import idc
import idautils
import ida_pro
import ida_kernwin

import HexRaysPyTools.Forms as Forms
import HexRaysPyTools.Core.Const as Const
import HexRaysPyTools.Core.Helper as Helper
import HexRaysPyTools.Api as Api
import Settings
from HexRaysPyTools.Core.StructureGraph import StructureGraph
from HexRaysPyTools.Core.TemporaryStructure import VirtualTable, TemporaryStructureModel
from HexRaysPyTools.Core.VariableScanner import NewShallowSearchVisitor, NewDeepSearchVisitor, DeepReturnVisitor
from HexRaysPyTools.Core.Helper import FunctionTouchVisitor
from HexRaysPyTools.Core.Helper import potential_negatives, get_closets_ea_with_path
import HexRaysPyTools.Core.Cache as Cache

#If I forget to add kudos in README
#Big thanks williballenthin for plugin. https://github.com/williballenthin/ida-netnode
from HexRaysPyTools.netnode import Netnode


from HexRaysPyTools.Core.SpaghettiCode import *
from HexRaysPyTools.Core.StructXrefs import XrefStorage

fDebug = False
if fDebug:
    import pydevd

RECAST_LOCAL_VARIABLE = 0
RECAST_GLOBAL_VARIABLE = 1
RECAST_ARGUMENT = 2
RECAST_RETURN = 3
RECAST_STRUCTURE = 4

logger = logging.getLogger(__name__)

RECAST_HELPER = 1
RECAST_ASSIGMENT = 2


def register(action, *args):
    idaapi.register_action(
        idaapi.action_desc_t(
            action.name,
            action.description,
            action(*args),
            action.hotkey
        )
    )


def unregister(action):
    idaapi.unregister_action(action.name)


class TypeLibrary:

    class til_t(ctypes.Structure):
        pass

    til_t._fields_ = [
        ("name", ctypes.c_char_p),
        ("desc", ctypes.c_char_p),
        ("nbases", ctypes.c_int),
        ("base", ctypes.POINTER(ctypes.POINTER(til_t)))
    ]

    def __init__(self):
        pass

    @staticmethod
    def enable_library_ordinals(library_num):
        idaname = "ida64" if Const.EA64 else "ida"
        if sys.platform == "win32":
            dll = ctypes.windll[idaname + ".wll"] if ida_pro.IDA_SDK_VERSION < 700 else ctypes.windll[idaname + ".dll"]
        elif sys.platform == "linux2":
            dll = ctypes.cdll["lib" + idaname + ".so"]
        elif sys.platform == "darwin":
            dll = ctypes.cdll["lib" + idaname + ".dylib"]
        else:
            print "[ERROR] Failed to enable ordinals"
            return

        if ida_pro.IDA_SDK_VERSION < 700:
            idati = ctypes.POINTER(TypeLibrary.til_t).in_dll(dll, "idati")
        else:
            get_idati = dll.get_idati
            get_idati.restype = ctypes.POINTER(TypeLibrary.til_t)
            idati = get_idati()


        dll.enable_numbered_types(idati.contents.base[library_num], True)

    @staticmethod
    def choose_til():
        idati = idaapi.cvar.idati
        list_type_library = [(idati, idati.name, idati.desc)]
        for idx in xrange(idaapi.cvar.idati.nbases):
            type_library = idaapi.cvar.idati.base(idx)          # idaapi.til_t type
            list_type_library.append((type_library, type_library.name, type_library.desc))

        library_chooser = Forms.MyChoose(
            list(map(lambda x: [x[1], x[2]], list_type_library)),
            "Select Library",
            [["Library", 10 | idaapi.Choose2.CHCOL_PLAIN], ["Description", 30 | idaapi.Choose2.CHCOL_PLAIN]],
            69
        )
        library_num = library_chooser.Show(True)
        if library_num != -1:
            selected_library = list_type_library[library_num][0]
            max_ordinal = idaapi.get_ordinal_qty(selected_library)
            if max_ordinal == idaapi.BADORD:
                TypeLibrary.enable_library_ordinals(library_num - 1)
                max_ordinal = idaapi.get_ordinal_qty(selected_library)
            print "[DEBUG] Maximal ordinal of lib {0} = {1}".format(selected_library.name, max_ordinal)
            return selected_library, max_ordinal, library_num == 0
        return None

    @staticmethod
    def import_type(library, name):
        if library.name != idaapi.cvar.idati.name:
            last_ordinal = idaapi.get_ordinal_qty(idaapi.cvar.idati)
            type_id = idaapi.import_type(library, -1, name)  # tid_t
            if type_id != idaapi.BADORD:
                return last_ordinal
        return None


class RemoveArgument(idaapi.action_handler_t):

    name = "my:RemoveArgument"
    description = "Remove Argument"
    hotkey = None
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype == idaapi.VDI_LVAR:
            # If we clicked on argument
            local_variable = ctree_item.get_lvar()  # idaapi.lvar_t
            if local_variable.is_arg_var:
                return True
        return False

    def activate(self, ctx):
        vu = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        function_tinfo = idaapi.tinfo_t()
        if not vu.cfunc.get_func_type(function_tinfo):
            return
        function_details = idaapi.func_type_data_t()
        function_tinfo.get_func_details(function_details)
        del_arg = vu.item.get_lvar()  # lvar_t

        function_details.erase(filter(lambda x: x.name == del_arg.name, function_details)[0])
        Helper.fix_automatic_naming(function_details)
        function_tinfo.create_func(function_details)
        idaapi.apply_tinfo2(vu.cfunc.entry_ea, function_tinfo, idaapi.TINFO_DEFINITE)
        vu.refresh_view(True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class AddRemoveReturn(idaapi.action_handler_t):

    name = "my:RemoveReturn"
    description = "Add/Remove Return"
    hotkey = None
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc,ctree_item):
        if ctree_item.citype == idaapi.VDI_FUNC:
            # If we clicked on function
            if not cfunc.entry_ea == idaapi.BADADDR:
                return True
        return False

    def activate(self, ctx):
        # ctx - action_activation_ctx_t
        vu = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        function_tinfo = idaapi.tinfo_t()
        if not vu.cfunc.get_func_type(function_tinfo):
            return
        function_details = idaapi.func_type_data_t()
        function_tinfo.get_func_details(function_details)
        if function_details.rettype.equals_to(Const.VOID_TINFO):
            function_details.rettype = idaapi.tinfo_t(Const.PVOID_TINFO)
        else:
            function_details.rettype = idaapi.tinfo_t(idaapi.BT_VOID)
        Helper.fix_automatic_naming(function_details)
        function_tinfo.create_func(function_details)
        idaapi.apply_tinfo2(vu.cfunc.entry_ea, function_tinfo, idaapi.TINFO_DEFINITE)
        vu.refresh_view(True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ConvertToUsercall(idaapi.action_handler_t):

    name = "my:ConvertToUsercall"
    description = "Convert to __usercall"
    hotkey = None
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc,ctree_item):
        if ctree_item.citype == idaapi.VDI_FUNC:
            # If we clicked on function
            if not cfunc.entry_ea == idaapi.BADADDR:
                return True
        return False

    def activate(self, ctx):
        # ctx - action_activation_ctx_t
        vu = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        function_tinfo = idaapi.tinfo_t()
        if not vu.cfunc.get_func_type(function_tinfo):
            return
        function_details = idaapi.func_type_data_t()
        function_tinfo.get_func_details(function_details)
        convention = idaapi.CM_CC_MASK & function_details.cc
        if convention == idaapi.CM_CC_CDECL:
            function_details.cc = idaapi.CM_CC_SPECIAL
        elif convention in (idaapi.CM_CC_STDCALL, idaapi.CM_CC_FASTCALL, idaapi.CM_CC_PASCAL, idaapi.CM_CC_THISCALL):
            function_details.cc = idaapi.CM_CC_SPECIALP
        elif convention == idaapi.CM_CC_ELLIPSIS:
            function_details.cc = idaapi.CM_CC_SPECIALE
        else:
            return
        Helper.fix_automatic_naming(function_details)
        function_tinfo.create_func(function_details)
        idaapi.apply_tinfo2(vu.cfunc.entry_ea, function_tinfo, idaapi.TINFO_DEFINITE)
        vu.refresh_view(True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class GetStructureBySize(idaapi.action_handler_t):
    # TODO: apply type automatically if expression like `var = new(size)`

    name = "my:WhichStructHaveThisSize"
    description = "Structures with this size"
    hotkey = "W"
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype == idaapi.VDI_EXPR:
            if ctree_item.e.op == idaapi.cot_num:
                # number_format = item.e.n.nf                       # idaapi.number_format_t
                # print "(number) flags: {0:#010X}, type_name: {1}, opnum: {2}".format(
                #     number_format.flags,
                #     number_format.type_name,
                #     number_format.opnum
                # )
                return True
        return False

    @staticmethod
    def select_structure_by_size(size):
        result = TypeLibrary.choose_til()
        if result:
            selected_library, max_ordinal, is_local_type = result
            matched_types = []
            tinfo = idaapi.tinfo_t()
            for ordinal in xrange(1, max_ordinal):
                tinfo.create_typedef(selected_library, ordinal)
                if tinfo.get_size() == size:
                    name = tinfo.dstr()
                    description = idaapi.print_tinfo(None, 0, 0, idaapi.PRTYPE_DEF, tinfo, None, None)
                    matched_types.append([str(ordinal), name, description])

            type_chooser = Forms.MyChoose(
                matched_types,
                "Select Type",
                [["Ordinal", 5 | idaapi.Choose2.CHCOL_HEX], ["Type Name", 25], ["Declaration", 50]],
                165
            )
            selected_type = type_chooser.Show(True)
            if selected_type != -1:
                if is_local_type:
                    return int(matched_types[selected_type][0])
                return TypeLibrary.import_type(selected_library, matched_types[selected_type][1])
        return None

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        if hx_view.item.citype != idaapi.VDI_EXPR or hx_view.item.e.op != idaapi.cot_num:
            return
        ea = ctx.cur_ea
        c_number = hx_view.item.e.n
        number_value = c_number._value
        ordinal = GetStructureBySize.select_structure_by_size(number_value)
        if ordinal:
            number_format_old = c_number.nf
            number_format_new = idaapi.number_format_t()
            number_format_new.flags = idaapi.FF_1STRO | idaapi.FF_0STRO
            operand_number = number_format_old.opnum
            number_format_new.opnum = operand_number
            number_format_new.props = number_format_old.props
            number_format_new.type_name = idaapi.create_numbered_type_name(ordinal)

            c_function = hx_view.cfunc
            number_formats = c_function.numforms    # idaapi.user_numforms_t
            operand_locator = idaapi.operand_locator_t(ea, ord(operand_number) if operand_number else 0)
            if operand_locator in number_formats:
                del number_formats[operand_locator]

            number_formats[operand_locator] = number_format_new
            c_function.save_user_numforms()
            hx_view.refresh_view(True)

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class ShallowScanVariable(idaapi.action_handler_t):

    name = "my:ShallowScanVariable"
    description = "Scan Variable"
    hotkey = "F"
    ForPopup = True

    def __init__(self):
        self.temporary_structure = Cache.temporary_structure
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        lvar = ctree_item.get_lvar()
        if lvar is not None:
            return Helper.is_legal_type(lvar.type())

        if ctree_item.citype != idaapi.VDI_EXPR:
            return False

        obj = Api.ScanObject.create(cfunc, ctree_item.e)
        return obj and Helper.is_legal_type(obj.tinfo)

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        cfunc = hx_view.cfunc
        origin = self.temporary_structure.main_offset

        if self.check(cfunc, hx_view.item):
            obj = Api.ScanObject.create(cfunc, hx_view.item)
            visitor = NewShallowSearchVisitor(cfunc, origin, obj, self.temporary_structure)
            visitor.process()

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class DeepScanVariable(idaapi.action_handler_t):

    name = "my:DeepScanVariable"
    description = "Deep Scan Variable"
    hotkey = "shift+F"
    ForPopup = True

    def __init__(self):
        self.temporary_structure = Helper.temporary_structure
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        return ShallowScanVariable.check(cfunc, ctree_item)

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        cfunc = hx_view.cfunc
        origin = self.temporary_structure.main_offset

        if ShallowScanVariable.check(cfunc, hx_view.item):
            obj = Api.ScanObject.create(cfunc, hx_view.item)
            if FunctionTouchVisitor(cfunc).process():
                hx_view.refresh_view(True)
            visitor = NewDeepSearchVisitor(hx_view.cfunc, origin, obj, self.temporary_structure)
            visitor.process()

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class DeepScanReturn(idaapi.action_handler_t):
    name = "my:DeepScanReturn"
    description = "Deep Scan Returned Variables"
    hotkey = None
    ForPopup = True

    def __init__(self):
        self.temp_struct = Cache.temporary_structure
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype == idaapi.VDI_FUNC and not cfunc.entry_ea == idaapi.BADADDR:
            # If we clicked on function
            tinfo = idaapi.tinfo_t()
            cfunc.get_func_type(tinfo)
            return not tinfo.get_rettype().equals_to(Const.VOID_TINFO)

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form)
        func_ea = hx_view.cfunc.entry_ea

        obj = Api.ReturnedObject(func_ea)
        visitor = DeepReturnVisitor(hx_view.cfunc, self.temp_struct.main_offset, obj, self.temp_struct)
        visitor.process()

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class DeepScanFunctions(idaapi.action_handler_t):

    name = "my:DeepScanFunctions"
    description = "Scan First Argument"
    hotkey = None
    ForPopup = False

    def __init__(self):
        self.temporary_structure = Cache.temporary_structure
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        for idx in ctx.chooser_selection:
            func_ea = idaapi.getn_func(idx - 1).startEA
            cfunc = Api.decompile_function(func_ea)
            obj = Api.VariableObject(cfunc.get_lvars()[0], 0)
            if cfunc:
                NewDeepSearchVisitor(cfunc, 0, obj, self.temporary_structure).process()

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_type == idaapi.BWN_FUNCS:
                idaapi.attach_action_to_popup(ctx.form, None, self.name)
            return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == idaapi.BWN_FUNCS:
                idaapi.attach_action_to_popup(ctx.widget, None, self.name)
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class RecognizeShape(idaapi.action_handler_t):

    name = "my:RecognizeShape"
    description = "Recognize Shape"
    hotkey = None
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        return ShallowScanVariable.check(cfunc, ctree_item)

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        cfunc = hx_view.cfunc

        if not ShallowScanVariable.check(cfunc, hx_view.item):
            return

        obj = Api.ScanObject.create(cfunc, hx_view.item)
        temp_struct = TemporaryStructureModel()
        visitor = NewShallowSearchVisitor(cfunc, 0, obj, temp_struct)
        visitor.process()
        tinfo = temp_struct.get_recognized_shape()
        if tinfo:
            tinfo.create_ptr(tinfo)
            if obj.id == Api.SO_LOCAL_VARIABLE:
                hx_view.set_lvar_type(obj.lvar, tinfo)
            elif obj.id == Api.SO_GLOBAL_OBJECT:
                idaapi.apply_tinfo2(obj.obj_ea, tinfo, idaapi.TINFO_DEFINITE)
            hx_view.refresh_view(True)

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class CreateNewField(idaapi.action_handler_t):
    name = "my:CreateNewField"
    description = "Create New Field"
    hotkey = None
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        item = ctree_item.it.to_specific_type
        if item.op != idaapi.cot_memptr:
            return

        parent = cfunc.body.find_parent_of(ctree_item.it).to_specific_type
        if parent.op != idaapi.cot_idx or parent.y.op != idaapi.cot_num:
            idx = 0
        else:
            idx = parent.y.numval()

        struct_type = item.x.type.get_pointed_object()
        udt_member = idaapi.udt_member_t()
        udt_member.offset = item.m * 8
        struct_type.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
        if udt_member.name[0:3] != "gap":
            return

        return struct_type, udt_member.offset // 8, idx

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        result = self.check(hx_view.cfunc, hx_view.item)
        if result is None:
            return

        struct_tinfo, offset, idx = result
        ordinal = struct_tinfo.get_ordinal()
        struct_name = struct_tinfo.dstr()

        if (offset + idx) % 2:
            default_field_type = "_BYTE"
        elif (offset + idx) % 4:
            default_field_type = "_WORD"
        else:
            default_field_type = "_DWORD"

        declaration = idaapi.asktext(
            0x10000, "{0} field_{1:X}".format(default_field_type, offset + idx), "Enter new structure member:"
        )
        if declaration is None:
            return

        result = self.parse_declaration(declaration)
        if result is None:
            logger.warn("Bad member declaration")
            return

        field_tinfo, field_name = result
        field_size = field_tinfo.get_size()
        udt_data = idaapi.udt_type_data_t()
        udt_member = idaapi.udt_member_t()

        struct_tinfo.get_udt_details(udt_data)
        udt_member.offset = offset * 8
        struct_tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
        gap_size = udt_member.size // 8

        gap_leftover = gap_size - idx - field_size

        if gap_leftover < 0:
            print "[ERROR] Too big size for the field. Type with maximum {0} bytes can be used".format(gap_size - idx)
            return

        iterator = udt_data.find(udt_member)
        iterator = udt_data.erase(iterator)

        if gap_leftover > 0:
            udt_data.insert(iterator, TemporaryStructureModel.get_padding_member(offset + idx + field_size, gap_leftover))

        udt_member = idaapi.udt_member_t()
        udt_member.offset = offset * 8 + idx
        udt_member.name = field_name
        udt_member.type = field_tinfo
        udt_member.size = field_size

        iterator = udt_data.insert(iterator, udt_member)

        if idx > 0:
            udt_data.insert(iterator, TemporaryStructureModel.get_padding_member(offset, idx))

        struct_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
        struct_tinfo.set_numbered_type(idaapi.cvar.idati, ordinal, idaapi.BTF_STRUCT, struct_name)
        hx_view.refresh_view(True)

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM

    @staticmethod
    def parse_declaration(declaration):
        m = re.search(r"^(\w+[ *]+)(\w+)(\[(\d+)\])?$", declaration)
        if m is None:
            return

        type_name, field_name, _, arr_size = m.groups()
        if field_name[0].isdigit():
            print "[ERROR] Bad field name"
            return

        result = idc.ParseType(type_name, 0)
        if result is None:
            return

        _, tp, fld = result
        tinfo = idaapi.tinfo_t()
        tinfo.deserialize(idaapi.cvar.idati, tp, fld, None)
        if arr_size:
            assert tinfo.create_array(tinfo, int(arr_size))
        return tinfo, field_name


class ShowGraph(idaapi.action_handler_t):
    name = "my:ShowGraph"
    description = "Show graph"
    hotkey = ""
    ForPopup = False

    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.graph = None
        self.graph_view = None

    def activate(self, ctx):
        """
        :param ctx: idaapi.action_activation_ctx_t
        :return:    None
        """
        form = self.graph_view.GetTForm() if self.graph_view else None
        if form:
            self.graph_view.change_selected(list(ctx.chooser_selection))
            self.graph_view.Show()
        else:
            self.graph = StructureGraph(list(ctx.chooser_selection))
            self.graph_view = Forms.StructureGraphViewer("Structure Graph", self.graph)
            self.graph_view.Show()

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_type == idaapi.BWN_LOCTYPS:
                idaapi.attach_action_to_popup(ctx.form, None, self.name)
            return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == idaapi.BWN_LOCTYPS:
                idaapi.attach_action_to_popup(ctx.widget, None, self.name)
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class ShowClasses(idaapi.action_handler_t):

    name = "my:ShowClasses"
    description = "Classes"
    hotkey = "Alt+F1"
    ForPopup = False

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        """
        :param ctx: idaapi.action_activation_ctx_t
        :return:    None
        """
        tform = idaapi.find_tform('Classes')
        if not tform:
            class_viewer = Forms.ClassViewer()
            class_viewer.Show()
        else:
            idaapi.switchto_tform(tform, True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class CreateVtable(idaapi.action_handler_t):
    name = "my:CreateVtable"
    description = "Create Vtable"
    hotkey = "shift+V"
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.is_citem() and ctree_item.it.is_expr():
            item = ctree_item.e
            if item.opname == "obj" and idaapi.isData(idaapi.getFlags(item.obj_ea)):
                return True
        return False

    def activate(self, ctx):
        if fDebug:
            pydevd.settrace('localhost', port=2255, stdoutToServer=True, stderrToServer=True)
        my_ti = idaapi.cvar.idati
        vdui = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        vdui.get_current_item(idaapi.USE_KEYBOARD)
        if vdui.item.is_citem() and vdui.item.it.is_expr():
            target_item = vdui.item.e
            name = self.create_vtable(target_item.obj_ea)
            # if name is not None:
            #     cfunc = vdui.cfunc
            #     it_parent = cfunc.body.find_parent_of(target_item)
            #     while not it_parent is None or it_parent.op != idaapi.cit_block:
            #         if it_parent.is_expr() and it_parent.op == idaapi.cot_asg:
            #             operand = it_parent.cexpr.x
            #             if operand.op == idaapi.cot_memptr:
            #                 off = operand.cexpr.m
            #                 it_obj = operand.cexpr.x
            #                 obj_name = ("%s"%it_obj.cexpr.type).strip(" *")
            #                 sid = idc.GetStrucIdByName(obj_name)
            #                 if sid == idaapi.BADADDR:
            #                     break
            #                 sptr = idaapi.get_struc(sid)
            #                 mptr = idaapi.get_best_fit_member(sptr,off)
            #                 tif = idaapi.tinfo_t()
            #                 idaapi.parse_decl2(my_ti,name + " *;",tif,0)
            #                 idaapi.set_member_tinfo2(sptr,mptr,0,tif,0)
            #                 break
            #         it_parent = cfunc.body.find_parent_of(it_parent)
            vdui.refresh_view(True)

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM

    def GetXrefCnt(self, ea):
        i = 0
        for xref in idautils.XrefsTo(ea, 0):
            i += 1
        return i

    def create_vtable(self, addr):

        def isMangled(n):
            if n.startswith("_ZN"): return True
            return False

        # print "addr = 0x%08X" % addr

        name = idc.AskStr("", "Please enter the class name")
        if name is None:
            return
        struct_id = idaapi.get_struc_id(name + "_vtbl")
        # print struct_id
        if struct_id != idaapi.BADADDR:
            i = idaapi.askyn_c(0, "A vtable structure for %s already exists. Are you sure you want to remake it?" % name)
            if i == idaapi.BADADDR:
                return
            if i == 1:
                idaapi.del_struc_members(idaapi.get_struc(struct_id),0,idaapi.get_struc_size(struct_id))
                # struct_id = idc.AddStrucEx(idaapi.BADADDR, name + "_vtbl", 0)
        else:
            struct_id = idaapi.add_struc(idaapi.BADADDR, name + "_vtbl", 0)
        if struct_id == idaapi.BADADDR:
            Warning("Could not create the vtable structure!.\nPlease check the entered class name.")
            return

        # bNameMethods = AskYN(0,"Would you like to assign auto names to the virtual methods (%s_virtXX)?"%name)
        i = 0
        n = Netnode("$ VTables")
        n[name + "_vtbl"] = []
        info = idaapi.get_inf_structure()
        if not Const.EA64:
            ptr_size = 4
            fSize = idaapi.FF_DWRD
            refinf = idaapi.refinfo_t(idaapi.REF_OFF32)
        else:
            ptr_size = 8
            fSize = idaapi.FF_QWRD
            refinf = idaapi.refinfo_t(idaapi.REF_OFF64)
        # else:
        #     ptr_size = 2
        #     fSize = idaapi.FF_WORD
        #     refinf = idaapi.refinfo_t(idaapi.REF_OFF16)

        opinf = idaapi.opinfo_t()
        opinf.ri = refinf
        while (idaapi.isFunc(idaapi.getFlags(idc.Dword(addr))) and (self.GetXrefCnt(addr) == 0 or i == 0) or idc.Dword(addr) != 0) is True:
            c = idaapi.get_full_long(addr)
            methName = ""
            # print "c = 0x%08X" % c
            # print "i = %d" % i
            if c != 0:
                if idc.hasName(c) or idaapi.get_name(idaapi.BADADDR,c) != "":
                    methName = idaapi.get_name(idaapi.BADADDR,c)
                    if isMangled(methName):
                        methName = idaapi.demangle_name(methName, 0)[:idaapi.demangle_name(methName, 0).find("(")]
                        methName = methName.replace("~", "dtor_").replace("==", "_equal")
                else:
                    methName = name + "__" + "virt_%X" % c
            else:
                methName = "field_%02X" % (i * 4)
            # print methName
            sptr = idaapi.get_struc(struct_id)
            e = idaapi.add_struc_member(sptr, methName, i * ptr_size, idaapi.FF_0OFF | fSize | idaapi.FF_DATA, opinf, ptr_size)
            # print "e = %d" % e
            if e != 0:
                if e == -1:
                    l = 0
                    while e == -1:
                        e = idaapi.add_struc_member(sptr, (methName + "_%d"%l), i * ptr_size, idaapi.FF_0OFF | fSize | idaapi.FF_DATA,
                                                    opinf, ptr_size)
                        l = l + 1
                elif e != -2 and e != idaapi.BADADDR:
                    Warning("Error adding a vtable entry!")
                    return
                else:
                    Warning("Unknown error! Err = %d"%e)
                    return
            idc.SetMemberComment(struct_id, i * ptr_size, "-> %08X, args: 0x%X" % (c, idc.GetFrameArgsSize(c)), 1)
            l = n[name + "_vtbl"]
            l.append((c - idaapi.get_imagebase()) if c else idaapi.BADADDR)
            n[name + "_vtbl"] = l

            i = i + 1
            addr = addr + ptr_size
        return name + "_vtbl"



# class CreateVtable(idaapi.action_handler_t):
#
#     name = "my:CreateVtable"
#     description = "Create Virtual Table"
#     hotkey = "V"
#
#     def __init__(self):
#         idaapi.action_handler_t.__init__(self)
#
#     def activate(self, ctx):
#         ea = ctx.cur_ea
#         if ea != idaapi.BADADDR and VirtualTable.check_address(ea):
#             vtable = VirtualTable(0, ea)
#             vtable.import_to_structures(True)
#
#     def update(self, ctx):
#         if ctx.form_type == idaapi.BWN_DISASM:
#             idaapi.attach_action_to_popup(ctx.form, None, self.name)
#             return idaapi.AST_ENABLE_FOR_FORM
#         return idaapi.AST_DISABLE_FOR_FORM


class SelectContainingStructure(idaapi.action_handler_t):

    name = "my:SelectContainingStructure"
    description = "Select Containing Structure"
    hotkey = None
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.potential_negative = potential_negatives

    @staticmethod
    def check(cfunc, ctree_item):
        # Check if we clicked on variable that is a pointer to a structure that is potentially part of
        # containing structure
        if ctree_item.citype == idaapi.VDI_EXPR and ctree_item.e.op == idaapi.cot_var and ctree_item.e.v.idx in potential_negatives:
            return True
        return False

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        result = TypeLibrary.choose_til()
        if result:
            selected_library, max_ordinal, is_local_types = result
            lvar_idx = hx_view.item.e.v.idx
            candidate = self.potential_negative[lvar_idx]
            structures = candidate.find_containing_structures(selected_library)
            items = map(lambda x: [str(x[0]), "0x{0:08X}".format(x[1]), x[2], x[3]], structures)
            structure_chooser = Forms.MyChoose(
                items,
                "Select Containing Structure",
                [["Ordinal", 5], ["Offset", 10], ["Member_name", 20], ["Structure Name", 20]],
                165
            )
            selected_idx = structure_chooser.Show(modal=True)
            if selected_idx != -1:
                if not is_local_types:
                    TypeLibrary.import_type(selected_library, items[selected_idx][3])
                lvar = hx_view.cfunc.get_lvars()[lvar_idx]
                lvar_cmt = re.sub("```.*```", '', lvar.cmt)
                hx_view.set_lvar_cmt(
                    lvar,
                    lvar_cmt + "```{0}+{1}```".format(
                        structures[selected_idx][3],
                        structures[selected_idx][1])
                )
                hx_view.refresh_view(True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ResetContainingStructure(idaapi.action_handler_t):

    name = "my:ResetContainingStructure"
    description = "Reset Containing Structure"
    hotkey = None
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype == idaapi.VDI_EXPR and ctree_item.e.op == idaapi.cot_var:
            return True if re.search("```.*```", cfunc.get_lvars()[ctree_item.e.v.idx].cmt) else False
        return False

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        lvar = hx_view.cfunc.get_lvars()[hx_view.item.e.v.idx]
        hx_view.set_lvar_cmt(lvar, re.sub("```.*```", '', lvar.cmt))
        hx_view.refresh_view(True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class RecastItemLeft(idaapi.action_handler_t):

    name = "my:RecastItemLeft"
    description = "Recast Item"
    hotkey = "Shift+L"
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expression = ctree_item.it.to_specific_type
        child = None
        branch_nodes = [expression]
        # Look through parents until we found Return, Assignment or Call
        while expression and expression.op not in (idaapi.cot_asg, idaapi.cit_return, idaapi.cot_call):
            child = expression.to_specific_type
            expression = cfunc.body.find_parent_of(expression)
            if expression:
                branch_nodes.append(expression.to_specific_type)
        if not expression:
            return
        branch_nodes.reverse()

        expression = expression.to_specific_type
        if expression.opname == 'asg':

            if expression.x.opname not in ('var', 'obj', 'memptr', 'memref'):
                return

            right_expr = expression.y
            right_tinfo = right_expr.x.type if right_expr.op == idaapi.cot_cast else right_expr.type

            # Check if both left and right parts of expression are of the same types.
            # If not then we can recast then.
            if right_tinfo.dstr() == expression.x.type.dstr():
                return

            if expression.x.op == idaapi.cot_var:
                # var = (TYPE ) ...;
                variable = cfunc.get_lvars()[expression.x.v.idx]
                idaapi.update_action_label(RecastItemLeft.name, 'Recast Variable "{0}"'.format(variable.name))
                return RECAST_LOCAL_VARIABLE, right_tinfo, variable
            elif expression.x.op == idaapi.cot_obj:
                # g_var = (TYPE ) ...;
                idaapi.update_action_label(RecastItemLeft.name, 'Recast Global')
                return RECAST_GLOBAL_VARIABLE, right_tinfo, expression.x.obj_ea
            # elif expression.x.op == idaapi.cot_memptr:
            #     # struct->member = (TYPE ) ...;
            #     idaapi.update_action_label(RecastItemLeft.name, 'Recast Field')
            #     return RECAST_STRUCTURE, expression.x.x.type.get_pointed_object().dstr(), expression.x.m, right_tinfo
            # elif expression.x.op == idaapi.cot_memref:
            #     # struct.member = (TYPE ) ...;
            #     idaapi.update_action_label(RecastItemLeft.name, 'Recast Field')
            #     return RECAST_STRUCTURE, expression.x.x.type.dstr(), expression.x.m, right_tinfo

        elif expression.op == idaapi.cit_return:

            idaapi.update_action_label(RecastItemLeft.name, "Recast Return")
            child = child or expression.creturn.expr

            if child.op == idaapi.cot_cast:
                # return (TYPE) ...;
                return RECAST_RETURN, child.x.type, None

            func_tinfo = idaapi.tinfo_t()
            cfunc.get_func_type(func_tinfo)
            rettype = func_tinfo.get_rettype()

            if func_tinfo.get_rettype().dstr() != child.type.dstr():
                # return ...;
                # This's possible when returned type and value are both pointers to different types
                return RECAST_RETURN, child.type, None

        elif expression.op == idaapi.cot_call:
            if expression.x.op == idaapi.cot_memptr:
                if expression.x == child:
                    return

                arg_index, arg_tinfo = Helper.get_func_argument_info(expression, child)
                if child.op == idaapi.cot_cast:
                    # struct_ptr->func(..., (TYPE) var, ...);
                    new_arg_tinfo = child.x.type
                else:
                    # struct_ptr->func(..., var, ...); When `var` and `arg` are different pointers
                    if arg_tinfo.equals_to(child.type):
                        return
                    new_arg_tinfo = child.type

                struct_type = expression.x.x.type.get_pointed_object()
                funcptr_tinfo = expression.x.type
                Helper.set_funcptr_argument(funcptr_tinfo, arg_index, new_arg_tinfo)
                return RECAST_STRUCTURE, struct_type.dstr(), expression.x.m, funcptr_tinfo

            if child and child.op == idaapi.cot_cast:
                if child.cexpr.x.op == idaapi.cot_memptr and expression.ea == idaapi.BADADDR:
                    idaapi.update_action_label(RecastItemLeft.name, 'Recast Virtual Function')
                    return RECAST_STRUCTURE, child.cexpr.x.x.type.get_pointed_object().dstr(), child.cexpr.x.m, child.type
                elif child.cexpr.x.op == idaapi.cot_memref and expression.x.index == child.index \
                        and cfunc.body.find_parent_of(ctree_item.e).op not in (idaapi.cot_memref, idaapi.cot_memptr):
                    idaapi.update_action_label(RecastItemLeft.name, 'Recast Virtual Function')
                    return RECAST_STRUCTURE, child.cexpr.x.x.type.dstr(), child.cexpr.x.m, child.type

                if expression.x == child.cexpr:
                    return

                arg_index, _ = Helper.get_func_argument_info(expression, child.cexpr)
                idaapi.update_action_label(RecastItemLeft.name, "Recast Argument")
                return (
                    RECAST_ARGUMENT,
                    arg_index,
                    expression.x.type.get_pointed_object(),
                    child.x.type,
                    expression.x.obj_ea
                )
        branch_idx = 0
        fPtr = False
        if len(branch_nodes) > 1 and branch_nodes[branch_idx].op == idaapi.cot_call and branch_nodes[branch_idx].x.index != branch_nodes[branch_idx + 1].index \
                and branch_nodes[branch_idx].x.op != idaapi.cot_helper:
            branch_idx += 1
            if branch_nodes[branch_idx].op == idaapi.cot_ref:
                fPtr = True
                branch_idx += 1
            if branch_nodes[branch_idx].index == ctree_item.e.index:
                func_tif = idaapi.tinfo_t()
                if fPtr:
                    item_type = idaapi.tinfo_t()
                    item_type.create_ptr(ctree_item.e.type)
                else:
                    item_type = ctree_item.e.type
                if idaapi.get_tinfo2(branch_nodes[0].x.obj_ea, func_tif):
                    arg_index, _ = Helper.get_func_argument_info(branch_nodes[0], branch_nodes[1])
                    fi = idaapi.func_type_data_t()
                    if func_tif.get_func_details(fi) and fi[arg_index].type.dstr() != item_type.dstr():
                        idaapi.update_action_label(RecastItemLeft.name, "Recast Argument")
                        return (
                            RECAST_ARGUMENT,
                            arg_index,
                            branch_nodes[0].x.type.get_pointed_object(),
                            item_type,
                            branch_nodes[0].x.obj_ea
                        )
                else:
                    arg_index, _ = Helper.get_func_argument_info(branch_nodes[0], branch_nodes[1])
                    idaapi.update_action_label(RecastItemLeft.name, "Recast Argument")
                    return (
                        RECAST_ARGUMENT,
                        arg_index,
                        branch_nodes[0].x.type.get_pointed_object(),
                        item_type,
                        branch_nodes[0].x.obj_ea
                    )

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        result = self.check(hx_view.cfunc, hx_view.item)

        if not result:
            return

        if result[0] == RECAST_LOCAL_VARIABLE:
            logger.debug("Recasting local variable. Type - %s", result[1].dstr())
            tinfo, lvar = result[1:]
            if hx_view.set_lvar_type(lvar, tinfo):
                hx_view.refresh_view(True)

        elif result[0] == RECAST_GLOBAL_VARIABLE:
            logger.debug("Recasting global. Type - %s. Address - %s", result[1].dstr(), Helper.to_hex(result[2]))
            tinfo, address = result[1:]
            if idaapi.apply_tinfo2(address, tinfo, idaapi.TINFO_DEFINITE):
                hx_view.refresh_view(True)

        elif result[0] == RECAST_ARGUMENT:
            arg_index, func_tinfo, arg_tinfo, address = result[1:]
            if arg_tinfo.is_array():
                arg_tinfo.convert_array_to_ptr()

            func_data = idaapi.func_type_data_t()
            func_tinfo.get_func_details(func_data)
            func_data[arg_index].type = arg_tinfo
            Helper.fix_automatic_naming(func_data)
            new_func_tinfo = idaapi.tinfo_t()
            new_func_tinfo.create_func(func_data)
            if idaapi.apply_tinfo2(address, new_func_tinfo, idaapi.TINFO_DEFINITE):
                hx_view.refresh_view(True)# if ida_hexrays.set_type(address, new_func_tinfo, ida_hexrays.GUESSED_WEAK,False):
            #     hx_view.refresh_view(True)

        elif result[0] == RECAST_RETURN:
            return_type, func_address = result[1:]
            try:
                cfunc = idaapi.decompile(func_address) if func_address else hx_view.cfunc
            except idaapi.DecompilationFailure:
                print "[ERROR] Ida failed to decompile function at 0x{0:08X}".format(func_address)
                return

            function_tinfo = idaapi.tinfo_t()
            cfunc.get_func_type(function_tinfo)
            func_data = idaapi.func_type_data_t()
            function_tinfo.get_func_details(func_data)
            func_data.rettype = return_type
            Helper.fix_automatic_naming(func_data)
            function_tinfo.create_func(func_data)
            if idaapi.apply_tinfo2(cfunc.entry_ea, function_tinfo, idaapi.TINFO_DEFINITE):
                hx_view.refresh_view(True)

        elif result[0] == RECAST_STRUCTURE:
            structure_name, field_offset, new_type = result[1:]
            tinfo = idaapi.tinfo_t()
            tinfo.get_named_type(idaapi.cvar.idati, structure_name)

            ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, structure_name)

            if ordinal:
                udt_member = idaapi.udt_member_t()
                udt_member.offset = field_offset * 8
                idx = tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
                # if udt_member.offset != field_offset * 8:
                #     print "[Info] Can't handle with arrays yet"
                # elif udt_member.type.get_size() != new_type.get_size():
                #     print "[Info] Can't recast different sizes yet"
                #     sid = idaapi.get_struc_id(structure_name)
                #     if sid != idaapi.BADADDR:
                #         sptr = idaapi.get_struc(sid)
                #         mptr = idaapi.get_member(sptr, field_offset)
                #         rc = idaapi.set_member_tinfo2(sptr,mptr,field_offset,new_type,idaapi.SET_MEMTI_MAY_DESTROY)
                #         if rc != 1:
                #             print ("set_member_tinfo2 rc = %d"%rc)
                #         hx_view.refresh_view(True)
                # else:
                    #Commented solution having troubles if struct with recasted member is a member of union.
                    #And, my variant may work with various sizes of types.

                    # udt_data = idaapi.udt_type_data_t()
                    # tinfo.get_udt_details(udt_data)
                    # udt_data[idx].type = new_type
                    # tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
                    # tinfo.set_numbered_type(idaapi.cvar.idati, ordinal, idaapi.NTF_REPLACE, structure_name)
                sid = idaapi.get_struc_id(structure_name)
                if sid != idaapi.BADADDR:
                    sptr = idaapi.get_struc(sid)
                    mptr = idaapi.get_member(sptr, field_offset)
                    if mptr is None:
                        if idaapi.add_struc_member(sptr,"field_%X"%field_offset,field_offset, idaapi.FF_DATA|idaapi.FF_BYTE,None,1) != 0:
                            print "Error on add_struc_member!"
                        mptr = idaapi.get_member(sptr, field_offset)
                    elif mptr.soff != field_offset:
                        if not idaapi.del_struc_member(sptr,mptr.soff):
                            print "Error on del_struc_member!"
                        if idaapi.add_struc_member(sptr,"field_%X"%field_offset,field_offset, idaapi.FF_DATA|idaapi.FF_BYTE,None,1) != 0:
                            print "Error on add_struc_member!"
                        mptr = idaapi.get_member(sptr, field_offset)
                    else:
                        tif = idaapi.tinfo_t()
                        idaapi.get_member_tinfo2(mptr, tif)
                        if tif.is_array():
                            if not idaapi.del_struc_member(sptr, mptr.soff):
                                print "Error on del_struc_member!"
                            if idaapi.add_struc_member(sptr, "field_%X" % field_offset, field_offset,
                                                       idaapi.FF_DATA | idaapi.FF_BYTE, None, 1) != 0:
                                print "Error on add_struc_member!"
                            mptr = idaapi.get_member(sptr, field_offset)
                    rc = idaapi.set_member_tinfo2(sptr, mptr, field_offset, new_type,
                                                  idaapi.SET_MEMTI_MAY_DESTROY)
                    if rc != 1:
                        print ("set_member_tinfo2 rc = %d" % rc)
                    hx_view.refresh_view(True)

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class RecastItemRight(RecastItemLeft):

    name = "my:RecastItemRight"
    description = "Recast Item"
    hotkey = "Shift+R"
    ForPopup = True

    def __init__(self):
        RecastItemLeft.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expression = ctree_item.it

        result = RecastItemRight._check_potential_array(cfunc, expression)
        if result:
            return result

        # Look through parents until we found Cast
        while expression and expression.op != idaapi.cot_cast:
            expression = expression.to_specific_type
            expression = cfunc.body.find_parent_of(expression)
        if not expression:
            return

        expression = expression.to_specific_type

        # Find `(TYPE) something;` or `(TYPE *) &something;` and calculate appropriate type for recast
        if expression.x.op == idaapi.cot_ref:
            new_type = expression.type.get_pointed_object()
            expression = expression.x
        else:
            new_type = expression.type
        nodes = Helper.get_nodes_to_call_parent(ctree_item,cfunc)
        call_parent = None
        call_child = None
        if nodes:
            call_parent, call_child = nodes[:2]

        if expression.x.op == idaapi.cot_var:
            # (TYPE) var;
            variable = cfunc.get_lvars()[expression.x.v.idx]
            idaapi.update_action_label(RecastItemRight.name, 'Recast Variable "{0}"'.format(variable.name))
            return RECAST_LOCAL_VARIABLE, new_type, variable

        elif expression.x.op == idaapi.cot_obj:
            # (TYPE) g_var;
            if Helper.is_code_ea(expression.x.obj_ea) and new_type.is_funcptr():
                # (TYPE) sub_XXXXXX;
                new_type = new_type.get_pointed_object()

            idaapi.update_action_label(RecastItemRight.name, 'Recast Global')
            return RECAST_GLOBAL_VARIABLE, new_type, expression.x.obj_ea

        elif expression.x.op == idaapi.cot_call:
            # (TYPE) call();
            idaapi.update_action_label(RecastItemRight.name, "Recast Return")
            return RECAST_RETURN, new_type, expression.x.x.obj_ea

        # elif expression.x.op == idaapi.cot_memptr:
        #     # (TYPE) var->member;
        #     idaapi.update_action_label(RecastItemRight.name, "Recast Field")
        #     return RECAST_STRUCTURE, expression.x.x.type.get_pointed_object().dstr(), expression.x.m, new_type
        #
        # elif expression.x.op in (idaapi.cot_memptr,idaapi.cot_memref) and call_parent is None:
        #     if expression.x.op == idaapi.cot_memptr:
        #         idaapi.update_action_label(RecastItemRight.name, "Recast Field")
        #         return RECAST_STRUCTURE, expression.x.x.type.get_pointed_object().dstr(),expression.x.m,new_type
        #     elif expression.x.op == idaapi.cot_memref:
        #         idaapi.update_action_label(RecastItemRight.name, "Recast Field")
        #         return RECAST_STRUCTURE, expression.x.x.type.dstr(), expression.x.m, new_type

        # elif call_parent and call_child.op == idaapi.cot_cast and ctree_item.e.op in (idaapi.cot_memptr, idaapi.cot_memref):
        #     if nodes[2].op == idaapi.cot_add:
        #         offset = nodes[2].to_specific_type.y.n._value if nodes[2].to_specific_type.x.index == nodes[3].index else nodes[2].to_specific_type.x.n._value
        #         if nodes[-2].op == idaapi.cot_ref:
        #             idaapi.update_action_label(RecastItemRight.name, "Recast Field")
        #             # tmp = (RECAST_STRUCTURE, ctree_item.e.x.type.get_pointed_object().dstr(), ctree_item.e.m + offset, call_child.to_specific_type.type.get_pointed_object())
        #             return RECAST_STRUCTURE, ctree_item.e.x.type.get_pointed_object().dstr(), ctree_item.e.m + offset, call_child.to_specific_type.type.get_pointed_object()
        #     if ctree_item.e.op == idaapi.cot_memptr:
        #         if nodes[-2].op == idaapi.cot_ref:
        #             idaapi.update_action_label(RecastItemRight.name, "Recast Field")
        #             return RECAST_STRUCTURE, ctree_item.e.x.type.get_pointed_object().dstr(),ctree_item.e.m, call_child.to_specific_type.type.get_pointed_object()
        #         else:
        #             sid = idaapi.get_struc_id(ctree_item.e.x.type.get_pointed_object().dstr())
        #             if sid != idaapi.BADADDR:
        #                 sptr = idaapi.get_struc(sid)
        #                 mptr = idaapi.get_member(sptr, ctree_item.e.m)
        #                 if mptr:
        #                     tif = idaapi.tinfo_t()
        #                     idaapi.get_member_tinfo2(mptr,tif)
        #                     if tif.is_array():
        #                         idaapi.update_action_label(RecastItemRight.name, "Recast Field")
        #                         return RECAST_STRUCTURE, ctree_item.e.x.type.get_pointed_object().dstr(), ctree_item.e.m, call_child.to_specific_type.type.get_pointed_object()
        #                     else:
        #                         idaapi.update_action_label(RecastItemRight.name, "Recast Field")
        #                         return RECAST_STRUCTURE, ctree_item.e.x.type.get_pointed_object().dstr(), ctree_item.e.m, call_child.to_specific_type.type
        #                 else:
        #                     idaapi.update_action_label(RecastItemRight.name, "Recast Field")
        #                     return RECAST_STRUCTURE, ctree_item.e.x.type.get_pointed_object().dstr(), ctree_item.e.m, call_child.to_specific_type.type.get_pointed_object()

    @staticmethod
    def _check_potential_array(cfunc, expr):
        """ Checks `call(..., &buffer, ..., number)` and returns information for recasting """
        if expr.op != idaapi.cot_var:
            return

        var_expr = expr.to_specific_type
        parent = cfunc.body.find_parent_of(expr)
        if parent.op != idaapi.cot_ref:
            return

        parent = cfunc.body.find_parent_of(parent)
        if parent.op != idaapi.cot_call:
            return

        call_expr = parent.to_specific_type
        for arg_expr in call_expr.a:
            if arg_expr.op == idaapi.cot_num:
                number = arg_expr.numval()
                if number:
                    variable = cfunc.lvars[var_expr.v.idx]
                    char_array_tinfo = idaapi.tinfo_t()
                    char_array_tinfo.create_array(idaapi.tinfo_t(idaapi.BTF_CHAR), number)
                    idaapi.update_action_label(RecastItemRight.name, 'Recast Variable "{}" to "{}"'.format(
                        variable.name, char_array_tinfo.dstr()
                    ))
                    return RECAST_LOCAL_VARIABLE, char_array_tinfo, variable


class RenameOther(idaapi.action_handler_t):
    name = "my:RenameOther"
    description = "Take other name"
    hotkey = "Ctrl+N"
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expression = ctree_item.it.to_specific_type
        if expression.op != idaapi.cot_var:
            return

        parent = cfunc.body.find_parent_of(expression).to_specific_type
        if parent.op != idaapi.cot_asg:
            return

        other = parent.theother(expression)
        if other.op != idaapi.cot_var:
            return

        this_lvar = ctree_item.get_lvar()
        other_lvar = cfunc.get_lvars()[other.v.idx]
        if (other_lvar.has_user_name or other_lvar.is_arg_var and re.search("a\d*$", other_lvar.name) is None) \
                and this_lvar.name.lstrip('_') != other_lvar.name.lstrip('_'):
            return '_' + other_lvar.name, this_lvar

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        result = self.check(hx_view.cfunc, hx_view.item)

        if result:
            name, lvar = result
            hx_view.rename_lvar(lvar, name, True)

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class RenameInside(idaapi.action_handler_t):
    name = "my:RenameInto"
    description = "Rename inside argument"
    hotkey = "Shift+N"
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return False

        expression = ctree_item.it.to_specific_type
        if expression.op == idaapi.cot_var:
            lvar = ctree_item.get_lvar()
            # Check if it's either variable with user name or argument with not standard `aX` name
            if lvar.has_user_name or lvar.is_arg_var and re.search("a\d*$", lvar.name) is None:
                parent = cfunc.body.find_parent_of(expression).to_specific_type
                if parent.op == idaapi.cot_call:
                    arg_index, _ = Helper.get_func_argument_info(parent, expression)
                    func_tinfo = parent.x.type.get_pointed_object()
                    func_data = idaapi.func_type_data_t()
                    func_tinfo.get_func_details(func_data)
                    if arg_index < func_tinfo.get_nargs() and lvar.name.lstrip('_') != func_data[arg_index].name:
                        return func_tinfo, parent.x.obj_ea, arg_index, lvar.name.lstrip('_')

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        result = self.check(hx_view.cfunc, hx_view.item)

        if result:
            func_tinfo, address, arg_index, name = result

            func_data = idaapi.func_type_data_t()
            func_tinfo.get_func_details(func_data)
            Helper.fix_automatic_naming(func_data)
            func_data[arg_index].name = name
            new_func_tinfo = idaapi.tinfo_t()
            new_func_tinfo.create_func(func_data)
            idaapi.apply_tinfo2(address, new_func_tinfo, idaapi.TINFO_DEFINITE)
            hx_view.refresh_view(True)

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class RenameOutside(idaapi.action_handler_t):
    name = "my:RenameOutside"
    description = "Take argument name"
    hotkey = "Ctrl+Shift+N"
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return False

        expression = ctree_item.it.to_specific_type
        if expression.op == idaapi.cot_var:
            lvar = ctree_item.get_lvar()
            parent = cfunc.body.find_parent_of(expression).to_specific_type

            if parent.op == idaapi.cot_call:
                arg_index, _ = Helper.get_func_argument_info(parent, expression)
                func_tinfo = parent.x.type.get_pointed_object()
                if func_tinfo.get_nargs() < arg_index:
                    return
                func_data = idaapi.func_type_data_t()
                func_tinfo.get_func_details(func_data)
                name = func_data[arg_index].name
                if name and re.search("a\d*$", name) is None and name != 'this' and name != lvar.name:
                    return name, lvar

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        result = self.check(hx_view.cfunc, hx_view.item)

        if result:
            name, lvar = result
            hx_view.rename_lvar(lvar, name, True)

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class SimpleCreateStruct(idaapi.action_handler_t):
    name = "my:CreateStruct"
    description = "Create simple struct"
    hotkey = "Shift+C"
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        idaname = "ida64" if Const.EA64 else "ida"
        if sys.platform == "win32":
            self.g_dll = ctypes.windll[idaname + ".wll"] if ida_pro.IDA_SDK_VERSION < 700 else ctypes.windll[idaname + ".dll"]
        elif sys.platform == "linux2":
            self.g_dll = ctypes.cdll["lib" + idaname + ".so"]
        elif sys.platform == "darwin":
            self.g_dll = ctypes.cdll["lib" + idaname + ".dylib"]

        self.set_numbered_type = self.g_dll.set_numbered_type
        self.set_numbered_type.argtypes = [
            ctypes.c_void_p,                                    #til_t *ti,
            ctypes.c_int,                                       #uint32 ordinal,
            ctypes.c_int,                                       #int ntf_flags,
            ctypes.c_char_p,                                    #const char *name,
            ctypes.c_char_p,     #const type_t *type,
            ctypes.c_char_p,     #const p_list *fields=NULL,
            ctypes.c_char_p,     #const char *cmt=NULL,
            ctypes.c_char_p,     #const p_list *fldcmts=NULL,
            ctypes.POINTER(ctypes.c_ulong),                     #const sclass_t *sclass=NULL
        ]



    @staticmethod
    def check(cfunc, ctree_item):
        return True

    def create_struct_type(self, struc_size, name, field_size=4, fAllign=True):
        if ida_pro.IDA_SDK_VERSION < 700:
            c_my_til = ctypes.c_void_p.in_dll(self.g_dll, 'idati')
        else:
            c_get_idati = self.g_dll.get_idati
            c_get_idati.restype = ctypes.c_longlong
            c_my_til = c_get_idati()
        my_ti = idaapi.cvar.idati
        c_compact_numbered_types = self.g_dll.compact_numbered_types

        c_compact_numbered_types.argtypes = [
            ctypes.c_longlong,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int
        ]
        def make_field_str(field_num, fsize, pad=0):
            ret = ""
            for i in range(0, field_num):
                ret += struct.pack(">B", len("field_%X" % (i * fsize)) + 1) + "field_%X" % (i * fsize)
            k = 1
            while pad > 0:
                ret += struct.pack(">B", len("field_%X" % (i * fsize + k)) + 1) + "field_%X" % (i * fsize + k)
                pad -= 1
                k += 1
            return ret

        def encode_size(num):
            enc = 0
            if num > 0xF:
                t, pad = divmod(num, 0x10)
                if t < 0x100:
                    enc = 0x8100 | (pad << 11) | t
                    return struct.pack(">BB", enc >> 8, enc & 0xFF)
                else:
                    t1, t2, t3 = (0, 0, 0)
                    t1, pad = divmod(num, 0x400)
                    t3 = pad
                    if pad > 7:
                        t2, t3 = divmod(pad, 8)
                    return "\xFF\xFF" + struct.pack(">BBB", t1 | 0x80, t2 | 0x80, t3 << 3 | 0x40)
            else:
                return struct.pack(">B", num << 3 | 1)

        def decode_size(size_str):
            l = 0
            if size_str[:2] == "\xFF\xFF":
                l += 2
                size_str = size_str[2:]
            b1 = ord(size_str[0])
            l += 1
            if b1 & 0x80:
                b2 = ord(size_str[1])
                l += 1
                if b2 & 0x80:
                    b3 = ord(size_str[2])
                    l += 1
                    if b3 & 0x40:
                        t1 = (b1 & 0x7f) * 0x400
                        t2 = (b2 & 0x7f) * 8
                        t3 = (b3 & 0x3f) >> 3
                        return (l, t1 + t2 + t3)
                    else:
                        return None
                t1 = b2 * 0x10
                t2 = (b1 & 0x7f) >> 3
                return (l, t1 + t2)
            return (l, b1 >> 3)

        def make_type_string(field_num, fsize, pad=0):
            ret = "\x0d" + encode_size(field_num + pad)
            if fsize == 1:
                t = "\x32"
            elif fsize == 2:
                t = "\x03"
            elif fsize == 8:
                t = "\x05"
            else:
                t = "\x07"
            ret += t * field_num
            if pad > 0:
                ret += "\x32" * pad
            return ret

        struct_id = idc.GetStrucIdByName(name)
        type_ord = idaapi.get_type_ordinal(my_ti,name)
        if struct_id != idaapi.BADADDR or type_ord != 0:
            answer = idc.AskYN(0, "A structure for %s already exists. Are you sure you want to remake it?" % name)
            if answer == 1:
                if struct_id != idaapi.BADADDR:
                    idc.DelStruc(struct_id)
            else:
                return
        fields_num, pad = divmod(struc_size, field_size)
        if fAllign and pad:
            fields_num += 1
            pad = 0
        typ_type = ctypes.c_char_p(make_type_string(fields_num, field_size, pad))
        # typ_type = make_type_string(fields_num, field_size, pad)
        typ_fields = ctypes.c_char_p(make_field_str(fields_num, field_size, pad))
        # typ_fields = make_field_str(fields_num, field_size, pad)
        typ_cmt = ctypes.c_char_p("")
        typ_fieldcmts = ctypes.c_char_p("")
        # typ_fieldcmts = ""
        sclass = ctypes.c_ulong(0)
        sclass = ctypes.byref(sclass)
        c_compact_numbered_types(c_my_til,1,0,0)
        # c_my_til = c_get_idati()
        pname = ctypes.c_char_p(name)
        if type_ord != 0:
            idx = type_ord
        else:
            idx = idaapi.alloc_type_ordinal(my_ti)
        ret = self.set_numbered_type(
            c_my_til,
            idx,
            0x5,
            pname,
            typ_type,
            typ_fields,
            typ_cmt,
            typ_fieldcmts,
            sclass
        )
        # tif = idaapi.tinfo_t()
        # tif.deserialize(my_ti,typ_type,typ_fields,typ_fieldcmts)
        # if tif.set_numbered_type(my_ti,idaapi.NTF_REPLACE,idx,name):
        #     if ida_pro.IDA_SDK_VERSION < 700:
        #         ret = 1
        #     else:
        #         ret = 0
        # else:
        #     if ida_pro.IDA_SDK_VERSION < 700:
        #         ret = 0
        #     else:
        #         ret = 1
        if (ida_pro.IDA_SDK_VERSION < 700 and ret != 0) or (ida_pro.IDA_SDK_VERSION >= 700 and ret != 1):
            idaapi.import_type(idaapi.cvar.idati,-1, name)
            sid = idaapi.get_struc_id(name)
            sptr = idaapi.get_struc(sid)
            align_shift = 0
            if fAllign:
                if field_size == 2:
                    align_shift = 1
                elif field_size == 4:
                    align_shift = 2
                elif field_size == 8:
                    align_shift = 3
            idaapi.set_struc_align(sptr, align_shift)
        else:
            Warning("set_numbered_type error")



    def activate(self, ctx):
        vdui = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        vdui.get_current_item(idaapi.USE_KEYBOARD)
        struc_size = 0
        if vdui.item.is_citem() and vdui.item.it.is_expr():
            target_item = vdui.item.e
            if target_item.opname == "num":
                s = idaapi.tag_remove(target_item.cexpr.print1(None)).rstrip("u")
                if s.startswith("0x"):
                    struc_size = int(s,16)
                else:
                    struc_size = int(s,10)

        class SimpleCreateStructForm(idaapi.Form):
            def __init__(self):
                idaapi.Form.__init__(self, r"""STARTITEM 0
        Create struct

        <Struct name:{cStrArg}><Struct size:{numSize}>
        <Field size :{numFieldSize}>                                        <Align:{ckAlign}>{gAlign}>

        """, {
                    'cStrArg': idaapi.Form.StringInput(),
                    'numSize': idaapi.Form.StringInput(swidth=10),
                    'numFieldSize': idaapi.Form.DropdownListControl(
                        items=["1", "2", "4", "8"],
                        readonly=False,
                        selval="8" if  Const.EA64 else "4"),
                    'gAlign': idaapi.Form.ChkGroupControl(("ckAlign",)),
                })

            def Go(self,size = 0):
                self.Compile()
                self.ckAlign.checked = True
                # f.numFieldSize.value = 4
                self.numSize.value = str(size)
                ok = self.Execute()
                # print "Ok = %d"%ok
                if ok == 1:
                    # print sel
                    # print len(sel)
                    return (int(self.numSize.value,16) if self.numSize.value.startswith("0x") else int(self.numSize.value,10), self.cStrArg.value, int(self.numFieldSize.value),
                    self.ckAlign.checked)
                return None
        ret = SimpleCreateStructForm().Go(struc_size)
        if ret is not None:
            self.create_struct_type(*ret)
        return 1

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM

class RecastStructMember(idaapi.action_handler_t):

    name = "my:RecastStructMember"
    description = "Recast Struct Member"
    hotkey = "Shift+M"
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype == idaapi.VDI_EXPR and ctree_item.it.op in (idaapi.cot_memptr, idaapi.cot_memref):
            parent = cfunc.body.find_parent_of(ctree_item.it)
            if parent and parent.op == idaapi.cot_call and parent.cexpr.x.op == idaapi.cot_helper:
                cast_helper = parent.to_specific_type.x.helper
                helpers = ["HIBYTE", "LOBYTE", "BYTE", "HIWORD", "LOWORD"]
                for h in helpers:
                    if cast_helper.startswith(h):
                        return RECAST_HELPER, idaapi.remove_pointer(ctree_item.e.x.type).dstr(), ctree_item.e.m, cast_helper

            rc = Helper.get_branch(cfunc,ctree_item)
            branch_idx = 0
            off_delta = 0
            fDoDeref = False
            if rc:
                return RecastStructMember.process_branch(rc)
            # if rc and rc[branch_idx].op == idaapi.cot_asg:
            #     tmp = RecastStructMember.process_asg_branch(rc)
            #     branch_idx += 1
            #     if rc[branch_idx].op == idaapi.cot_ptr:
            #         fDoDeref = True
            #         branch_idx += 1
            #     if rc[branch_idx].op == idaapi.cot_cast:
            #         new_type = idaapi.remove_pointer(rc[branch_idx].cexpr.type) if fDoDeref else rc[branch_idx].cexpr.type
            #         if rc[branch_idx].cexpr.x.index == rc[-1].index:
            #             struct_name = rc[-1].cexpr.x.type.get_pointed_object().dstr() if rc[-1].op == idaapi.cot_memptr else \
            #                 rc[-1].cexpr.x.type.dstr()
            #             return RECAST_STRUCTURE, struct_name, ctree_item.e.m + off_delta, new_type
            #         branch_idx += 1
            #         if rc[branch_idx].op == idaapi.cot_ref:
            #             branch_idx += 1
            #         if rc[branch_idx].op in (idaapi.cot_add, idaapi.cot_idx):
            #             off_delta = rc[branch_idx].cexpr.y.n._value if rc[branch_idx].cexpr.x.index == rc[branch_idx+1].index \
            #                 else rc[branch_idx].to_specific_type.x.n._value
            #             off_delta = idaapi.remove_pointer(rc[branch_idx].cexpr.type).get_size() * off_delta
            #             if rc[branch_idx].op == idaapi.cot_idx and (rc[branch_idx].cexpr.x.index == rc[-1].index or rc[branch_idx].cexpr.y.index == rc[-1].index):
            #                 struct_name = rc[-1].cexpr.x.type.get_pointed_object().dstr() if rc[-1].op == idaapi.cot_memptr else rc[-1].cexpr.x.type.dstr()
            #                 return RECAST_STRUCTURE, struct_name, ctree_item.e.m + off_delta, new_type
            #             branch_idx += 1
            #             while rc[branch_idx].index != ctree_item.it.index:
            #                 if rc[branch_idx].op not in (idaapi.cot_ref, idaapi.cot_cast, idaapi.cot_ptr):
            #                     return
            #                 branch_idx += 1
            #             struct_name = rc[-1].cexpr.x.type.get_pointed_object().dstr() if rc[-1].op == idaapi.cot_memptr else \
            #                 rc[-1].cexpr.x.type.dstr()
            #             return RECAST_STRUCTURE, struct_name, ctree_item.e.m + off_delta, new_type
            #         if rc[branch_idx].index == rc[-1].index:
            #             struct_name = rc[-1].cexpr.x.type.get_pointed_object().dstr() if rc[-1].op == idaapi.cot_memptr else \
            #                 rc[-1].cexpr.x.type.dstr()
            #             return RECAST_STRUCTURE, struct_name, ctree_item.e.m + off_delta, new_type
            #     elif rc[branch_idx].op == idaapi.cot_add:
            #         off_delta = rc[branch_idx].cexpr.y.n._value if rc[branch_idx].cexpr.x.index == rc[branch_idx + 1].index \
            #             else rc[branch_idx].to_specific_type.x.n._value
            #         off_delta = idaapi.remove_pointer(rc[branch_idx].cexpr.type).get_size() * off_delta
            #         branch_idx += 1
            #         if rc[branch_idx].op == idaapi.cot_ref:
            #             branch_idx += 1
            #         if rc[branch_idx].cexpr.index == rc[-1].index:
            #             struct_name = rc[-1].cexpr.x.type.get_pointed_object().dstr() if rc[-1].op == idaapi.cot_memptr else \
            #                 rc[-1].cexpr.x.type.dstr()
            #             sid = idaapi.get_struc_id(struct_name)
            #             if sid != idaapi.BADADDR:
            #                 sptr = idaapi.get_struc(sid)
            #                 mptr = idaapi.get_member(sptr, ctree_item.e.m + off_delta)
            #                 if mptr is None:
            #                     return RECAST_STRUCTURE, struct_name, ctree_item.e.m + off_delta, rc[0].cexpr.type
            #
            # elif rc and rc[0].op in (idaapi.cot_slt, idaapi.cot_eq):
            #     branch_idx += 1
            #     if rc[branch_idx].op == idaapi.cot_ptr:
            #         fDoDeref = True
            #         branch_idx += 1
            #     if rc[branch_idx].op == idaapi.cot_cast:
            #         new_type = idaapi.remove_pointer(rc[branch_idx].cexpr.type) if fDoDeref else rc[branch_idx].cexpr.type
            #         if rc[branch_idx].cexpr.x.index == rc[-1].index:
            #             struct_name = rc[-1].cexpr.x.type.get_pointed_object().dstr() if rc[-1].op == idaapi.cot_memptr else \
            #                 rc[-1].cexpr.x.type.dstr()
            #             return RECAST_STRUCTURE, struct_name, ctree_item.e.m + off_delta, new_type
            #
            # elif rc and rc[branch_idx].op == idaapi.cot_call:
            #     return RecastStructMember.process_call_branch(rc)
        return

    @staticmethod
    def process_call_branch(nodes,idx = 0):
        target = nodes[-1]
        new_type = None
        fDoDeref = False
        off_delta = 0
        while nodes[idx] != target:
            item = nodes[idx]
            if item.op == idaapi.cot_cast:
                if new_type is None:
                    new_type = item.cexpr.type
            elif item.op == idaapi.cot_ref:
                fDoDeref = True
            elif item.op in (idaapi.cot_add, idaapi.cot_idx):
                if new_type is None and item.op == idaapi.cot_add:
                    new_type = item.cexpr.type
                num = item.cexpr.y.n._value if item.cexpr.x.index == nodes[idx + 1].index else item.to_specific_type.x.n._value
                off_delta += (num * idaapi.remove_pointer(item.cexpr.type).get_size())
            idx += 1
        if new_type:
            struct_name = target.cexpr.x.type.get_pointed_object().dstr() if target.op == idaapi.cot_memptr else \
                target.cexpr.x.type.dstr()
            if fDoDeref or (target.cexpr.type.is_array() and not target.cexpr.type.get_array_element().is_ptr()):
                new_type = idaapi.remove_pointer(new_type)
            return RECAST_STRUCTURE, struct_name, target.cexpr.m + off_delta, new_type

    @staticmethod
    def resolve_references(tp, ref_cnt, ptr_cnt):
        delta = ref_cnt - ptr_cnt
        if delta > 0:
            while delta:
                tp = idaapi.remove_pointer(tp)
                delta -= 1
        elif delta < 0:
            delta = abs(delta)
            while delta:
                tif = idaapi.tinfo_t()
                tif.create_ptr(tp)
                tp = tif
                delta -= 1
        return tp

    @staticmethod
    def process_asg_second_branch(nodes):
        top = nodes[0]
        target = nodes[-1]
        next_node = top.x if top.y.index == nodes[1].index else top.y
        ref_cnt = 0
        ptr_cnt = 0
        new_type = None
        while next_node and next_node.op not in (idaapi.cot_var, idaapi.cot_memptr, idaapi.cot_memref, idaapi.cot_call, idaapi.cot_num):
            if next_node.op == idaapi.cot_ref:
                ref_cnt += 1
            elif next_node.op == idaapi.cot_ptr:
                ptr_cnt += 1
            if next_node.x:
                next_node = next_node.x.cexpr
            else:
                break
        return RecastStructMember.resolve_references(next_node.type, ref_cnt, ptr_cnt)


    @staticmethod
    def process_asg_branch(nodes, idx = 0):
        second_branch_node = nodes[idx].cexpr.x if nodes[idx+1].index == nodes[idx].cexpr.y.index else nodes[idx].cexpr.y
        target = nodes[-1]
        new_type = None
        fDoDeref = False
        ref_cnt = 0
        ptr_cnt = 0
        off_delta = 0
        new_type_second = None
        while second_branch_node and second_branch_node.op not in (idaapi.cot_var,):
            second_branch_node = second_branch_node.cexpr.x
        if second_branch_node:
            new_type_second = second_branch_node.cexpr.type
        while nodes[idx] != target:
            item = nodes[idx]
            if item.op == idaapi.cot_cast:
                if new_type is None:
                    new_type = item.cexpr.type
            elif item.op == idaapi.cot_ref:
                ref_cnt += 1
            elif item.op == idaapi.cot_ptr:
                ptr_cnt += 1
            elif item.op in (idaapi.cot_add, idaapi.cot_idx):
                if new_type is None and item.op == idaapi.cot_add:
                    new_type = item.cexpr.type
                num = item.cexpr.y.n._value if item.cexpr.x.index == nodes[idx + 1].index else item.to_specific_type.x.n._value
                off_delta += (num * idaapi.remove_pointer(item.cexpr.type).get_size())
            idx += 1
        if new_type or (new_type_second and target.cexpr.type.dstr() != new_type_second.dstr()):
            struct_name = target.cexpr.x.type.get_pointed_object().dstr() if target.op == idaapi.cot_memptr else \
                target.cexpr.x.type.dstr()
            new_type = RecastStructMember.resolve_references(new_type,ref_cnt,ptr_cnt)
            if target.cexpr.type.is_array() and not target.cexpr.type.get_array_element().is_ptr():
                new_type = idaapi.remove_pointer(new_type)
            return RECAST_STRUCTURE, struct_name, target.cexpr.m + off_delta, new_type

    @staticmethod
    def process_branch(nodes, idx = 0):
        target = nodes[-1]
        types = collections.OrderedDict()
        opcodes = []
        new_type = None
        asg_type = None
        ref_cnt = 0
        ptr_cnt = 0
        off_delta = 0
        while nodes[idx] != target:
            item = nodes[idx]
            opcodes.append(item.op)
            if item.op == idaapi.cot_cast:
                types[item] = item.cexpr.type
                if new_type is None:
                    new_type = item.cexpr.type
            elif item.op == idaapi.cot_asg:
                # asg_type = item.cexpr.type
                second_type = RecastStructMember.process_asg_second_branch(nodes[idx:])
                if target.type != second_type:
                    types[item] = item.cexpr.type
                    asg_type = second_type
            elif item.op == idaapi.cot_ref:
                ref_cnt += 1
            elif item.op == idaapi.cot_ptr:
                types[item] = item.cexpr.type
                if new_type is None:
                    new_type = item.cexpr.type
                ptr_cnt += 1
            elif item.op in (idaapi.cot_add, idaapi.cot_idx):
                types[item] = item.cexpr.type
                if item.x.op == idaapi.cot_num or item.y.op == idaapi.cot_num:
                    if new_type is None and item.op == idaapi.cot_add:
                        new_type = item.cexpr.type
                    num = item.cexpr.y.n._value if item.cexpr.x.index == nodes[idx + 1].index else item.cexpr.x.n._value
                    off_delta += (num * idaapi.remove_pointer(item.cexpr.type).get_size())
                else:
                    return None
            idx += 1
        if asg_type and new_type is None:
            new_type = asg_type
        if new_type:
            struct_name = target.cexpr.x.type.get_pointed_object().dstr() if target.op == idaapi.cot_memptr else target.cexpr.x.type.dstr()
            new_type = RecastStructMember.resolve_references(new_type,ref_cnt,ptr_cnt)
            if new_type.is_ptr() and idaapi.cot_idx not in opcodes and (Helper.is_gap(struct_name,target.cexpr.m + off_delta) or Helper.get_struct_member_type(struct_name,target.cexpr.m + off_delta).is_array()):
                new_type = new_type.get_pointed_object()
            return RECAST_STRUCTURE, struct_name, target.cexpr.m + off_delta, new_type

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        result = self.check(hx_view.cfunc, hx_view.item)

        if result[0] == RECAST_HELPER:
            struct_name, member_offset, cast_helper = result[1:]
            sid = idaapi.get_struc_id(struct_name)
            if sid != idaapi.BADADDR:
                sptr = idaapi.get_struc(sid)
                mptr = idaapi.get_member(sptr,member_offset)
                member_name = idaapi.get_member_name(mptr.id)
                member_size = idaapi.get_member_size(mptr)
                if cast_helper.startswith("BYTE") or cast_helper in ("HIBYTE", "LOBYTE"):
                    idaapi.del_struc_member(sptr, member_offset)
                    for i in range(member_size):
                        idc.AddStrucMember(sptr.id,member_name if i == 0 else "field_%X"%(member_offset + i), member_offset+i, idaapi.FF_DATA|idaapi.FF_BYTE,idaapi.BADADDR, 1)
                if cast_helper in ("LOWORD","HIWORD"):
                    idaapi.del_struc_member(sptr, member_offset)
                    for i in range(0,member_size,2):
                        idc.AddStrucMember(sptr.id,member_name if i == 0 else "field_%X"%(member_offset + i), member_offset+i, idaapi.FF_DATA|idaapi.FF_WORD,idaapi.BADADDR, 2)
                hx_view.refresh_view(True)

        elif result[0] == RECAST_STRUCTURE:
            structure_name, field_offset, new_type = result[1:]
            sid = idaapi.get_struc_id(structure_name)
            if sid != idaapi.BADADDR:
                sptr = idaapi.get_struc(sid)
                mptr = idaapi.get_member(sptr, field_offset)
                if mptr is None:
                    if idaapi.add_struc_member(sptr, "field_%X" % field_offset, field_offset,
                                               idaapi.FF_DATA | idaapi.FF_BYTE, None, 1) != 0:
                        print "Error on add_struc_member!"
                    mptr = idaapi.get_member(sptr, field_offset)
                elif mptr.soff != field_offset:
                    if not idaapi.del_struc_member(sptr, mptr.soff):
                        print "Error on del_struc_member!"
                    if idaapi.add_struc_member(sptr, "field_%X" % field_offset, field_offset,
                                               idaapi.FF_DATA | idaapi.FF_BYTE, None, 1) != 0:
                        print "Error on add_struc_member!"
                    mptr = idaapi.get_member(sptr, field_offset)
                else:
                    tif = idaapi.tinfo_t()
                    idaapi.get_member_tinfo2(mptr, tif)
                    if tif.is_array():
                        if not idaapi.del_struc_member(sptr, mptr.soff):
                            print "Error on del_struc_member!"
                        if idaapi.add_struc_member(sptr, "field_%X" % field_offset, field_offset,
                                                   idaapi.FF_DATA | idaapi.FF_BYTE, None, 1) != 0:
                            print "Error on add_struc_member!"
                        mptr = idaapi.get_member(sptr, field_offset)
                rc = idaapi.set_member_tinfo2(sptr, mptr, field_offset, new_type,
                                              idaapi.SET_MEMTI_MAY_DESTROY)
                if rc != 1:
                    print ("set_member_tinfo2 rc = %d" % rc)
                hx_view.refresh_view(True)


    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class TakeTypeAsName(idaapi.action_handler_t):

    name = "my:TakeTypeAsName"
    description = "Take Type As Name"
    hotkey = ""
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype == idaapi.VDI_EXPR:
            if ctree_item.it.op in (idaapi.cot_memptr, idaapi.cot_memref):
                tp_name = idaapi.remove_pointer(ctree_item.e.type).dstr()
                struct_name = idaapi.remove_pointer(ctree_item.e.x.type).dstr()
                if idaapi.get_type_ordinal(idaapi.cvar.idati, struct_name) and idaapi.get_type_ordinal(idaapi.cvar.idati, tp_name):
                    sid = idaapi.get_struc_id(struct_name)
                    if sid != idaapi.BADADDR:
                        sptr = idaapi.get_struc(sid)
                        mptr = idaapi.get_member(sptr, ctree_item.e.m)
                        if tp_name not in idaapi.get_member_name2(mptr.id):
                            return True
            elif ctree_item.it.op == idaapi.cot_var:
                lv = cfunc.get_lvars()[ctree_item.e.v.idx]
                lv_type_name = idaapi.remove_pointer(lv.tif).dstr()
                if idaapi.get_type_ordinal(idaapi.cvar.idati,lv_type_name) and lv_type_name not in lv.name:
                    return True

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        item = hx_view.item.e
        if item.op in (idaapi.cot_memptr, idaapi.cot_memref):
            offset = item.m
            tp_name = "p" if item.type.is_ptr() else "o_"
            tp_name = tp_name + idaapi.remove_pointer(item.type).dstr()
            struct_name = idaapi.remove_pointer(item.x.type).dstr()
            sid = idaapi.get_struc_id(struct_name)
            sptr = idaapi.get_struc(sid)
            idaapi.set_member_name(sptr,offset,tp_name)
            hx_view.refresh_view(True)
        elif item.op == idaapi.cot_var:
            lv = hx_view.cfunc.get_lvars()[item.v.idx]
            tp_name = "p" if lv.tif.is_ptr() else "o_"
            tp_name = tp_name + idaapi.remove_pointer(lv.tif).dstr()
            hx_view.rename_lvar(lv,tp_name,True)
            hx_view.refresh_view(True)

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM

class RenameUsingAssertVisitor(idaapi.ctree_parentee_t):

    def __init__(self, cfunc, func_addr, arg_idx):
        idaapi.ctree_parentee_t.__init__(self)
        self.__cfunc = cfunc
        self.__func_addr = func_addr
        self.__arg_idx = arg_idx
        self.__possible_names = set()

    def visit_expr(self, expr):
        if expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_obj and expr.x.obj_ea == self.__func_addr:
            arg_expr = expr.a[self.__arg_idx]
            if arg_expr.op != idaapi.cot_obj:
                logger.error("Argument is not string at {}".format(Helper.to_hex(self._find_asm_address(expr))))
                return 1
            self.__add_func_name(arg_expr)
        return 0

    def process(self):
        self.apply_to(self.__cfunc.body, None)
        if len(self.__possible_names) == 1:
            self.__rename_func()
        else:
            logger.error("Function at {} has more than one candidate for renaming: {}".format(
                Helper.to_hex(self.__cfunc.entry_ea), ", ".join(self.__possible_names)))

    def __add_func_name(self, arg_expr):
        new_name = idc.get_strlit_contents(arg_expr.obj_ea)
        if not idaapi.is_valid_typename(new_name):
            logger.warn("Argument has weird name `{}` at {}".format(
                new_name, Helper.to_hex(self._find_asm_address(arg_expr))))
            return

        self.__possible_names.add(new_name)

    def __rename_func(self):
        idc.set_name(self.__cfunc.entry_ea, self.__possible_names.pop())


class RenameUsingAssert(idaapi.action_handler_t):

    name = "my:RenameUsingAssert"
    description = "Rename as assert argument"
    hotkey = None
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return False

        expression = ctree_item.it.to_specific_type
        if expression.op != idaapi.cot_obj:
            return False

        parent = cfunc.body.find_parent_of(expression).to_specific_type
        if parent.op != idaapi.cot_call or parent.x.op != idaapi.cot_obj:
            return False

        obj_ea = expression.obj_ea
        if not Helper.is_code_ea(obj_ea) and idc.get_str_type(obj_ea) == idc.STRTYPE_C:
            str_potential_name = idc.get_strlit_contents(obj_ea)
            return idaapi.is_valid_typename(str_potential_name)
        return False

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        cfunc = hx_view.cfunc
        ctree_item = hx_view.item
        if not self.check(cfunc, ctree_item):
            return

        expr_arg = ctree_item.it.to_specific_type
        expr_call = cfunc.body.find_parent_of(expr_arg).to_specific_type

        arg_idx, _ = Helper.get_func_argument_info(expr_call, expr_arg)

        assert_ea = expr_call.x.obj_ea
        all_callers = Helper.get_funcs_calling_address(assert_ea)

        for caller_ea in all_callers:
            try:
                cfunc = idaapi.decompile(caller_ea)
                if not cfunc:
                    raise idaapi.DecompilationFailure

                RenameUsingAssertVisitor(cfunc, assert_ea, arg_idx).process()

            except idaapi.DecompilationFailure:
                logger.warn("IDA failed to decompile at {}".format(Helper.to_hex(caller_ea)))

        hx_view.refresh_view(True)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class PropagateName(idaapi.action_handler_t):
    name = "my:PropagateName"
    description = "Propagate name"
    hotkey = "P"
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def callback_start(self):
        hx_view, _ = self._data
        hx_view.switch_to(self._cfunc, False)

    @staticmethod
    def callback_manipulate(self, cexpr, obj):
        if self.crippled:
            logger.debug("Skipping crippled function at {}".format(Helper.to_hex(self._cfunc.entry_ea)))
            return

        if obj.id == Api.SO_GLOBAL_OBJECT:
            old_name = idaapi.get_short_name(cexpr.obj_ea)
            if Settings.PROPAGATE_THROUGH_ALL_NAMES or PropagateName._is_default_name(old_name):
                _, name = self._data
                new_name = PropagateName.rename(lambda x: idaapi.set_name(cexpr.obj_ea, x), name)
                logger.debug("Renamed global variable from {} to {}".format(old_name, new_name))
        elif obj.id == Api.SO_LOCAL_VARIABLE:
            lvar = self._cfunc.get_lvars()[cexpr.v.idx]
            old_name = lvar.name
            if Settings.PROPAGATE_THROUGH_ALL_NAMES or PropagateName._is_default_name(old_name):
                hx_view, name = self._data
                new_name = PropagateName.rename(lambda x: hx_view.rename_lvar(lvar, x, True), name)
                logger.debug("Renamed local variable from {} to {}".format(old_name, new_name))
        elif obj.id in (Api.SO_STRUCT_POINTER, Api.SO_STRUCT_REFERENCE):
            struct_tinfo = cexpr.x.type
            offset = cexpr.m
            struct_tinfo.remove_ptr_or_array()
            old_name = Helper.get_member_name(struct_tinfo, offset)
            if Settings.PROPAGATE_THROUGH_ALL_NAMES or PropagateName._is_default_name(old_name):
                _, name = self._data
                new_name = PropagateName.rename(lambda x: Helper.change_member_name(struct_tinfo.dstr(), offset, x), name)
                logger.debug("Renamed struct member from {} to {}".format(old_name, new_name))

    @staticmethod
    def rename(rename_func, name):
        while not rename_func(name):
            name = "_" + name
        return name

    @staticmethod
    def _is_default_name(string):
        return re.match(r"[av]\d+$", string) is not None or \
               re.match(r"this|[qd]?word|field_|off_", string) is not None

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        obj = Api.ScanObject.create(cfunc, ctree_item)
        if obj and not PropagateName._is_default_name(obj.name):
            return obj

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        obj = self.check(hx_view.cfunc, hx_view.item)
        if obj:
            cfunc = hx_view.cfunc
            visitor = Api.RecursiveObjectDownwardsVisitor(cfunc, obj, (hx_view, obj.name), True)
            visitor.set_callbacks(
                manipulate=PropagateName.callback_manipulate,
                start_iteration=PropagateName.callback_start,
                finish=lambda x: hx_view.switch_to(cfunc, True)
            )
            visitor.process()
            hx_view.refresh_view(True)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class GuessAllocation(idaapi.action_handler_t):
    name = "my:ActionApi"
    description = "Guess allocation"
    hotkey = None
    ForPopup = True

    class StructAllocChoose(Forms.MyChoose):
        def __init__(self, items):
            Forms.MyChoose.__init__(
                self, items, "Possible structure allocations",
                [["Function", 30], ["Variable", 10], ["Line", 50], ["Type", 10]]
            )

        def OnSelectLine(self, n):
            idaapi.jumpto(self.items[n][0])

        def OnGetLine(self, n):
            func_ea, var, line, alloc_type = self.items[n]
            return [Helper.to_nice_str(func_ea), var, line, alloc_type]

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return
        return Api.ScanObject.create(cfunc, ctree_item)

    @staticmethod
    def callback_manipulate(self, cexpr, obj):
        if obj.id == Api.SO_LOCAL_VARIABLE:
            parent = self.parent_expr()
            if parent.op == idaapi.cot_asg:
                alloc_obj = Api.MemoryAllocationObject.create(self._cfunc, self.parent_expr().y)
                if alloc_obj:
                    self._data.append([alloc_obj.ea, obj.name, self._get_line(), "HEAP"])
            elif self.parent_expr().op == idaapi.cot_ref:
                self._data.append([self._find_asm_address(cexpr), obj.name, self._get_line(), "STACK"])
        elif obj.id == Api.SO_GLOBAL_OBJECT:
            self._data.append([self._find_asm_address(cexpr), obj.name, self._get_line(), "GLOBAL"])

    @staticmethod
    def callback_finish(self):
        chooser = GuessAllocation.StructAllocChoose(self._data)
        chooser.Show(False)

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        item = hx_view.item
        obj = GuessAllocation.check(hx_view.cfunc, item)
        if obj:
            visitor = Api.RecursiveObjectUpwardsVisitor(hx_view.cfunc, obj, data=[], skip_after_object=True)
            visitor.set_callbacks(
                manipulate=self.callback_manipulate,
                finish=self.callback_finish
            )
            visitor.process()

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM

class SwapThenElse(idaapi.action_handler_t):
    name = "my:SwapIfElse"
    description = "Swap then/else"
    hotkey = "Shift+S"
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return False

        insn = ctree_item.it.to_specific_type

        if insn.op != idaapi.cit_if or insn.cif.ielse is None:
            return False

        return insn.op == idaapi.cit_if and insn.cif.ielse

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        if self.check(hx_view.cfunc, hx_view.item):
            insn = hx_view.item.it.to_specific_type
            inverse_if(insn.cif)
            hx_view.refresh_ctext()

            InversionInfo(hx_view.cfunc.entry_ea).switch_inverted(insn.ea)

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class ModifyArrayIndexes(idaapi.action_handler_t):

    name = "my:ModifyArrayIndexes"
    description = "Modify Array Indexes"
    hotkey = ""
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(cfunc, ctree_item):
        if ctree_item.citype == idaapi.VDI_EXPR and ctree_item.it.op in (idaapi.cot_memptr, idaapi.cot_memref) and cfunc.body.find_parent_of(ctree_item.it).op == idaapi.cot_idx:
            rc = Helper.get_branch(cfunc,ctree_item)
            if rc:
                for node in rc:
                    if node.op == idaapi.cot_idx:
                        field_info = (node.x.m,node.x.x.type)
                        index = node.y



    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        pass

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM

class FindFieldXrefs(idaapi.action_handler_t):
    name = "my:FindFieldXrefs"
    description = "Field Xrefs"
    hotkey = "Ctrl+X"
    ForPopup = True

    @staticmethod
    def check(cfunc, ctree_item):
        return ctree_item.citype == idaapi.VDI_EXPR and \
               ctree_item.it.to_specific_type.op in (idaapi.cot_memptr, idaapi.cot_memref)

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        item = hx_view.item

        if not self.check(hx_view.cfunc,item):
            return

        data = []
        offset = item.e.m
        struct_type = idaapi.remove_pointer(item.e.x.type)
        ordinal = struct_type.get_ordinal()
        result = XrefStorage().get_structure_info(ordinal, offset)
        for xref_info in result:
            data.append([
                idaapi.get_short_name(xref_info.func_ea) + "+" + hex(int(xref_info.offset)),
                xref_info.type,
                xref_info.line
            ])

        field_name = Helper.get_member_name(struct_type, offset)
        chooser = Forms.MyChoose(
            data,
            "Cross-references to {0}::{1}".format(struct_type.dstr(), field_name),
            [["Function", 20 | idaapi.Choose2.CHCOL_PLAIN],
             ["Type", 2 | idaapi.Choose2.CHCOL_PLAIN],
             ["Line", 40 | idaapi.Choose2.CHCOL_PLAIN]]
        )
        idx = chooser.Show(True)
        if idx == -1:
            return

        xref = result[idx]
        idaapi.open_pseudocode(xref.func_ea + xref.offset, False)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM


class ReplaceLVar(idaapi.action_handler_t):
    name = "my:ReplaceLVar"
    description = "Replace Local Var"
    hotkey = ""
    ForPopup = True

    @staticmethod
    def check(cfunc, ctree_item):

        if ctree_item.citype != idaapi.VDI_EXPR:
            return False
        expression = ctree_item.it.to_specific_type
        if expression.op != idaapi.cot_var:
            return False
        return True

    def activate(self, ctx):
        hx_view = idaapi.get_tform_vdui(ctx.form if ida_pro.IDA_SDK_VERSION < 700 else ctx.widget)
        cfunc = hx_view.cfunc
        item = hx_view.item
        expression = item.it.to_specific_type
        data = []
        lvars = cfunc.get_lvars()
        for i in range(0,len(lvars)):
            if expression.v.idx != i:
                data.append([
                    str(i),
                    lvars[i].name,
                    lvars[i].tif.dstr()
                ])

        chooser = Forms.MyChoose(
            data,
            "Choose local variable to repalce",
            [["idx", 4 | idaapi.Choose2.CHCOL_PLAIN],
            ["Name", 20 | idaapi.Choose2.CHCOL_PLAIN],
             ["Type", 40 | idaapi.Choose2.CHCOL_PLAIN]]
        )
        idx = chooser.Show(True)
        if idx == -1:
            return
        idx = data[idx][0]
        # new_lvar = lvars[idx]
        ea, path = get_closets_ea_with_path(cfunc,expression)
        func_ea = cfunc.entry_ea
        n = Netnode("$HexRaysPyTools:ReplacedLVars")
        # n[func_ea] = {}
        if func_ea not in n:
            n[func_ea] = {}
        l = n[func_ea]
        path.reverse()
        l[ea] = (expression.v.idx, path, int(idx,10))
        n[func_ea] = l
        hx_view.refresh_view(True)

    def update(self, ctx):
        if ida_pro.IDA_SDK_VERSION < 700:
            if ctx.form_title[0:10] == "Pseudocode":
                return idaapi.AST_ENABLE_FOR_FORM
        else:
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
                return idaapi.AST_ENABLE_FOR_FORM
        return idaapi.AST_DISABLE_FOR_FORM

