import ida_frame
import ida_struct
import collections
import logging

import idaapi
import idautils
import idc
# import Const

import re
import HexRaysPyTools.Core.Cache as Cache
import HexRaysPyTools.Core.Const as Const
import HexRaysPyTools.Settings as Settings

temporary_structure = None
demangled_names = {}
potential_negatives = {}
name_regex = re.compile(r"^a[\d]*[a]?$")
logger = logging.getLogger(__name__)


def is_imported_ea(ea):
    if idc.get_segm_name(ea) == ".plt":
        return True
    return ea in Cache.imported_ea


def is_code_ea(ea):
    flags = idaapi.getFlags(ea)  # flags_t
    return idaapi.isCode(flags)


def is_rw_ea(ea):
    seg = idaapi.getseg(ea)
    return seg.perm & idaapi.SEGPERM_WRITE and seg.perm & idaapi.SEGPERM_READ


def init_demangled_names(*args):
    """
    Creates dictionary of demangled names => address, that will be used further at double click on methods got from
    symbols.
    """
    demangled_names.clear()
    for address, name in idautils.Names():
        short_name = idc.Demangle(name, idc.GetLongPrm(idc.INF_SHORT_DN))
        if short_name:
            demangled_names[short_name.split('(')[0]] = address - idaapi.get_imagebase()

            # Names can have templates and should be transformed before creating local type
            name = re.sub(r'[<>]', '_t_', name)

            # Thunk functions with name like "[thunk]:CWarmupHostProvider::Release`adjustor{8}'"
            result = re.search(r"(\[thunk\]:)?([^`]*)(.*\{(\d+)}.*)?", short_name)
            name, adjustor = result.group(2), result.group(4)
            if adjustor:
                demangled_names[name + "_adj_" + adjustor] = address - idaapi.get_imagebase()

    print "[DEBUG] Demangled names have been initialized"

def is_func_call(item,cfunc):
    if type(item) is idaapi.ctree_item_t:
        item = item.it
    while True:
        parent = cfunc.body.find_parent_of(item)
        if not parent or not parent.is_expr() or parent.to_specific_type.x.index != item.index:
            return False
        elif parent.op == idaapi.cot_call:
            return True
        item = parent

def is_func_arg(item,cfunc):
    if type(item) is idaapi.ctree_item_t:
        item = item.it
    while True:
        parent = cfunc.body.find_parent_of(item)
        if not parent or not parent.is_expr():
            return False
        elif parent.op == idaapi.cot_call and parent.to_specific_type.x.index != item.index:
            return True
        item = parent

def get_nodes_to_call_parent(item,cfunc):
    if type(item) is idaapi.ctree_item_t:
        item = item.it
    rc = [item]
    while True:
        parent = cfunc.body.find_parent_of(item)
        if not parent or not parent.is_expr():
            return None
        rc.append(parent)
        if parent.op == idaapi.cot_call:
            rc.reverse()
            return rc
        item = parent

def get_up_branch_to_op(cfunc,item,ops):
    if type(item) is idaapi.ctree_item_t:
        item = item.it
    rc = [item]
    while True:
        parent = cfunc.body.find_parent_of(item)
        if not parent or not parent.is_expr():
            return None
        rc.append(parent)
        if parent.op in ops:
            rc.reverse()
            return rc
        item = parent

def get_branch(cfunc,item):
    if type(item) is idaapi.ctree_item_t:
        item = item.it
    rc = [item.cexpr]
    while True:
        parent = cfunc.body.find_parent_of(item)
        if not parent or not parent.is_expr():
            break
        rc.append(parent.cexpr)
        item = parent
    rc.reverse()
    return rc

def get_virtual_func_address(name, tinfo=None, offset=None):
    """
    :param name: method name
    :param tinfo: class tinfo
    :param offset: virtual table offset
    :return: address of the method
    """
    # address = idaapi.BADADDR
    # if name in idautils.Functions():
    address = idc.LocByName(name) #fucking idaapi. It's function work incorrectly. This returned 0xFF005BE7 instead BADADDR in some cases. get_name_ea problem.

    if address != idaapi.BADADDR:
        return address

    address = Cache.demangled_names.get(name, idaapi.BADADDR)
    if address != idaapi.BADADDR:
        return address + idaapi.get_imagebase()

    if tinfo is None or offset is None:
        return

    offset *= 8
    udt_member = idaapi.udt_member_t()
    while tinfo.is_struct():
        address = Cache.demangled_names.get(tinfo.dstr() + '::' + name, idaapi.BADADDR)
        if address != idaapi.BADADDR:
            return address + idaapi.get_imagebase()
        udt_member.offset = offset
        tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
        tinfo = udt_member.type
        offset = offset - udt_member.offset


def get_func_argument_info(function, expression):
    """
    Function is cexpr with opname == 'cot_call', expression is any son. Returns index of argument and it's type

    :param function: idaapi.cexpr_t
    :param expression: idaapi.cexpr_t
    :return: (int, idaapi.tinfo_t)
    """
    for idx, argument in enumerate(function.a):
        if expression == argument.cexpr:
            func_tinfo = function.x.type
            if idx < func_tinfo.get_nargs():
                return idx, func_tinfo.get_nth_arg(idx)
            return idx, None
    print "[ERROR] Wrong usage of 'Helper.get_func_argument_info()'"


def set_func_argument(func_tinfo, index, arg_tinfo):
    func_data = idaapi.func_type_data_t()
    func_tinfo.get_func_details(func_data)
    func_data[index].type = arg_tinfo
    func_tinfo.create_func(func_data)


def set_funcptr_argument(funcptr_tinfo, index, arg_tinfo):
    func_tinfo = funcptr_tinfo.get_pointed_object()
    set_func_argument(func_tinfo, index, arg_tinfo)
    funcptr_tinfo.create_ptr(func_tinfo)


def get_nice_pointed_object(tinfo):
    """
    Returns nice pointer name (if exist) or None.
    For example if tinfo is PKSPIN_LOCK which is typedef of unsigned int *, then if in local types exist KSPIN_LOCK with
    type unsigned int, this function returns KSPIN_LOCK
    """
    try:
        name = tinfo.dstr()
        if name[0] == 'P':
            pointed_tinfo = idaapi.tinfo_t()
            if pointed_tinfo.get_named_type(idaapi.cvar.idati, name[1:]):
                if tinfo.get_pointed_object().equals_to(pointed_tinfo):
                    return pointed_tinfo
    except TypeError:
        pass


def get_fields_at_offset(tinfo, offset):
    """
    Given tinfo and offset of the structure or union, returns list of all tinfo at that offset.
    This function helps to find appropriate structures by type of the offset
    """
    result = []
    if offset == 0:
        result.append(tinfo)
    udt_data = idaapi.udt_type_data_t()
    tinfo.get_udt_details(udt_data)
    udt_member = idaapi.udt_member_t()
    udt_member.offset = offset * 8
    idx = tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
    if idx != -1:
        while idx < tinfo.get_udt_nmembers() and udt_data[idx].offset <= offset * 8:
            udt_member = udt_data[idx]
            if udt_member.offset == offset * 8:
                if udt_member.type.is_ptr():
                    result.append(idaapi.get_unk_type(Const.EA_SIZE))
                    result.append(udt_member.type)
                    result.append(idaapi.dummy_ptrtype(Const.EA_SIZE, False))
                elif not udt_member.type.is_udt():
                    result.append(udt_member.type)
            if udt_member.type.is_array():
                if (offset - udt_member.offset / 8) % udt_member.type.get_array_element().get_size() == 0:
                    result.append(udt_member.type.get_array_element())
            elif udt_member.type.is_udt():
                result.extend(get_fields_at_offset(udt_member.type, offset - udt_member.offset / 8))
            idx += 1
    return result


def is_legal_type(tinfo):
    tinfo.clr_const()
    if tinfo.is_ptr() and tinfo.get_pointed_object().is_forward_decl():
        return tinfo.get_pointed_object().get_size() == idaapi.BADSIZE
    return Settings.SCAN_ANY_TYPE or bool(filter(lambda x: x.equals_to(tinfo), Const.LEGAL_TYPES))


def search_duplicate_fields(udt_data):
    # Returns list of lists with duplicate fields

    default_dict = collections.defaultdict(list)
    for idx, udt_member in enumerate(udt_data):
        default_dict[udt_member.name].append(idx)
    return [indices for indices in default_dict.values() if len(indices) > 1]

def is_gap(structure_name,field_offset):
    sid = idaapi.get_struc_id(structure_name)
    if sid != idaapi.BADADDR:
        sptr = idaapi.get_struc(sid)
        mptr = idaapi.get_member(sptr, field_offset)
        if mptr:
            return False
        else:
            return True


def get_struct_member_type(structure_name, field_offset):
    sid = idaapi.get_struc_id(structure_name)
    if sid != idaapi.BADADDR:
        sptr = idaapi.get_struc(sid)
        mptr = idaapi.get_member(sptr, field_offset)
        if mptr:
            tif = idaapi.tinfo_t()
            idaapi.get_member_tinfo2(mptr, tif)
            return tif
        return None


touched_functions = set()

def get_member_name(tinfo, offset):
    udt_member = idaapi.udt_member_t()
    udt_member.offset = offset * 8
    tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)
    return udt_member.name


def change_member_name(struct_name, offset, name):
    return idc.set_member_name(idc.get_struc_id(struct_name), offset, name)


def import_structure(name, tinfo):
    cdecl_typedef = idaapi.print_tinfo(None, 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI,
                                       tinfo, name, None)
    if idc.parse_decl(cdecl_typedef, idaapi.PT_TYP) is None:
        return 0

    previous_ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, name)
    if previous_ordinal:
        idaapi.del_numbered_type(idaapi.cvar.idati, previous_ordinal)
        ordinal = idaapi.idc_set_local_type(previous_ordinal, cdecl_typedef, idaapi.PT_TYP)
    else:
        ordinal = idaapi.idc_set_local_type(-1, cdecl_typedef, idaapi.PT_TYP)
    return ordinal


def get_funcs_calling_address(ea):
    """ Returns all addresses of functions which make call to a function at `ea`"""
    xref_ea = idaapi.get_first_cref_to(ea)
    xrefs = set()
    while xref_ea != idaapi.BADADDR:
        xref_func_ea = idc.GetFunctionAttr(xref_ea, idc.FUNCATTR_START)
        if xref_func_ea != idaapi.BADADDR:
            xrefs.add(xref_func_ea)
        else:
            print "[Warning] Function not found at 0x{0:08X}".format(xref_ea)
        xref_ea = idaapi.get_next_cref_to(ea, xref_ea)
    return xrefs

class FunctionTouchVisitor(idaapi.ctree_parentee_t):
    def __init__(self, cfunc):
        super(FunctionTouchVisitor, self).__init__()
        self.functions = set()
        self.cfunc = cfunc

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_call:
            self.functions.add(expression.x.obj_ea)
        return 0

    def touch_all(self):
        diff = self.functions.difference(Cache.touched_functions)
        for address in diff:
            if is_imported_ea(address):
                continue
            try:
                cfunc = idaapi.decompile(address)
                if cfunc:
                    FunctionTouchVisitor(cfunc).process()
            except idaapi.DecompilationFailure:
                logger.warn("IDA failed to decompile function at {}".format(to_hex(address)))
                Cache.touched_functions.add(address)
        idaapi.decompile(self.cfunc.entry_ea)

    def process(self):
        if self.cfunc.entry_ea not in Cache.touched_functions:
            Cache.touched_functions.add(self.cfunc.entry_ea)
            self.apply_to(self.cfunc.body, None)
            self.touch_all()
            return True
        return False


def fix_automatic_naming(func_data):

    for i in range(0, len(func_data)):
        if name_regex.match(func_data[i].name):
            func_data[i].name = ""




    # fn_ea = vu.cfunc.entry_ea
    # fn = idaapi.get_func(fn_ea)
    # frame = idaapi.get_frame(fn)
    # end_off = idaapi.frame_off_savregs(fn)
    #
    # for i in range(0, frame.memqty):
    #     member = frame.get_member(i)
    #     off = member.soff
    #     if off >= end_off:
    #         break
    #     name = idaapi.get_member_name(member.id)
    #     if name_regex.match(name):
    #         ida_struct.set_member_name(frame, off, ida_frame.build_stkvar_name(fn, off))

def to_hex(ea):
    """ Formats address so it could be double clicked at console """
    if Const.EA64:
        return "0x{:016X}".format(ea)
    return "0x{:08X}".format(ea)


def to_nice_str(ea):
    """ Shows address as function name + offset """
    func_start_ea = idc.get_func_attr(ea, idc.FUNCATTR_START)
    func_name = idc.Name(func_start_ea)
    offset = ea - func_start_ea
    return "{}+0x{:X}".format(func_name, offset)


def save_long_str_to_idb(array_name, value):
    """ Overwrites old array completely in process """
    id = idc.get_array_id(array_name)
    if id != -1:
        idc.delete_array(id)
    id = idc.create_array(array_name)
    r = []
    for idx in xrange(len(value) / 1024 + 1):
        s = value[idx * 1024: (idx + 1) * 1024]
        r.append(s)
        idc.set_array_string(id, idx, s)


def load_long_str_from_idb(array_name):
    id = idc.get_array_id(array_name)
    if id == -1:
        return None
    max_idx = idc.get_last_index(idc.AR_STR, id)
    result = [idc.get_array_element(idc.AR_STR, id, idx) for idx in xrange(max_idx + 1)]
    return "".join(result)


# ======================================================================
# Functions that extends IDA Pro capabilities
# ======================================================================


def _find_asm_address(self, cexpr):
    """ Returns most close virtual address corresponding to cexpr """

    ea = cexpr.ea
    if ea != idaapi.BADADDR:
        return ea

    for p in reversed(self.parents):
        if p.ea != idaapi.BADADDR:
            return p.ea


def my_cexpr_t(*args, **kwargs):
    """ Replacement of bugged cexpr_t() function """

    if len(args) == 0:
        return idaapi.cexpr_t()

    if len(args) != 1:
        raise NotImplementedError

    cexpr = idaapi.cexpr_t()
    cexpr.thisown = False
    if type(args[0]) == idaapi.cexpr_t:
        cexpr.assign(args[0])
    else:
        op = args[0]
        cexpr._set_op(op)

        if 'x' in kwargs:
            cexpr._set_x(kwargs['x'])
        if 'y' in kwargs:
            cexpr._set_y(kwargs['y'])
        if 'z' in kwargs:
            cexpr._set_z(kwargs['z'])
    return cexpr


def extend_ida():
    idaapi.ctree_parentee_t._find_asm_address = _find_asm_address


def get_path_letter(parent, child):
    if 1 <= parent.op <= 15 or 17 <= parent.op <= 45 or parent.op == 58:
        if parent.x.index == child.index:
            return "x"
        else:
            return "y"
    elif (46 <= parent.op <= 60 or parent.op == 67) and parent.op not in (57,58):
        return "x"
    elif parent.op == 16:
        if parent.x.index == child.index:
            return "x"
        elif parent.y.index == child.index:
            return "y"
        else:
            return "z"
    elif parent.op == 57:
        if parent.x.index == child.index:
            return "x"
        else:
            args = parent.a
            for i in range(0,len(args)):
                if args[i].index == child.index:
                    return "a%d"%i
    elif parent.op in (61,62,63,64,65,68,69):
        return "e"
    else:
        return "u"


def get_closets_ea_with_path(cfunc,item):
    path = [("e",idaapi.cot_var)]
    expr = item.to_specific_type
    while expr.ea == idaapi.BADADDR:
        parent = cfunc.body.find_parent_of(expr).to_specific_type
        path.append((get_path_letter(parent,expr),parent.op))
        expr = parent
    return expr.ea, path
