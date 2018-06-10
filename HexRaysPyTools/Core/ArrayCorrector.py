import idaapi
import idc
from HexRaysPyTools.netnode import Netnode

NetnodeName = "$ArrCorrectionInfo"
StorageName = "CorrectionRecords"



PersistentStorage = None
Storage = None


def save_to_persistent():
    if Storage:
        PersistentStorage[StorageName] = Storage

def load_from_persistent():
    global PersistentStorage
    global Storage

    PersistentStorage = Netnode(NetnodeName)
    if StorageName not in PersistentStorage:
        PersistentStorage[StorageName] = []

    Storage = PersistentStorage[StorageName]


class ArrayCorrectorChooser(idaapi.Choose2 if idaapi.IDA_SDK_VERSION < 700 else idaapi.Choose):

    def __init__(self, title, flags=0):

        if idaapi.IDA_SDK_VERSION < 700:
            idaapi.Choose2.__init__(self,
                             title,
                             [["Area start", 10],["Area end", 10],["Offset", 10],["Specific function", 10]],
                             embedded=True, width=40, height=10, flags=flags)
        else:
            idaapi.Choose.__init__(self,
                            title,
                            [["Area start", 10], ["Area end", 10], ["Offset", 10], ["Specific function", 10]],
                            embedded=True, width=40, height=10, flags=flags)
        self.n = 0
        # self.items = [ self.make_item() for x in xrange(0, nb+1) ]
        self.items = []
        self.icon = 5
        self.selected = []

    def OnClose(self):
        pass

    def Close(self):
        print "Trying close"
        pass

    def OnGetLine(self, n):
        #print("getline %d" % n)
        global Storage
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            m = "0x%016X"
        else:
            m = "0x%08X"
        start, end, off, func =  Storage[n]
        start = m%start
        end = m%end
        off = "%d"%off
        func = m%func
        return [start, end, off, func]

    def OnGetSize(self):
        global Storage
        n = len(Storage)
        #print("getsize -> %d" % n)
        return n

    def OnDeleteLine(self, n):
        #print("del %d " % n)
        global Storage
        Storage.pop(n)
        return n

    def OnSelectLine(self, n):
        #print "Selected %d"%n
        #print self.items[n]
        self.selected = [n]

    def OnSelectionChange(self, sel_list):
        self.selected = []
        # print sel_list
        if idaapi.IDA_SDK_VERSION < 700:
            for sel in sel_list:
                self.selected.append(sel-1)
        else:
            if type(sel_list) == int:
                self.selected.append(sel_list)
            else:
                for sel in sel_list:
                    self.selected.append(sel)


class ArrayCorrectorUI(idaapi.Form):
    def __init__(self):
        self.__n = 0
        self.selected = None
        self.EChooser = ArrayCorrectorChooser("Correction records")
        idaapi.Form.__init__(self,
                      r"""
                      Global address corrections.
                      Ctree node cot_obj will be corrected by add Offset value to obj_ea if address of it in specific range.
                      If new address falls into a item's range (array or mapped structure) obj_ea will be setted to item head.
                      Function address is optional. If setted, global will be corrected only in target func.
                  
                      <Correction records:{cEChooser}>   <##Create new record:{iButtonNewRecord}><##Delete Record:{iButtonDelRecord}>
                      """, {
                          'cEChooser': idaapi.Form.EmbeddedChooserControl(self.EChooser),
                          'iButtonNewRecord': idaapi.Form.ButtonInput(self.onNewRecord),
                          'iButtonDelRecord': idaapi.Form.ButtonInput(self.onDelRecord),
                      })

    def Go(self):
        self.Compile()
        ok = self.Execute()
        #print "Ok = %d"%ok
        if ok == 1:
            sel = self.EChooser.selected
            #print sel
            #print len(sel)
            return sel[0]
        return None

    def OnFormChange(self, fid):
        if fid == -1:
            self.SetFocusedField(self.EChooser)

    def onNewRecord(self, code=0):
        global Storage
        class NewRecordUI(idaapi.Form):
            def __init__(self):
                idaapi.Form.__init__(self,
                         r"""
                         <##Start address 0x:{iStart}>
                         <##End address   0x:{iEnd}>
                         <##Offset     (Dec):{iOff}>
                         <##FuncAddress   0x:{iFunc}>
                         """,
                         {
                           "iStart":idaapi.Form.NumericInput(idaapi.Form.FT_RAWHEX,width=100),
                           "iEnd":idaapi.Form.NumericInput(idaapi.Form.FT_RAWHEX,width=100),
                           "iOff":idaapi.Form.NumericInput(idaapi.Form.FT_DEC,width=100),
                           "iFunc":idaapi.Form.NumericInput(idaapi.Form.FT_RAWHEX,width=100),
                         })

            def Go(self):
                self.Compile()
                ok = self.Execute()
                # print "Ok = %d"%ok
                if ok == 1:
                    return [self.iStart.value, self.iEnd.value, self.iOff.value, self.iFunc.value]
                return None

        f = NewRecordUI()
        rc = f.Go()
        if rc:
            Storage.append(rc)
            self.RefreshField(self.controls['cEChooser'])

    def onDelRecord(self,code = 0):
       global Storage
       if len(self.EChooser.selected) > 0:
           for sel in self.EChooser.selected:
               Storage.pop(sel)
           self.RefreshField(self.controls['cEChooser'])

def button_click():
    f = ArrayCorrectorUI()
    f.Go()
    del f


def cfunc_test_manipulation(cfunc):
    nodes = []
    l = cfunc.treeitems
    rc = cfunc.treeitems.size()
    rc = cfunc.body.cblock.size()
    while True:
        n = cfunc.treeitems[0]
        rc = cfunc.treeitems._del(n)
        rc = cfunc.treeitems.size()
        if n is None:
            break
        nodes.append(n)

class ArrayCorrectorVisitorStage1(idaapi.ctree_parentee_t):

    def __init__(self,cfunc = None):
        self.cfunc = cfunc
        self.nodes = []
        super(ArrayCorrectorVisitorStage1, self).__init__()

    def visit_insn(self, ins):
        self.nodes.append(ins)
        return 0

    def visit_expr(self, expression):
        global Storage
        self.nodes.append(expression)
        if expression.op == idaapi.cot_obj:
            for start, end, off, func in Storage:
                if expression.obj_ea >= start and expression.obj_ea <= end:
                    if func and self.cfunc.entry_ea != func:
                        return 0

                    target_ea = expression.obj_ea + off
                    head_ea = idaapi.get_item_head(target_ea)
                    if head_ea != target_ea and idaapi.isStruct(idaapi.getFlags(head_ea)):
                        ref_parent = self.cfunc.body.find_parent_of(expression)
                        if ref_parent.op == idaapi.cot_ref:
                            parent = self.cfunc.body.find_parent_of(ref_parent)
                            if parent.op == idaapi.cot_add:
                                v = target_ea - head_ea
                                num_node = idaapi.make_num(v)
                                num_node.thisown = False
                                num_node.n.thisown = False
                                parent = parent.cexpr
                                # parent.thisown = False
                                tif = idaapi.tinfo_t()
                                if not idaapi.get_tinfo(tif, head_ea):
                                    idaapi.guess_tinfo(tif, head_ea)
                                if parent.x == ref_parent.cexpr:
                                    # ref_parent.thisown = False
                                    # ref_parent.cexpr.thisown = False
                                    ref_parent = parent.x
                                    # expression = ref_parent.x
                                    ref_new = idaapi.cexpr_t(ref_parent)
                                    ref_new.thisown = False
                                    # expression.thisown = False
                                    # expression_new.type.thisown = False
                                    # tif.thisown = False
                                    element_tif = tif.get_ptrarr_object()
                                    element_tif.create_ptr(element_tif)
                                    ref_new.type = element_tif
                                    ref_new.x.type = tif
                                    ref_new.x.obj_ea = head_ea
                                    expr_add = idaapi.cexpr_t(idaapi.cot_add, ref_new, num_node)
                                    expr_add.thisown = False
                                    # expr_add.type = element_tif
                                    ref_parent.cexpr.assign(expr_add)
                                    # parent.x.thisown = False
                                    # parent.x.swap(expr_add)
                                    # ref_parent1 = idaapi.cexpr_t(ref_parent.cexpr)
                                    # parent.x.swap(ref_parent1)
                                elif parent.y == ref_parent.cexpr:
                                    ref_parent.thisown = False
                                    ref_parent.cexpr.thisown = False
                                    ref_parent = idaapi.cexpr_t(ref_parent.cexpr)
                                    expression.thisown = False
                                    expression = idaapi.cexpr_t(expression)
                                    ref_parent.x.replace_by(expression)
                                    expr_add = idaapi.cexpr_t(idaapi.cot_add, ref_parent, num_node)
                                    parent.y.thisown = False
                                    parent.y.replace_by(expr_add)
                                else:
                                    print "FUCK!"


                                rc = self.recalc_parent_types()
                        # parent = self.nodes[-2]
                        # parent = self.nodes[-3]
                        # parent = self.nodes[-4]
        return 0

class ArrayCorrectorVisitorStage2(idaapi.ctree_parentee_t):
   def __init__(self, cfunc=None):
       self.cfunc = cfunc
       self.nodes = []
       super(ArrayCorrectorVisitorStage2, self).__init__()

   def visit_expr(self, expression):
       global Storage
       if expression.op == idaapi.cot_obj:
           for start, end, off, func in Storage:
               if expression.obj_ea >= start and expression.obj_ea <= end:
                   if func and self.cfunc.entry_ea != func:
                       return 0

                   parent = self.cfunc.body.find_parent_of(expression)
                   if parent.op != idaapi.cot_idx:
                       return 0
                   parent = self.cfunc.body.find_parent_of(parent)
                   if parent.op != idaapi.cot_memref:
                       return 0
                   target_ea = expression.obj_ea + off
                   head_ea = idaapi.get_item_head(target_ea)
                   if head_ea != target_ea and idaapi.isStruct(idaapi.getFlags(head_ea)):
                       parent.cexpr.m = target_ea - head_ea
                       expression.obj_ea = head_ea
                       rc = self.recalc_parent_types()
                       return 0
       return 0


