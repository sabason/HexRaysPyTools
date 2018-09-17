import idaapi
from HexRaysPyTools.netnode import Netnode

def traverse_path(item,path):
    cur = item.to_specific_type
    for step, op in path:
        if step == "e":
            return cur
        elif step == "x":
            cur = cur.x
        elif step == "y":
            cur = cur.y
        elif step == "z":
            cur = cur.z
        elif len(step) > 1 and step[0] == "a":
            cur = cur.a[int(step[1],10)]
    return cur

def clear_persist_storage():
    n = Netnode("$HexRaysPyTools:ReplacedLVars")
    n.kill()

def process_replace_lvars(cfunc):

    n = Netnode("$HexRaysPyTools:ReplacedLVars")
    if cfunc.entry_ea in n:
        l = n[cfunc.entry_ea]
        for target_ea in l:
            target_idx, path, new_idx = l[target_ea]
            target_ea = int(target_ea,10)
            visitor = ReplaceLVarVisitor(cfunc)
            nodes = visitor.process()
            for node in nodes:
                if node.is_expr() and node.ea == target_ea and node.op == path[0][1]:
                    node = traverse_path(node,path)
                    if node.op == idaapi.cot_var and node.v.idx == target_idx:
                        node.to_specific_type.v.idx = new_idx
                        break
            visitor.recalc_parent_types()
                    # v = cfunc.treeitems[target_item.index].to_specific_type
                    # print v.v.idx


class ReplaceLVarVisitor(idaapi.ctree_parentee_t):
    def __init__(self, cfunc=None):
        self.cfunc = cfunc
        self.nodes = []
        super(ReplaceLVarVisitor, self).__init__()

    def visit_expr(self, expression):
        self.nodes.append(expression)
        return 0

    def process(self):
        self.apply_to_exprs(self.cfunc.body, None)
        return self.nodes


class ReplaceLVarChooser(idaapi.Choose):

    def __init__(self, title, obj, flags=0):
        idaapi.Choose.__init__(self,
                               title,
                               [["Func addr",10], ["Target addr", 10], ["Target lvar idx", 10], ["New lvar idx", 10], ["Path", 10]],
                               embedded=True, width=50, height=10, flags=flags|idaapi.Choose.CH_CAN_REFRESH|idaapi.Choose.CH_CAN_DEL)
        self.n = 0
        self.obj = obj
        # self.items = [ self.make_item() for x in xrange(0, nb+1) ]
        self.items = []
        self.icon = 5
        self.selected = []
        self.populate_items()

    def populate_items(self):
        import pydevd
        # pydevd.settrace('localhost', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
        self.items = []
        n = Netnode("$HexRaysPyTools:ReplacedLVars")
        for func_ea in n.keys():
            l = n[func_ea]
            if type(func_ea) == int:
                func_ea = str(func_ea)
            for target_ea in l:
                target_idx, path, new_idx = l[target_ea]
                if type(target_ea) == int:
                    target_ea = str(target_ea)
                self.items.append([func_ea, target_ea, str(target_idx), str(new_idx), str(path)])

    def OnClose(self):
        pass

    def Close(self):
        print "Trying close"
        pass

    def OnGetLine(self, n):
        # print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        # print("getsize -> %d" % n)
        return n

    def OnDeleteLine(self, n):
        # print("del %d " % n)
        func_ea, target_ea, target_idx, new_idx, path = self.items[n]
        func_ea = int(func_ea,10)
        net = Netnode("$HexRaysPyTools:ReplacedLVars")
        if func_ea in net:
            l = net[func_ea]
            if target_ea in l:
                del l[target_ea]
                net[func_ea] = l
                if len(net[func_ea]) == 0:
                    del net[func_ea]
                self.items.pop(n)
                self.obj.RefreshField(self.obj.controls['cEChooser'])
        return n

    def OnSelectLine(self, n):
        # print "Selected %d"%n
        # print self.items[n]
        self.selected = [n]

    def OnSelectionChange(self, sel_list):
        self.selected = []
        # print sel_list
        if type(sel_list) == int:
            self.selected.append(sel_list)
        else:
            for sel in sel_list:
                self.selected.append(sel)



class  ReplaceLVarUI(idaapi.Form):
    def __init__(self):
        self.__n = 0
        self.selected = None
        self.EChooser = ReplaceLVarChooser("Replaced lvars list",self)
        idaapi.Form.__init__(self,
                             r"""       
                             <Local Vars:{cEChooser}>   <##Clear all:{iButtonClearAll}>
                             """, {
                                 'cEChooser': idaapi.Form.EmbeddedChooserControl(self.EChooser),
                                 'iButtonClearAll': idaapi.Form.ButtonInput(self.clear_all)
                             })

    def Go(self):
        self.Compile()
        ok = self.Execute()
        # print "Ok = %d"%ok
        if ok == 1:
            sel = self.EChooser.selected
            # print sel
            # print len(sel)
            if len(sel) > 0:
                return sel[0]
            else:
                return None
        return None

    def OnFormChange(self, fid):
        if fid == -1:
            self.SetFocusedField(self.EChooser)

    def clear_all(self, code=0):
        net = Netnode("$HexRaysPyTools:ReplacedLVars")
        net.kill()
        self.EChooser.populate_items()
        self.RefreshField(self.controls['cEChooser'])

def ReplaceLVar_button_click():
    f = ReplaceLVarUI()
    f.Go()
    del f