import idaapi

from . import actions
import HexRaysPyTools.core.cache as cache
import HexRaysPyTools.core.classes as classes
from HexRaysPyTools.core.structure_graph import StructureGraph
from HexRaysPyTools.forms import StructureGraphViewer, ClassViewer, StructureBuilder
from ..settings import get_config
from HexRaysPyTools.log import Log, LogLevel
logger = Log.get_logger()
from HexRaysPyTools.core.struct_xrefs import XrefStorage
from HexRaysPyTools.core.temporary_structure import TemporaryStructureModel
from HexRaysPyTools.core.rename_hooks import rename_hook
from HexRaysPyTools.callbacks.export_pseudocode import ExportPseudocodeAction


class ShowGraph(actions.Action):
    description = "Show graph"
    hotkey = "G"

    def __init__(self):
        super(ShowGraph, self).__init__()
        self.graph = None
        self.graph_view = None

    def activate(self, ctx):
        widget = self.graph_view.GetWidget() if self.graph_view else None
        if widget:
            self.graph_view.change_selected([sel + 1 for sel in ctx.chooser_selection])
            self.graph_view.Show()
        else:
            self.graph = StructureGraph([sel + 1 for sel in ctx.chooser_selection])
            self.graph_view = StructureGraphViewer("Structure Graph", self.graph)
            self.graph_view.Show()

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_LOCTYPS:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name)
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET





class ShowClasses(actions.Action):
    description = "Classes"
    hotkey = "Alt+F1"

    def __init__(self):
        super(ShowClasses, self).__init__()

    def activate(self, ctx):
        tform = idaapi.find_widget('Classes')
        if not tform:
            class_viewer = ClassViewer(classes.ProxyModel(), classes.TreeModel())
            class_viewer.Show()
        else:
            idaapi.activate_widget(tform, True)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


show_classes = ShowClasses()
actions.action_manager.register(show_classes)
idaapi.attach_action_to_menu('View/Open subviews/Local types', show_classes.name, idaapi.SETMENU_APP)


class ShowStructureBuilder(actions.HexRaysPopupAction):
    description = "Show Structure Builder"
    hotkey = "Alt+F8"

    def __init__(self):
        super(ShowStructureBuilder, self).__init__()

    def check(self, hx_view):
        return True

    def activate(self, ctx):
        tform = idaapi.find_widget("Structure Builder")
        if tform:
            idaapi.activate_widget(tform, True)
        else:
            StructureBuilder(cache.temporary_structure).Show()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

show_classes = ShowClasses()
actions.action_manager.register(show_classes)
idaapi.attach_action_to_menu('View/Open subviews/Local types', show_classes.name, idaapi.SETMENU_APP)

if get_config().get_opt("Main plugins UI forms", "ShowGraph"):
    actions.action_manager.register(ShowGraph())
if get_config().get_opt("Main plugins UI forms", "ShowGraph"):
    actions.action_manager.register(ShowGraph())
actions.action_manager.register(ShowStructureBuilder())

# 注册导出伪代码动作
export_pseudocode = ExportPseudocodeAction()
actions.action_manager.register(export_pseudocode)	