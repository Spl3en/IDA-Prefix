import os

import idc
import idaapi
import idautils

# ------------------------------------------------------------------------------
# IDA Plugin
# ------------------------------------------------------------------------------

VERSION = "v1.3"  # Fixed for IDA 9.0
AUTHORS = ['Andrew Marumoto', 'Markus Gaasedelen', 'Spl3en']


def PLUGIN_ENTRY():
  """
  Required plugin entry point for IDAPython Plugins.
  """
  return prefix_t()


class prefix_t(idaapi.plugin_t):
  """
  The IDA Plugin for Prefix.
  """

  flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
  help = ""
  comment = "A plugin for easy function prefixing"
  wanted_name = "prefix"
  wanted_hotkey = ""

  # --------------------------------------------------------------------------
  # Plugin Overloads
  # --------------------------------------------------------------------------

  def init(self):
    """
    This is called by IDA when it is loading the plugin.
    """

    # initialize the menu actions our plugin will inject
    self._init_action_bulk()
    self._init_action_clear()

    # initialize plugin hooks
    self._init_hooks()

    # done
    idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
    return idaapi.PLUGIN_KEEP

  def run(self, arg):
    """
    This is called by IDA when this file is loaded as a script.
    """
    idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

  def term(self):
    """
    This is called by IDA when it is unloading the plugin.
    """

    # unhook our plugin hooks
    self._hooks.unhook()

    # unregister our actions & free their resources
    self._del_action_bulk()
    self._del_action_clear()

    # done
    idaapi.msg("%s terminated...\n" % self.wanted_name)

  # --------------------------------------------------------------------------
  # Plugin Hooks
  # --------------------------------------------------------------------------

  def _init_hooks(self):
    """
    Install plugin hooks into IDA.
    """
    self._hooks = Hooks()
    self._hooks.ready_to_run = self._init_hexrays_hooks
    self._hooks.hook()

  def _init_hexrays_hooks(self):
    """
    Install Hex-Rrays hooks (when available).

    NOTE: This is called when the ui_ready_to_run event fires.
    """
    if idaapi.init_hexrays_plugin():
      idaapi.install_hexrays_callback(self._hooks.hxe_callback)

  # --------------------------------------------------------------------------
  # IDA Actions
  # --------------------------------------------------------------------------

  ACTION_BULK = "prefix:bulk"
  ACTION_CLEAR = "prefix:clear"

  def _init_action_bulk(self):
    """
    Register the bulk prefix action with IDA.
    """

    # load the icon for this action
    self._bulk_icon_id = idaapi.load_custom_icon(plugin_resource("bulk.png"))

    # describe the action
    action_desc = idaapi.action_desc_t(
        self.ACTION_BULK,                        # The action name.
        "Prefix selected functions",             # The action text.
        IDACtxEntry(bulk_prefix),                # The action handler.
        None,                                    # Optional: action shortcut
        "Assign a user prefix to the selected functions",  # Optional: tooltip
        self._bulk_icon_id                       # Optional: the action icon
    )

    # register the action with IDA
    assert idaapi.register_action(action_desc), "Action registration failed"

  def _init_action_clear(self):
    """
    Register the clear prefix action with IDA.
    """

    # load the icon for this action
    self._clear_icon_id = idaapi.load_custom_icon(plugin_resource("clear.png"))

    # describe the action
    action_desc = idaapi.action_desc_t(
        self.ACTION_CLEAR,                       # The action name.
        "Clear prefixes",                        # The action text.
        IDACtxEntry(clear_prefix),               # The action handler.
        None,                                    # Optional: action shortcut
        "Clear user prefixes from the selected functions",  # Optional: tooltip
        self._clear_icon_id                      # Optional: the action icon
    )

    # register the action with IDA
    assert idaapi.register_action(action_desc), "Action registration failed"

  def _del_action_bulk(self):
    """
    Delete the bulk prefix action from IDA.
    """
    idaapi.unregister_action(self.ACTION_BULK)
    idaapi.free_custom_icon(self._bulk_icon_id)
    self._bulk_icon_id = idaapi.BADADDR

  def _del_action_clear(self):
    """
    Delete the clear prefix action from IDA.
    """
    idaapi.unregister_action(self.ACTION_CLEAR)
    idaapi.free_custom_icon(self._clear_icon_id)
    self._clear_icon_id = idaapi.BADADDR

# ------------------------------------------------------------------------------
# Plugin Hooks
# ------------------------------------------------------------------------------


class Hooks(idaapi.UI_Hooks):

  def ready_to_run(self):
    """
    UI ready to run -- an IDA event fired when everything is spunup.

    NOTE: this is a placeholder func, it gets replaced on a live instance
    but we need it defined here for IDA 7.2+ to properly hook it.
    """
    pass

  def finish_populating_widget_popup(self, widget, popup):
    """
    A right click menu is about to be shown. (IDA 7)
    """
    inject_prefix_actions(widget, popup, idaapi.get_widget_type(widget))
    return 0

  def hxe_callback(self, event, *args):
    """
    HexRays event callback.

    We lump this under the (UI) Hooks class for organizational reasons.
    """

    # done
    return 0

# ------------------------------------------------------------------------------
# Prefix Wrappers
# ------------------------------------------------------------------------------


def inject_prefix_actions(form, popup, form_type):
  """
  Inject prefix actions to popup menu(s) based on context.
  """

  #
  # disassembly window
  #

  if form_type == idaapi.BWN_DISASMS:

    #
    # if the user cursor isn't hovering over a function ref, there
    # is nothing for us to do
    #

    if get_cursor_func_ref() == idaapi.BADADDR:
      return

  #
  # functions window
  #

  elif form_type == idaapi.BWN_FUNCS:

    # inject the 'Bulk' function prefix action
    idaapi.attach_action_to_popup(
        form,
        popup,
        prefix_t.ACTION_BULK,
        "Bulk prefix functions",
        idaapi.SETMENU_INS
    )

    # inject the 'Clear prefix' action
    idaapi.attach_action_to_popup(
        form,
        popup,
        prefix_t.ACTION_CLEAR,
        "Clear prefix",
        idaapi.SETMENU_INS
    )

    # inject a menu separator
    idaapi.attach_action_to_popup(
        form,
        popup,
        None,
        "Separator",
        idaapi.SETMENU_INS
    )

  # done
  return 0

# ------------------------------------------------------------------------------
# Prefix API
# ------------------------------------------------------------------------------


PREFIX_DEFAULT = "MyPrefix"
PREFIX_SEPARATOR = '::'


def get_selected_funcs(ctx):  # loop through all the functions selected in the 'Functions window' and
  # apply the user defined prefix tag to each one.
  selected_functions = []
  selection = ctx.chooser_selection

  for idx in range(selection.size()):
    function_info = idaapi.get_chooser_data("Functions", selection.at(idx))
    if function_info:
      func_ea = int(function_info[2], 16)
      func_name = function_info[0]
      selected_functions.append((func_ea, func_name))

  return selected_functions


def bulk_prefix(ctx):
  """
  Prefix the Functions window selection with a user defined string.
  """

  # prompt the user for a prefix to apply to the selected functions
  tag = idaapi.ask_str(PREFIX_DEFAULT, 0, "Function Tag")

  # the user closed the window... ignore
  if tag == None:
    return

  # the user put a blank string and hit 'okay'... notify & ignore
  elif tag == '':
    idaapi.warning("[ERROR] Tag cannot be empty [ERROR]")
    return

  # loop through all the functions selected in the 'Functions window' and
  # apply the user defined prefix tag to each one.
  for func_ea, func_name in get_selected_funcs(ctx):
    # ignore functions that already have the specified prefix applied
    if func_name.startswith(tag):
      continue

    # apply the user defined prefix to the function (rename it)
    new_name = '%s%s%s' % (str(tag), PREFIX_SEPARATOR, func_name)
    idaapi.set_name(func_ea, new_name, idaapi.SN_FORCE)

  # refresh the IDA views
  refresh_views()


def clear_prefix(ctx):
  """
  Clear user defined prefixes from the selected functions in the Functions window.
  """

  #
  # loop through all the functions selected in the 'Functions window' and
  # clear any user defined prefixes applied to them.
  #

  for func_ea, func_name in get_selected_funcs(ctx):
    real_name = idaapi.get_name(func_ea)

    #
    # locate the last (rfind) prefix separator in the function name as
    # we will want to keep everything that comes after it
    #

    i = real_name.rfind(PREFIX_SEPARATOR)

    # if there is no prefix (separator), there is nothing to trim
    if i == -1:
      continue

    # trim the prefix off the original function name and discard it
    new_name = real_name[i + len(PREFIX_SEPARATOR):]
    idaapi.set_name(func_ea, new_name, idaapi.SN_NOWARN)

  # refresh the IDA views
  refresh_views()

# ------------------------------------------------------------------------------
# IDA Util
# ------------------------------------------------------------------------------


def refresh_views():
  """
  Refresh the IDA views.
  """

  # refresh IDA views
  idaapi.refresh_idaview_anyway()

  # refresh hexrays
  current_widget = idaapi.get_current_widget()
  vu = idaapi.get_widget_vdui(current_widget)
  if vu:
    vu.refresh_ctext()


def get_all_funcs():
  """
  Enumerate all function names defined in the IDB.
  """
  return set(idaapi.get_func_name(ea) for ea in idautils.Functions())


def get_cursor_func_ref():
  """
  Get the function reference under the user cursor.

  Returns BADADDR or a valid function address.
  """
  current_widget = idaapi.get_current_widget()
  form_type = idaapi.get_widget_type(current_widget)
  vu = idaapi.get_widget_vdui(current_widget)

  #
  # hexrays view is active
  #

  if vu:
    cursor_addr = vu.item.get_ea()

  #
  # disassembly view is active
  #

  elif form_type == idaapi.BWN_DISASM:
    cursor_addr = idaapi.get_screen_ea()
    opnum = idaapi.get_opnum()

    if opnum != -1:

      #
      # if the cursor is over an operand value that has a function ref,
      # use that as a valid rename target
      #

      op_addr = idc.get_operand_value(cursor_addr, opnum)
      op_func = idaapi.get_func(op_addr)

      if op_func and op_func.start_ea == op_addr:
        return op_addr

  # unsupported/unknown view is active
  else:
    return idaapi.BADADDR

  #
  # if the cursor is over a function definition or other reference, use that
  # as a valid rename target
  #

  cursor_func = idaapi.get_func(cursor_addr)
  if cursor_func and cursor_func.start_ea == cursor_addr:
    return cursor_addr

  # fail
  return idaapi.BADADDR


def match_funcs(qt_funcs):
  """
  Convert function names scraped from Qt to their *actual* representation.

  The function names we scrape from the Functions window Qt table actually
  use the underscore character ('_') as a substitute for a variety of
  different characters.

  For example, a function named foo%bar in the IDB will appears as foo_bar
  in the Functions window table.

  This function takes a list of names as they appear in the Functions window
  table such as the following:

      ['foo_bar']

  And applies a best effort lookup to return a list of the 'true' function
  names as they are stored in the IDB.

     ['foo%bar']

  TODO: rewrite this to be more efficient for larger idbs
  TODO: takes first matching function, may want to change it to make the requirements more strict
  """
  res = set()
  ida_funcs = get_all_funcs()
  for f in qt_funcs:
    for f2 in ida_funcs:
      if len(f) == len(f2):
        i = 0
        while i < len(f) and (f[i] == f2[i] or f[i] == '_'):
          i += 1

        if i == len(f):
          res.add(f2)
          break

  return list(res)


class IDACtxEntry(idaapi.action_handler_t):
  """
  A basic Context Menu class to utilize IDA's action handlers.
  """

  def __init__(self, action_function):
    idaapi.action_handler_t.__init__(self)
    self.action_function = action_function

  def activate(self, ctx):
    """
    Execute the embedded action_function when this context menu is invoked.
    """
    self.action_function(ctx)
    return 1

  def update(self, ctx):
    """
    Ensure the context menu is always available in IDA.
    """
    return idaapi.AST_ENABLE_ALWAYS

# ------------------------------------------------------------------------------
# Plugin Util
# ------------------------------------------------------------------------------


PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), prefix_t.wanted_name))


def plugin_resource(resource_name):
  """
  Return the full path for a given plugin resource file.
  """
  return os.path.join(
      PLUGIN_PATH,
      "resources",
      resource_name
  )
