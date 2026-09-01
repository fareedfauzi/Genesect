# -*- coding: utf-8 -*-
"""Subtle VS Code-style indentation marks for Hex-Rays pseudocode."""
import math

import idaapi
import ida_hexrays
import ida_kernwin
import ida_lines


_hooks_instance = None
_MAX_LINES = 10000
_STYLE_GLYPHS = {"Subtle": "│", "Dotted": "┊", "Strong": "┃"}
_GUIDE_COLOR_NAME = "SCOLOR_AUTOCMT"


def _level_mark(glyph, indent, level):
    """Create a quiet guide using IDA's theme-aware light comment color."""
    color = getattr(ida_lines, _GUIDE_COLOR_NAME, ida_lines.SCOLOR_AUTOCMT)
    return ida_lines.COLSTR(glyph + " " * max(0, indent - 1), color)


def _config():
    from pseudonote_extended.config import CONFIG
    return CONFIG


def _leading_spaces(line):
    plain = ida_lines.tag_remove(line or "")
    return len(plain) - len(plain.lstrip(" "))


def _detect_indent(lines):
    configured = int(getattr(_config(), "indent_guides_width", 0) or 0)
    if configured > 0:
        return max(1, min(configured, 8))
    values = sorted(set(_leading_spaces(line.line) for line in lines if _leading_spaces(line.line) > 0))
    if not values:
        return 2
    candidate = values[0]
    for value in values[1:]:
        candidate = math.gcd(candidate, value)
    if candidate == 1 and len(values) > 1:
        # A one-column GCD is usually caused by aligned continuation arguments,
        # not Hex-Rays' actual BLOCK_INDENT setting.
        divisible_by_two = sum(1 for value in values if value % 2 == 0)
        if divisible_by_two >= max(1, len(values) // 2):
            return 2
    return candidate if 1 <= candidate <= 8 else min(values[0], 8)


def _blank_levels(lines, indent):
    levels = [max(0, _leading_spaces(line.line) // indent) for line in lines]
    if not bool(getattr(_config(), "indent_guides_empty_lines", False)):
        return levels
    for index, line in enumerate(lines):
        if ida_lines.tag_remove(line.line).strip():
            continue
        previous = next((levels[pos] for pos in range(index - 1, -1, -1) if ida_lines.tag_remove(lines[pos].line).strip()), 0)
        following = next((levels[pos] for pos in range(index + 1, len(lines)) if ida_lines.tag_remove(lines[pos].line).strip()), 0)
        levels[index] = min(previous, following) if previous and following else max(previous, following)
    return levels


def apply_indent_guides(lines):
    if not lines or not bool(getattr(_config(), "indent_guides_enabled", True)):
        return
    indent = _detect_indent(lines)
    style = str(getattr(_config(), "indent_guides_style", "Subtle") or "Subtle")
    glyph = _STYLE_GLYPHS.get(style, _STYLE_GLYPHS["Subtle"])
    levels = _blank_levels(lines, indent)
    # IDA 8.3 exposes qstrvec_t through SWIG: integer indexing works, slicing does not.
    for index in range(min(len(lines), _MAX_LINES)):
        line = lines[index]
        level = levels[index]
        if level <= 0:
            continue
        plain = ida_lines.tag_remove(line.line)
        # Empty tagged lines can carry navigation metadata but no replaceable
        # whitespace run. Leave them untouched for a cleaner, safer layout.
        if not plain.strip():
            continue
        if glyph in plain[:level * indent + 2]:
            continue
        leading = _leading_spaces(line.line)
        marks = "".join(_level_mark(glyph, indent, nesting) for nesting in range(level))
        if plain.strip():
            # Hex-Rays prefixes lines with invisible address/color tags, so the raw
            # string rarely starts with its visible whitespace. Find the one intact
            # leading run and replace only that run. Never use a global replacement:
            # it can corrupt color tags; replace never spacing inside code or strings.
            prefix = " " * leading
            raw_offset = line.line.find(prefix)
            if raw_offset >= 0:
                line.line = line.line[:raw_offset] + marks + line.line[raw_offset + leading:]


def indent_guide_hooks_installed():
    return _hooks_instance is not None


def refresh_pseudocode_widget(widget, regenerate=False):
    """Apply marks to an already-cached cfunc and refresh its visible text."""
    vu = ida_hexrays.get_widget_vdui(widget) if widget else None
    if vu:
        try:
            if vu.cfunc and bool(getattr(_config(), "indent_guides_enabled", True)):
                apply_indent_guides(vu.cfunc.get_pseudocode())
            if regenerate:
                # Regenerate once when a late hook is installed so func_printed
                # runs for restored tabs too. IDAGuides uses this refresh path.
                vu.refresh_view(True)
            else:
                vu.refresh_ctext()
        except Exception:
            try:
                vu.refresh_view(True) if regenerate else vu.refresh_ctext()
            except Exception:
                pass
    idaapi.request_refresh(idaapi.IWID_PSEUDOCODE)


def refresh_current_pseudocode():
    refresh_pseudocode_widget(ida_kernwin.get_current_widget())


def refresh_open_pseudocode_widgets(regenerate=False):
    """Refresh every restored pseudocode tab, not only the currently focused one."""
    get_count = getattr(ida_kernwin, "get_widget_qty", None)
    get_widget = getattr(ida_kernwin, "getn_widget", None)
    if not callable(get_count) or not callable(get_widget):
        refresh_current_pseudocode()
        return
    refreshed = False
    try:
        for index in range(int(get_count())):
            widget = get_widget(index)
            if widget and idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE:
                refresh_pseudocode_widget(widget, regenerate=regenerate)
                refreshed = True
    except Exception:
        pass
    if not refreshed:
        refresh_current_pseudocode()


def create_indent_guide_hooks():
    global _hooks_instance
    if _hooks_instance is not None:
        return _hooks_instance
    if not ida_hexrays.init_hexrays_plugin():
        return None

    class _IndentGuideHooks(ida_hexrays.Hexrays_Hooks):
        def __init__(self):
            ida_hexrays.Hexrays_Hooks.__init__(self)

        def func_printed(self, cfunc):
            try:
                if cfunc and bool(getattr(_config(), "indent_guides_enabled", True)):
                    apply_indent_guides(cfunc.get_pseudocode())
            except Exception as exc:
                ida_kernwin.msg("[PseudoNote] Indent mark rendering skipped: %s\n" % exc)
            return 0

        def text_ready(self, vu):
            try:
                if vu and vu.cfunc and bool(getattr(_config(), "indent_guides_enabled", True)):
                    apply_indent_guides(vu.cfunc.get_pseudocode())
            except Exception as exc:
                ida_kernwin.msg("[PseudoNote] Indent mark rendering skipped: %s\n" % exc)
            return 0

    instance = _IndentGuideHooks()
    if not instance.hook():
        return None
    _hooks_instance = instance
    return instance


def destroy_indent_guide_hooks():
    global _hooks_instance
    if _hooks_instance is not None:
        try:
            _hooks_instance.unhook()
        except Exception:
            pass
    _hooks_instance = None


class ToggleIndentGuidesHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        config = _config()
        config.indent_guides_enabled = not bool(getattr(config, "indent_guides_enabled", True))
        config.save()
        create_indent_guide_hooks()
        refresh_current_pseudocode()
        ida_kernwin.msg("[PseudoNote] Indent marks %s\n" % ("enabled" if config.indent_guides_enabled else "disabled"))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
