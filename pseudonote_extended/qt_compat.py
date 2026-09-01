# -*- coding: utf-8 -*-
"""
Qt compatibility layer for PseudoNote.
Handles Qt 5/6 across PyQt5, PySide2, PySide6, and PyQt6.
"""

import importlib
import sys

QtWidgets = None
QtCore = None
QtGui = None
QtPrintSupport = None
QT_BINDING = None
QT_MAJOR = 0

def _try_import(backend):
    global QtWidgets, QtCore, QtGui, QtPrintSupport, QT_BINDING, QT_MAJOR
    try:
        QtWidgets = importlib.import_module(f"{backend}.QtWidgets")
        QtCore = importlib.import_module(f"{backend}.QtCore")
        QtGui = importlib.import_module(f"{backend}.QtGui")
    except ImportError:
        return False
    QT_BINDING = backend
    QT_MAJOR = 6 if backend in ("PySide6", "PyQt6") else 5
        
    try:
        QtPrintSupport = importlib.import_module(f"{backend}.QtPrintSupport")
    except ImportError:
        QtPrintSupport = None
        
    return True

SUPPORTED_QT_BINDINGS = ("PySide6", "PyQt6", "PyQt5", "PySide2")
_loaded_binding = next((name for name in SUPPORTED_QT_BINDINGS if name in sys.modules), None)
_binding_candidates = ((_loaded_binding,) if _loaded_binding else ()) + tuple(
    name for name in SUPPORTED_QT_BINDINGS if name != _loaded_binding
)
for _binding_name in _binding_candidates:
    if _try_import(_binding_name):
        break
else:
    print("[PseudoNote] Qt not found (PySide6, PyQt6, PyQt5 or PySide2 required).")

# Flattening for easier imports
def _export_module_safe(mod):
    if mod:
        for k in dir(mod):
            if not k.startswith('__'):
                try:
                    globals()[k] = getattr(mod, k)
                except Exception:
                    pass

_export_module_safe(QtWidgets)
_export_module_safe(QtGui)
_export_module_safe(QtCore)
_export_module_safe(QtPrintSupport)


def _install_attr(owner, name, value):
    if owner is None or value is None or hasattr(owner, name):
        return
    try:
        setattr(owner, name, value)
    except (AttributeError, TypeError):
        pass


def _flatten_enums(owner, enum_names):
    """Expose Qt6 scoped enum members through their Qt5-compatible names."""
    if owner is None:
        return
    for enum_name in enum_names:
        enum_type = getattr(owner, enum_name, None)
        if enum_type is None:
            continue
        for member_name in dir(enum_type):
            if member_name.startswith("_"):
                continue
            try:
                member = getattr(enum_type, member_name)
            except Exception:
                continue
            # Enum values are descriptors/constants; methods and metadata are not aliases.
            if callable(member) or member_name in ("name", "value"):
                continue
            _install_attr(owner, member_name, member)


def _install_qt5_api_compatibility():
    """Normalize APIs removed or scoped by Qt6/PySide6/PyQt6."""
    if not QtCore or not QtWidgets or not QtGui:
        return
    _flatten_enums(QtCore.Qt, (
        "AlignmentFlag", "ApplicationAttribute", "AspectRatioMode", "BrushStyle",
        "CaseSensitivity", "CheckState", "ConnectionType", "ContextMenuPolicy",
        "Corner", "CursorShape", "DropAction", "ElideMode", "FillRule",
        "FocusPolicy", "FocusReason", "GlobalColor", "ItemDataRole", "ItemFlag",
        "Key", "KeyboardModifier", "MatchFlag", "MouseButton", "Orientation",
        "PenStyle", "ScrollBarPolicy", "SortOrder", "TextFormat",
        "TextInteractionFlag", "ToolButtonStyle", "TransformationMode",
        "WidgetAttribute", "WindowModality", "WindowState", "WindowType",
    ))
    _flatten_enums(QtCore.QEvent, ("Type",))
    for owner, enum_names in (
        (QtCore.QEventLoop, ("ProcessEventsFlag",)),
        (QtWidgets.QAbstractItemView, ("DragDropMode", "EditTrigger", "ScrollHint", "ScrollMode", "SelectionBehavior", "SelectionMode")),
        (QtWidgets.QDialog, ("DialogCode",)),
        (QtWidgets.QDialogButtonBox, ("ButtonRole", "StandardButton")),
        (QtWidgets.QComboBox, ("InsertPolicy", "SizeAdjustPolicy")),
        (QtWidgets.QCompleter, ("CompletionMode", "ModelSorting")),
        (QtWidgets.QFileDialog, ("AcceptMode", "DialogLabel", "FileMode", "Option", "ViewMode")),
        (QtWidgets.QFrame, ("Shadow", "Shape")),
        (QtWidgets.QGraphicsItem, ("GraphicsItemChange", "GraphicsItemFlag")),
        (QtWidgets.QGraphicsView, ("CacheModeFlag", "DragMode", "OptimizationFlag", "ViewportAnchor", "ViewportUpdateMode")),
        (QtWidgets.QHeaderView, ("ResizeMode",)),
        (QtWidgets.QLineEdit, ("ActionPosition", "EchoMode")),
        (QtWidgets.QMessageBox, ("ButtonRole", "Icon", "StandardButton")),
        (QtWidgets.QSizePolicy, ("ControlType", "Policy", "PolicyFlag")),
        (QtWidgets.QStyle, ("ControlElement", "PixelMetric", "PrimitiveElement", "StateFlag", "StandardPixmap", "SubControl", "SubElement")),
        (QtGui.QFont, ("Capitalization", "HintingPreference", "SpacingType", "Stretch", "Style", "StyleHint", "StyleStrategy", "Weight")),
        (QtGui.QImage, ("Format", "InvertMode")),
        (QtGui.QPainter, ("CompositionMode", "PixmapFragmentHint", "RenderHint")),
        (QtGui.QPalette, ("ColorGroup", "ColorRole")),
        (QtGui.QTextCursor, ("MoveMode", "MoveOperation", "SelectionType")),
        (QtGui.QTextFormat, ("FormatType", "ObjectTypes", "PageBreakFlag", "Property")),
    ):
        _flatten_enums(owner, enum_names)

    # PySide6 removed exec_ while Qt5/PyQt code conventionally uses it.
    for owner in (QtWidgets.QDialog, QtWidgets.QMenu, QtWidgets.QMessageBox):
        if owner is not None and not hasattr(owner, "exec_") and hasattr(owner, "exec"):
            _install_attr(owner, "exec_", owner.exec)

    # Qt6 mouse events use floating-point position accessors.
    for event_type in (getattr(QtGui, "QMouseEvent", None), getattr(QtGui, "QWheelEvent", None)):
        if event_type is None:
            continue
        if not hasattr(event_type, "globalPos") and hasattr(event_type, "globalPosition"):
            def globalPos(self):
                return self.globalPosition().toPoint()
            _install_attr(event_type, "globalPos", globalPos)
        if not hasattr(event_type, "pos") and hasattr(event_type, "position"):
            def pos(self):
                return self.position().toPoint()
            _install_attr(event_type, "pos", pos)


_install_qt5_api_compatibility()


def plugin_form_to_widget(plugin_form, form_handle):
    """Return an IDA PluginForm QWidget under either PyQt- or PySide-based IDA."""
    errors = []
    for method_name in ("FormToPySideWidget", "FormToPyQtWidget"):
        converter = getattr(plugin_form, method_name, None)
        if converter is None:
            continue
        try:
            return converter(form_handle)
        except Exception as exc:
            errors.append(f"{method_name}: {exc}")
    detail = "; ".join(errors) or "no supported PluginForm converter is available"
    raise RuntimeError(f"Unable to convert the IDA PluginForm to a Qt widget ({detail}).")


def get_text_width(fm, text):
    if hasattr(fm, "horizontalAdvance"):
        return fm.horizontalAdvance(text)
    return fm.width(text)


def set_tab_stop_width(editor, width):
    if hasattr(editor, "setTabStopDistance"):
        editor.setTabStopDistance(width)
    else:
        editor.setTabStopWidth(width)


def qt_cast_flags(flags, flag_type):
    """Cast flags safely. Handle PySide6 bitwise operation warnings."""
    def to_int(f):
        if hasattr(f, 'value'): # PySide6
            return f.value
        try:
            return int(f)
        except:
            return f

    if isinstance(flags, (list, tuple)):
        res = 0
        for f in flags:
            val = to_int(f)
            if isinstance(val, int):
                res |= val
        flags = res
    else:
        flags = to_int(flags)
        
    if flag_type is not None:
        try:
            # In PySide6, calling the flag type with int returns the flag object
            return flag_type(flags)
        except:
            # Fallback to int if the type is not a proper Enum/Flag or fails
            pass
    return flags


# ---------- QRegExp compatibility shim for PySide6 / PyQt6 ----------
if QtWidgets and not hasattr(QtCore, "QRegExp"):
    class QRegExpWrapper(QtCore.QRegularExpression):
        def __init__(self, pattern="", options=0, syntax=0):
            if isinstance(pattern, QtCore.QRegularExpression):
                super().__init__(pattern)
            else:
                super().__init__(pattern)
                if options & 1:  # CaseInsensitive
                    self.setPatternOptions(self.patternOptions() | QtCore.QRegularExpression.CaseInsensitiveOption)
            self._last_match = None

        def indexIn(self, text, offset=0):
            self._last_match = self.match(text, offset)
            if self._last_match.hasMatch():
                return self._last_match.capturedStart()
            return -1

        def matchedLength(self):
            if self._last_match:
                return self._last_match.capturedLength()
            return -1

        def setCaseSensitivity(self, cs):
            if cs == QtCore.Qt.CaseInsensitive:
                self.setPatternOptions(self.patternOptions() | QtCore.QRegularExpression.CaseInsensitiveOption)
            else:
                self.setPatternOptions(self.patternOptions() & ~QtCore.QRegularExpression.CaseInsensitiveOption)

    QtCore.QRegExp = QRegExpWrapper

# ---------- Signal/Slot compatibility ----------
if QtCore:
    Signal = getattr(QtCore, "pyqtSignal", getattr(QtCore, "Signal", None))
    Slot = getattr(QtCore, "pyqtSlot", getattr(QtCore, "Slot", None))
    # Inject into QtCore module namespace for clients using QtCore.Signal/Slot
    if Signal and not hasattr(QtCore, "Signal"):
        QtCore.Signal = Signal
    if Slot and not hasattr(QtCore, "Slot"):
        QtCore.Slot = Slot
else:
    Signal = None
    Slot = None

# ---------- Optional AI libraries ----------
try:
    import openai
    import httpx
except ImportError:
    openai = None
    print("[PseudoNote] OpenAI or httpx not found. AI features will be disabled.")

# Provider-specific SDKs are deliberately loaded lazily by ai_client. Importing
# them here made every PseudoNote startup initialize unused backends; the legacy
# Gemini SDK in particular prints optional-module and Pydantic warnings in IDA.
anthropic = None
genai = None
gemini_backend = None
