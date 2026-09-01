"""Namespaced window-state persistence helpers."""

from pseudonote_extended.qt_compat import QtCore


class UIStateStore:
    def __init__(self, scope):
        self.scope = str(scope).strip("/") or "global"
        self.settings = QtCore.QSettings("PseudoNoteExtended", "IDAPlugin")

    def _key(self, name):
        return f"ui/{self.scope}/{name}"

    def value(self, name, default=None):
        return self.settings.value(self._key(name), default)

    def set_value(self, name, value):
        self.settings.setValue(self._key(name), value)

    def save_window(self, widget):
        self.set_value("geometry", widget.saveGeometry())

    def restore_window(self, widget):
        geometry = self.value("geometry")
        return bool(geometry and widget.restoreGeometry(geometry))

    def save_splitter(self, name, splitter):
        self.set_value(f"splitter/{name}", splitter.saveState())

    def restore_splitter(self, name, splitter):
        state = self.value(f"splitter/{name}")
        return bool(state and splitter.restoreState(state))
