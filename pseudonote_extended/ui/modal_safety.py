"""Safe modal execution when an IDA custom-painted view is active."""


def exec_modal(dialog, title="PseudoNote Modal Host", address=None):
    """Run a Qt modal away from Hex-Rays' native viewport and restore focus."""
    source = None
    safe = None
    try:
        import idaapi
        import ida_kernwin

        source = ida_kernwin.get_current_widget()
        if source and idaapi.get_widget_type(source) == idaapi.BWN_PSEUDOCODE:
            safe = ida_kernwin.open_disasm_window(str(title))
            if safe:
                ida_kernwin.activate_widget(safe, True)
                if address is not None:
                    try:
                        ida_kernwin.jumpto(int(address))
                    except Exception:
                        pass
        return dialog.exec_()
    finally:
        try:
            import ida_kernwin
            if source:
                ida_kernwin.activate_widget(source, True)
            if safe:
                close_later = getattr(ida_kernwin, "WCLS_CLOSE_LATER", 0)
                ida_kernwin.close_widget(safe, close_later)
        except Exception:
            pass
