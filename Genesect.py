# -*- coding: utf-8 -*-
"""
Genesect — IDA Pro AI Assistant Plugin (entry point).
This file is placed in IDA's plugins/ directory and delegates to the
genesect package.
"""
from genesect.plugin import GenesectPlugin

def PLUGIN_ENTRY():
    return GenesectPlugin()
