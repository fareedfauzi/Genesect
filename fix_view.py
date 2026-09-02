import sys

fixed_text = """            self.deep_batch_spin = QtWidgets.QSpinBox()
            self.deep_batch_spin.setRange(1, 100)
            self.deep_batch_spin.setValue(getattr(self.config, 'deep_batch_size', 10))
            fl.addRow("Batch Size (Funcs):", self.deep_batch_spin)
            
            self.deep_lines_spin = QtWidgets.QSpinBox()
            self.deep_lines_spin.setRange(10, 5000)
            self.deep_lines_spin.setValue(getattr(self.config, 'deep_max_lines', 200))
            fl.addRow("Max Lines per Func:", self.deep_lines_spin)

            self.deep_cooldown_spin = QtWidgets.QSpinBox()
            self.deep_cooldown_spin.setRange(0, 300)
            self.deep_cooldown_spin.setValue(getattr(self.config, 'deep_cooldown', 0))
            fl.addRow("Cooldown (s):", self.deep_cooldown_spin)

            self.agent_cooldown_spin = QtWidgets.QSpinBox()
            self.agent_cooldown_spin.setRange(0, 1000)
            self.agent_cooldown_spin.setValue(getattr(self.config, 'agent_cooldown', 240))
            fl.addRow("Agent Rate Limit (429) Wait (s):", self.agent_cooldown_spin)

            perf_grp.setLayout(fl)
            layout.addWidget(perf_grp)

            # Naming
            name_grp = QtWidgets.QGroupBox("Naming Convention")
            nl = QtWidgets.QVBoxLayout()
            
            h1 = QtWidgets.QHBoxLayout()
            self.deep_use_prefix_cb = QtWidgets.QCheckBox("Use Prefix")
            self.deep_use_prefix_cb.setChecked(getattr(self.config, 'deep_use_prefix', False))
            h1.addWidget(self.deep_use_prefix_cb)
            
            self.deep_prefix_edit = QtWidgets.QLineEdit()
            self.deep_prefix_edit.setText(getattr(self.config, 'deep_prefix', ''))
            self.deep_prefix_edit.setPlaceholderText("Optional prefix")
            self.deep_prefix_edit.setFixedWidth(100)
            self.deep_prefix_edit.setEnabled(self.deep_use_prefix_cb.isChecked())
            self.deep_use_prefix_cb.toggled.connect(self.deep_prefix_edit.setEnabled)
            h1.addWidget(self.deep_prefix_edit)
            h1.addStretch()
            nl.addLayout(h1)
            
            self.deep_append_addr_cb = QtWidgets.QCheckBox("Append address postfix")
            self.deep_append_addr_cb.setChecked(getattr(self.config, 'deep_append_address', True))
            nl.addWidget(self.deep_append_addr_cb)
            
            self.deep_use_0x_cb = QtWidgets.QCheckBox("Use 0x for address (e.g., _0x18001db0)")
            self.deep_use_0x_cb.setChecked(getattr(self.config, 'deep_use_0x', False))
            self.deep_use_0x_cb.setEnabled(self.deep_append_addr_cb.isChecked())
            self.deep_append_addr_cb.toggled.connect(self.deep_use_0x_cb.setEnabled)
            nl.addWidget(self.deep_use_0x_cb)
            
            name_grp.setLayout(nl)
            layout.addWidget(name_grp)

            layout.addStretch()
            self.analyzer_tab.setLayout(layout)

        def on_provider_changed(self, text):
            self.save_fields_to_temp(self.current_provider)
            self.current_provider = text
            self.load_fields(text)

        def init_rename_tab(self):
            layout = QtWidgets.QVBoxLayout()
            
            grp = QtWidgets.QGroupBox("Function Renaming Settings")
            fl = QtWidgets.QFormLayout()
            
            self.disable_prefix_cb = QtWidgets.QCheckBox("No prefix")
            # If use_rename_prefix is True, disable_prefix is False
            use_pref = getattr(self.config, 'use_rename_prefix', False)
            self.disable_prefix_cb.setChecked(not use_pref)
            fl.addRow("", self.disable_prefix_cb)
            
            self.func_prefix_edit = QtWidgets.QLineEdit()
            self.func_prefix_edit.setText(getattr(self.config, 'function_prefix', ''))
            self.func_prefix_edit.setPlaceholderText("Optional, for example project_")
            fl.addRow("Rename prefix:", self.func_prefix_edit)

            self.disable_prefix_cb.toggled.connect(lambda checked: self.func_prefix_edit.setEnabled(not checked))
            self.func_prefix_edit.setEnabled(not self.disable_prefix_cb.isChecked())

            self.rename_append_addr_cb = QtWidgets.QCheckBox("Append offset address (e.g., FunctionName_18001db0)")
            self.rename_append_addr_cb.setChecked(getattr(self.config, 'rename_append_address', False))
            fl.addRow("", self.rename_append_addr_cb)
            
            self.rename_use_0x_cb = QtWidgets.QCheckBox("Use 0x prefix for address (e.g., _0x18001db0)")
            self.rename_use_0x_cb.setChecked(getattr(self.config, 'rename_use_0x', False))
            self.rename_use_0x_cb.setEnabled(self.rename_append_addr_cb.isChecked())
            self.rename_append_addr_cb.toggled.connect(self.rename_use_0x_cb.setEnabled)
            fl.addRow("", self.rename_use_0x_cb)
            
            grp.setLayout(fl)
            layout.addWidget(grp)
            
            info = QtWidgets.QLabel("This prefix applies to 'Rename Function' context menu actions (both code and malware). You can leave it empty or uncheck the box above if you don't want any prefix.")
            info.setStyleSheet("color: gray; font-style: italic;")
            info.setWordWrap(True)
            layout.addWidget(info)
            
            layout.addStretch()
            self.renaming_tab.setLayout(layout)

        def save_fields_to_temp(self, provider):
            if provider in self.temp_settings:
                self.temp_settings[provider]["key"] = self.key_edit.text()
                self.temp_settings[provider]["url"] = self.url_edit.text()
                self.temp_settings[provider]["model"] = self.model_edit.text()

        def load_fields(self, provider):
            data = self.temp_settings.get(provider, {})
            self.key_edit.setText(data.get("key", ""))
            self.url_edit.setText(data.get("url", ""))
            self.model_edit.setText(data.get("model", ""))
            self.key_edit.setEnabled(True)
            self.url_edit.setEnabled(True)
            self.model_edit.setEnabled(True)
            self.key_edit.setPlaceholderText("")
            self.reveal_key_cb.setChecked(False)
            self.key_edit.setEchoMode(QtWidgets.QLineEdit.Password)
            self.url_edit.setPlaceholderText("")
            self.key_label.setText("API Key (Optional for saving):")
            if provider == "Ollama":
                self.key_edit.setEnabled(False)
                self.key_edit.setPlaceholderText("Not required")
                self.url_label.setText("Host:")
                self.url_edit.setPlaceholderText("http://localhost:11434")
            elif provider == "Gemini":
                self.url_edit.setEnabled(False)
                self.url_edit.setText("")
                self.url_edit.setPlaceholderText("Managed by Google GenAI SDK")
                self.url_label.setText("Base URL:")
            else:
                self.url_label.setText("Base URL:")
                if provider == "OpenAI":
                    self.url_edit.setPlaceholderText("https://api.openai.com/v1")
                elif provider == "LMStudio":
                    self.url_edit.setPlaceholderText("http://localhost:1234/v1")
                    self.key_label.setText("API Key (Optional):")

        def init_log_tab(self):
            layout = QtWidgets.QVBoxLayout()
            self.log_view = QtWidgets.QPlainTextEdit()
            self.log_view.setReadOnly(True)
            self.log_view.setStyleSheet("background-color: #1E1E1E; color: #D4D4D4; font-family: Consolas, monospace;")
            self.log_view.setPlainText("\\n".join(LOGGER.logs))
            layout.addWidget(self.log_view)
            self.log_tab.setLayout(layout)
            sb = self.log_view.verticalScrollBar()
            sb.setValue(sb.maximum())
            if hasattr(LOGGER, 'log_signal'):
                LOGGER.log_signal.connect(self.append_log)

        def append_log(self, text):
            self.log_view.appendPlainText(text)

        def closeEvent(self, event):
            if hasattr(self, 'test_worker') and self.test_worker.isRunning():
                self.test_result_label.setText("Wait for the connection test to finish before closing Settings.")
                event.ignore()
                return
            if hasattr(LOGGER, 'log_signal'):
                try: LOGGER.log_signal.disconnect(self.append_log)
                except: pass
            super().closeEvent(event)

        def on_save(self):
            self.save_fields_to_temp(self.current_provider)
            profile = self._current_profile()
            validation = validate_profile(profile, require_api_key=False)
            if not validation.valid:
                QtWidgets.QMessageBox.warning(
                    self, "Invalid provider configuration",
                    "\\n".join(f"• {error}" for error in validation.errors),
                )
                return
            c = self.config
            c.active_provider = self.combo.currentText()
            s = self.temp_settings
            c.openai_key = s["OpenAI"]["key"]; c.openai_url = s["OpenAI"]["url"]; c.openai_model = s["OpenAI"]["model"]
            c.anthropic_key = s["Anthropic"]["key"]; c.anthropic_url = s["Anthropic"]["url"]; c.anthropic_model = s["Anthropic"]["model"]
            c.deepseek_key = s["DeepSeek"]["key"]; c.deepseek_url = s["DeepSeek"]["url"]; c.deepseek_model = s["DeepSeek"]["model"]
            c.gemini_key = s["Gemini"]["key"]; c.gemini_model = s["Gemini"]["model"]
            c.ollama_host = s["Ollama"]["url"]; c.ollama_model = s["Ollama"]["model"]
            c.lmstudio_key = s["LMStudio"]["key"]; c.lmstudio_url = s["LMStudio"]["url"]; c.lmstudio_model = s["LMStudio"]["model"]
            c.custom_key = s["OpenAICompatible"]["key"]; c.custom_url = s["OpenAICompatible"]["url"]; c.custom_model = s["OpenAICompatible"]["model"]
            active_data = s.get(c.active_provider, {})
            if active_data.get("model"):
                c.model = active_data.get("model")
            c.request_timeout_seconds = self.request_timeout_spin.value()
            c.request_max_completion_tokens = self.request_tokens_spin.value()
            c.request_context_window_tokens = self.request_context_spin.value()
            c.request_temperature = self.request_temperature_spin.value()
            c.request_retry_attempts = self.request_retry_spin.value()
            c.request_retry_backoff_seconds = self.request_backoff_spin.value()
            c.proxy = self.request_proxy_edit.text().strip()

            if hasattr(self, "bookmark_list"):
                c.bookmarked_actions = [
                    str(self.bookmark_list.item(index).data(QtCore.Qt.UserRole))
                    for index in range(self.bookmark_list.count())
                    if self.bookmark_list.item(index).checkState() == QtCore.Qt.Checked
                ]

            # Appearance (only present when hide_extra_tabs=False)
            if hasattr(self, 'font_widgets'):
                fw = self.font_widgets
                c.ui_font = fw["ui"][0].currentText(); c.ui_font_size = fw["ui"][1].value()
                c.code_font = fw["code"][0].currentText(); c.code_font_size = fw["code"][1].value()
                c.markdown_font = fw["md"][0].currentText(); c.markdown_font_size = fw["md"][1].value()
                
                c.highlight_color = self.hl_color
                c.indent_guides_enabled = self.indent_guides_enabled_cb.isChecked()
                c.indent_guides_color = self.indent_guides_color
                c.pseudocode_folding_color = getattr(self, 'fold_color', '#3F3F3F')

            # Bulk Renamer tab settings
            if hasattr(self, 'force_rename_cb'):
                c.force_bulk_rename = self.force_rename_cb.isChecked()
            if hasattr(self, 'bulk_force_rename_sub_cb'):
                c.bulk_force_rename_sub = self.bulk_force_rename_sub_cb.isChecked()
            if hasattr(self, 'cooldown_spin'):
                c.bulk_cooldown = self.cooldown_spin.value()
            if hasattr(self, 'asm_max_spin'):
                c.bulk_asm_max = self.asm_max_spin.value()
            if hasattr(self, 'disable_bulk_prefix_cb'):
                c.use_bulk_prefix = not self.disable_bulk_prefix_cb.isChecked()
            if hasattr(self, 'prefix_edit'):
                c.rename_prefix = self.prefix_edit.text().strip()
            if hasattr(self, 'bulk_append_addr_cb'):
                c.bulk_append_address = self.bulk_append_addr_cb.isChecked()
                c.bulk_use_0x = self.bulk_use_0x_cb.isChecked()
            if hasattr(self, 'custom_batch_spin'):
                c.bulk_batch_size = self.custom_batch_spin.value()
            if hasattr(self, 'custom_workers_spin'):
                c.bulk_parallel_workers = self.custom_workers_spin.value()

            # Bulk Function Analyzer tab settings
            if hasattr(self, 'analyze_workers_spin'):
                c.analyze_parallel_workers = self.analyze_workers_spin.value()
            if hasattr(self, 'analyze_batch_spin'):
                c.analyze_batch_size = self.analyze_batch_spin.value()
            if hasattr(self, 'analyze_cooldown_spin') and (not self.hide_extra_tabs or self.mode == 'analyzer'):
                c.analyze_cooldown = self.analyze_cooldown_spin.value()

            # Bulk Variable Renamer tab settings
            if hasattr(self, 'var_batch_spin'):
                c.var_batch_size = self.var_batch_spin.value()
            if hasattr(self, 'var_workers_spin'):
                c.var_parallel_workers = self.var_workers_spin.value()
            if hasattr(self, 'var_cooldown_spin') and (not self.hide_extra_tabs or self.mode == 'var_renamer'):
                c.var_cooldown = self.var_cooldown_spin.value()
            if hasattr(self, 'var_asm_max_spin'):
                c.var_asm_max = self.var_asm_max_spin.value()
            if hasattr(self, 'var_auto_apply_cb'):
                c.var_auto_apply = self.var_auto_apply_cb.isChecked()
            if hasattr(self, 'var_force_rename_cb'):
                c.var_force_rename = self.var_force_rename_cb.isChecked()

            # Function Rename tab settings
            if hasattr(self, 'disable_prefix_cb'):
                c.use_rename_prefix = not self.disable_prefix_cb.isChecked()
            if hasattr(self, 'func_prefix_edit'):
                c.function_prefix = self.func_prefix_edit.text().strip()
            if hasattr(self, 'rename_append_addr_cb'):
                c.rename_append_address = self.rename_append_addr_cb.isChecked()
            if hasattr(self, 'rename_use_0x_cb'):
                c.rename_use_0x = self.rename_use_0x_cb.isChecked()

            # Deep Analyzer settings
            if hasattr(self, 'deep_batch_spin'):
                c.deep_batch_size = self.deep_batch_spin.value()
                c.deep_parallel_workers = self.deep_workers_spin.value()
                c.deep_cooldown = self.deep_cooldown_spin.value()
                c.deep_max_lines = self.deep_lines_spin.value()
            if hasattr(self, 'agent_cooldown_spin'):
                c.agent_cooldown = self.agent_cooldown_spin.value()

                # These pipeline stages are always enabled; variable rename is controlled
                # by the toggle in the main Deep Analyzer dialog toolbar.
                c.deep_do_bottom_up_rename = True
                c.deep_do_func_comment = True"""

with open(r"d:\DEV\PseudoNote-Extended\pseudonote_extended\view.py", "r", encoding="utf-8") as f:
    text = f.read()

# I will find the starting prefix and ending suffix in the actual file and replace the middle.
start_idx = text.find("            self.deep_batch_spin = QtWidgets.QSpinBox()")
end_idx = text.find("                c.deep_do_analysis_rename = True")

if start_idx != -1 and end_idx != -1:
    new_text = text[:start_idx] + fixed_text + "\n" + text[end_idx:]
    with open(r"d:\DEV\PseudoNote-Extended\pseudonote_extended\view.py", "w", encoding="utf-8") as f:
        f.write(new_text)
    print("Fixed!")
else:
    print(f"Could not find indices! start: {start_idx}, end: {end_idx}")
