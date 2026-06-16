import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, List

from core.plugin_manager import (
    Plugin, set_enabled_plugins, set_plugin_option_values,
)


class ConfigDialog:
    """Modal dialog for enabling/disabling plugins and configuring their options."""

    def __init__(self, parent: tk.Tk, plugins: List[Plugin]) -> None:
        """
        plugins must already have title/options resolved (e.g. via
        get_enabled_plugins() run on a background thread by the caller) —
        this dialog never spawns plugin subprocesses itself, so it always
        opens instantly.
        """
        self.top = tk.Toplevel(parent)
        self.top.title('Plugin Configuration')
        self.top.resizable(False, False)
        self.top.grab_set()

        self._enabled_vars: Dict[str, tk.BooleanVar] = {}
        # {plugin_name: {option_name: tk.StringVar}}
        self._option_vars: Dict[str, Dict[str, tk.StringVar]] = {}
        self._plugins: List[Plugin] = plugins

        self._build_ui()

        # Center over parent
        self.top.update_idletasks()
        px = parent.winfo_x() + (parent.winfo_width() - self.top.winfo_width()) // 2
        py = parent.winfo_y() + (parent.winfo_height() - self.top.winfo_height()) // 2
        self.top.geometry(f'+{px}+{py}')

    def _build_ui(self) -> None:
        frame = ttk.Frame(self.top, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text='Enable plugins to run on discovered hosts:',
                  font=('', 10, 'bold')).pack(anchor='w', pady=(0, 8))

        plugin_frame = ttk.LabelFrame(frame, text='Available plugins', padding=8)
        plugin_frame.pack(fill=tk.BOTH, expand=True)

        if not self._plugins:
            ttk.Label(plugin_frame,
                      text='No plugins found.\nAdd .py files to the plugins/ folder.',
                      foreground='grey').pack(padx=8, pady=8)
        else:
            for p in self._plugins:
                self._build_plugin_row(plugin_frame, p)

        sep = ttk.Separator(frame)
        sep.pack(fill=tk.X, pady=10)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text='Save', command=self._save).pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text='Cancel', command=self.top.destroy).pack(side=tk.RIGHT, padx=(0, 4))

    def _build_plugin_row(self, parent: ttk.Frame, p: Plugin) -> None:
        block = ttk.Frame(parent)
        block.pack(fill=tk.X, pady=3)

        header = ttk.Frame(block)
        header.pack(fill=tk.X)

        var = tk.BooleanVar(value=p.enabled)
        self._enabled_vars[p.name] = var
        ttk.Checkbutton(header, variable=var, text=p.name).pack(side=tk.LEFT)
        if p.description:
            ttk.Label(header, text=f'— {p.description}',
                      foreground='grey').pack(side=tk.LEFT, padx=(4, 0))

        if not p.options:
            return

        self._option_vars[p.name] = {}
        opts_frame = ttk.Frame(block, padding=(24, 2, 0, 0))
        opts_frame.pack(fill=tk.X)

        for opt in p.options:
            opt_name = opt.get('name')
            if not opt_name:
                continue
            label = opt.get('label', opt_name)
            opt_type = opt.get('type', 'choice')
            current = p.selected_options.get(opt_name, opt.get('default', ''))

            row = ttk.Frame(opts_frame)
            row.pack(fill=tk.X, pady=1)
            ttk.Label(row, text=f'{label}:').pack(side=tk.LEFT)

            str_var = tk.StringVar(value=str(current))
            self._option_vars[p.name][opt_name] = str_var

            if opt_type == 'choice':
                choices = [str(c) for c in opt.get('choices', [])]
                ttk.Combobox(
                    row, textvariable=str_var, values=choices,
                    state='readonly', width=18,
                ).pack(side=tk.LEFT, padx=(6, 0))
            else:
                # Unknown option type — fall back to a free-text entry
                ttk.Entry(row, textvariable=str_var, width=20).pack(side=tk.LEFT, padx=(6, 0))

    def _save(self) -> None:
        enabled = [name for name, var in self._enabled_vars.items() if var.get()]
        try:
            set_enabled_plugins(enabled)
            for plugin_name, option_vars in self._option_vars.items():
                values = {opt_name: var.get() for opt_name, var in option_vars.items()}
                set_plugin_option_values(plugin_name, values)
        except OSError as exc:
            messagebox.showerror('Save failed', str(exc), parent=self.top)
            return
        self.top.destroy()
