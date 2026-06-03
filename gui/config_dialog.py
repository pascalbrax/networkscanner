import tkinter as tk
from tkinter import ttk, messagebox
from typing import List

from core.plugin_manager import Plugin, discover_plugins, get_enabled_plugins, set_enabled_plugins


class ConfigDialog:
    """Modal dialog for enabling / disabling plugins."""

    def __init__(self, parent: tk.Tk) -> None:
        self.top = tk.Toplevel(parent)
        self.top.title('Plugin Configuration')
        self.top.resizable(False, False)
        self.top.grab_set()

        self._vars: dict[str, tk.BooleanVar] = {}
        self._plugins: List[Plugin] = get_enabled_plugins()

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
                var = tk.BooleanVar(value=p.enabled)
                self._vars[p.name] = var
                row = ttk.Frame(plugin_frame)
                row.pack(fill=tk.X, pady=2)
                ttk.Checkbutton(row, variable=var, text=p.name).pack(side=tk.LEFT)
                if p.description:
                    ttk.Label(row, text=f'— {p.description}',
                              foreground='grey').pack(side=tk.LEFT, padx=(4, 0))

        sep = ttk.Separator(frame)
        sep.pack(fill=tk.X, pady=10)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text='Save', command=self._save).pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text='Cancel', command=self.top.destroy).pack(side=tk.RIGHT, padx=(0, 4))

    def _save(self) -> None:
        enabled = [name for name, var in self._vars.items() if var.get()]
        try:
            set_enabled_plugins(enabled)
        except OSError as exc:
            messagebox.showerror('Save failed', str(exc), parent=self.top)
            return
        self.top.destroy()
