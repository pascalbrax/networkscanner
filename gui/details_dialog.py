import tkinter as tk
from tkinter import ttk


class DetailsDialog:
    """Non-modal window showing full plugin output for a single host."""

    def __init__(self, parent: tk.Tk, ip: str, data: dict) -> None:
        self.top = tk.Toplevel(parent)
        self.top.title(f'Details — {ip}')
        self.top.minsize(480, 320)

        self._build_ui(ip, data)

        # Position near parent
        self.top.update_idletasks()
        px = parent.winfo_x() + 60
        py = parent.winfo_y() + 60
        self.top.geometry(f'+{px}+{py}')

    def _build_ui(self, ip: str, data: dict) -> None:
        frame = ttk.Frame(self.top, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        # Header
        header = ttk.Frame(frame)
        header.grid(row=0, column=0, sticky='ew', pady=(0, 8))

        ttk.Label(header, text=ip, font=('', 14, 'bold')).pack(side=tk.LEFT)
        hostname = data.get('hostname', '')
        if hostname:
            ttk.Label(header, text=f'  ({hostname})', foreground='grey').pack(side=tk.LEFT)

        status = data.get('status', '')
        color = '#007700' if status == 'alive' else '#880000'
        ttk.Label(header, text=status.upper(), foreground=color,
                  font=('', 10, 'bold')).pack(side=tk.RIGHT)

        # Notebook: one tab per plugin + raw tab
        notebook = ttk.Notebook(frame)
        notebook.grid(row=1, column=0, sticky='nsew')

        plugins = data.get('plugins', {})
        if not plugins:
            tab = ttk.Frame(notebook, padding=8)
            ttk.Label(tab, text='No plugins were run on this host.',
                      foreground='grey').pack(anchor='nw')
            notebook.add(tab, text='Info')
        else:
            for plugin_name, (short, long_) in plugins.items():
                tab = ttk.Frame(notebook, padding=4)
                notebook.add(tab, text=plugin_name.upper())
                tab.columnconfigure(0, weight=1)
                tab.rowconfigure(1, weight=1)

                summary_frame = ttk.Frame(tab)
                summary_frame.grid(row=0, column=0, sticky='ew', pady=(0, 4))
                ttk.Label(summary_frame, text='Result: ', font=('', 9, 'bold')).pack(side=tk.LEFT)
                ttk.Label(summary_frame, text=short or '—').pack(side=tk.LEFT)

                text_frame = ttk.Frame(tab)
                text_frame.grid(row=1, column=0, sticky='nsew')
                text_frame.columnconfigure(0, weight=1)
                text_frame.rowconfigure(0, weight=1)

                text = tk.Text(text_frame, wrap=tk.WORD, font=('Consolas', 9),
                               relief=tk.FLAT, bg='#f8f8f8', state=tk.DISABLED)
                text.grid(row=0, column=0, sticky='nsew')
                vsb = ttk.Scrollbar(text_frame, orient='vertical', command=text.yview)
                vsb.grid(row=0, column=1, sticky='ns')
                text.configure(yscrollcommand=vsb.set)

                text.configure(state=tk.NORMAL)
                text.insert('1.0', long_ or '(no details)')
                text.configure(state=tk.DISABLED)

        # Close button
        ttk.Button(frame, text='Close', command=self.top.destroy).grid(
            row=2, column=0, sticky='e', pady=(8, 0)
        )
