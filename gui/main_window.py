import csv
import json
import socket
import threading
import tkinter as tk
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import messagebox, filedialog
from tkinter import ttk
from typing import Dict, List, Optional, Tuple

from core.scanner import parse_targets, ping_host
from core.plugin_manager import (
    Plugin, get_enabled_plugins, run_plugin,
    get_recent_targets, add_recent_target,
)
from gui.config_dialog import ConfigDialog
from gui.details_dialog import DetailsDialog

class AutoHScrollbar(ttk.Scrollbar):
    """Horizontal scrollbar that hides itself when all content fits in view."""

    def set(self, lo: str, hi: str) -> None:
        if float(lo) <= 0.0 and float(hi) >= 1.0:
            # All content visible — hide the bar and free its row space
            self.grid_remove()
        else:
            self.grid()
        super().set(lo, hi)


# Unicode symbols used as button icons (render fine on Win 10/11 + Python 3)
ICO_SCAN    = '▶'   # ▶
ICO_STOP    = '■'   # ■
ICO_PLUGIN  = '⚙'   # ⚙
ICO_CSV     = '⇩'   # ⇩
ICO_JSON    = '⇩'   # ⇩
ICO_CLEAR   = '✕'   # ✕


class MainWindow:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title('Network Scanner')
        self.root.minsize(900, 540)

        # Scan state — only touched on the main thread
        self.scan_active    = False
        self.stop_event     = threading.Event()
        self.total_count    = 0
        self.scanned_count  = 0
        self.alive_count    = 0
        self.plugin_total   = 0
        self.plugin_done    = 0
        self._row_index     = 0   # incremented per inserted row, drives stripe
        self._loading_plugins = False   # guards against overlapping plugin loads

        # {ip: {'status': str, 'hostname': str, 'plugins': {name: (short, long)}}}
        self.results: Dict[str, dict] = {}
        self.enabled_plugins: List[Plugin] = []

        self._build_styles()
        self._build_ui()
        # Defer until the event loop is actually running: _refresh_plugins()
        # spawns a background thread that calls root.after() from a worker
        # thread, which Tk can reject with "main thread is not in main loop"
        # if mainloop() hasn't started processing events yet.
        self.root.after(0, self._refresh_plugins)
        self._clamp_to_screen()   # synchronous, safe before mainloop starts

    # ------------------------------------------------------------------
    # Styles
    # ------------------------------------------------------------------

    def _build_styles(self) -> None:
        s = ttk.Style()
        # Larger, bolder action buttons
        s.configure('Action.TButton', font=('Segoe UI', 11, 'bold'), padding=(14, 7))

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)

        # ── Controls ────────────────────────────────────────────────
        ctrl = ttk.Frame(self.root, padding=(8, 6))
        ctrl.grid(row=0, column=0, sticky='ew')
        ctrl.columnconfigure(1, weight=1)

        ttk.Label(ctrl, text='Target:').grid(row=0, column=0, sticky='w')
        self.target_var = tk.StringVar(value='192.168.1.0/24')
        self.target_entry = ttk.Combobox(
            ctrl, textvariable=self.target_var,
            font=('Segoe UI', 10), values=get_recent_targets(),
        )
        self.target_entry.grid(row=0, column=1, padx=(4, 10), sticky='ew')
        self.target_entry.bind('<Return>', lambda _e: self._start_scan())

        ttk.Label(ctrl, text='Workers:').grid(row=0, column=2)
        self.workers_var = tk.IntVar(value=100)
        ttk.Spinbox(ctrl, from_=1, to=1000, textvariable=self.workers_var,
                    width=5).grid(row=0, column=3, padx=(2, 10))

        ttk.Label(ctrl, text='Timeout (ms):').grid(row=0, column=4)
        self.timeout_var = tk.IntVar(value=800)
        ttk.Entry(ctrl, textvariable=self.timeout_var, width=6).grid(row=0, column=5, padx=(2, 10))

        ttk.Label(ctrl, text='Resolve:').grid(row=0, column=6)
        self.resolve_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctrl, variable=self.resolve_var).grid(row=0, column=7, padx=(0, 10))

        # Big action buttons
        self.scan_btn = ttk.Button(
            ctrl, text=f'{ICO_SCAN}  Scan',
            command=self._start_scan, style='Action.TButton',
        )
        self.scan_btn.grid(row=0, column=8, padx=(0, 4))

        self.stop_btn = ttk.Button(
            ctrl, text=f'{ICO_STOP}  Stop',
            command=self._stop_scan, style='Action.TButton', state=tk.DISABLED,
        )
        self.stop_btn.grid(row=0, column=9, padx=(0, 10))

        self.plugins_btn = ttk.Button(
            ctrl, text=f'{ICO_PLUGIN}  Plugins',
            command=self._open_config,
        )
        self.plugins_btn.grid(row=0, column=10)

        # ── Progress ────────────────────────────────────────────────
        prog_frame = ttk.Frame(self.root, padding=(8, 2))
        prog_frame.grid(row=1, column=0, sticky='ew')
        prog_frame.columnconfigure(0, weight=1)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            prog_frame, variable=self.progress_var, maximum=100,
        )
        self.progress_bar.grid(row=0, column=0, sticky='ew')

        self.progress_lbl = ttk.Label(prog_frame, text='0 / 0', width=14, anchor='e')
        self.progress_lbl.grid(row=0, column=1, padx=(6, 0))

        self.alive_lbl = ttk.Label(prog_frame, text='Alive: 0', width=10, anchor='e')
        self.alive_lbl.grid(row=0, column=2, padx=(6, 0))

        # ── Results table ───────────────────────────────────────────
        tree_frame = ttk.Frame(self.root)
        tree_frame.grid(row=2, column=0, sticky='nsew', padx=8, pady=(4, 0))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(tree_frame, show='headings', selectmode='browse')
        self.tree.grid(row=0, column=0, sticky='nsew')

        vsb = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky='ns')
        hsb = AutoHScrollbar(tree_frame, orient='horizontal', command=self.tree.xview)
        hsb.grid(row=1, column=0, sticky='ew')
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.tag_configure('alive', foreground='#006600')
        self.tree.tag_configure('odd',  background='#ffffff')
        self.tree.tag_configure('even', background='#eef3fb')
        self.tree.bind('<Double-1>', self._on_double_click)
        self.tree.bind('<Button-3>', self._on_right_click)

        self._ctx_menu = tk.Menu(self.root, tearoff=0)
        self._ctx_menu.add_command(label=f'Copy IP',         command=self._ctx_copy_ip)
        self._ctx_menu.add_command(label=f'Open in Browser', command=self._ctx_open_browser)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label=f'Details…',        command=self._ctx_open_details)

        # ── Bottom bar ──────────────────────────────────────────────
        bottom = ttk.Frame(self.root, padding=(8, 5))
        bottom.grid(row=3, column=0, sticky='ew')

        ttk.Button(bottom, text=f'{ICO_CSV}  Export CSV',
                   command=self._export_csv).pack(side=tk.LEFT)
        ttk.Button(bottom, text=f'{ICO_JSON}  Export JSON',
                   command=self._export_json).pack(side=tk.LEFT, padx=(4, 0))
        ttk.Button(bottom, text=f'{ICO_CLEAR}  Clear',
                   command=self._clear_results).pack(side=tk.LEFT, padx=(4, 0))

        self.status_var = tk.StringVar(value='Ready.')
        ttk.Label(bottom, textvariable=self.status_var).pack(side=tk.RIGHT)

    # ------------------------------------------------------------------
    # Plugin management
    # ------------------------------------------------------------------

    def _refresh_plugins(self) -> None:
        """
        Reload plugin metadata (title, options) in a background thread.
        Each plugin costs up to two subprocess calls, so this can take a
        noticeable amount of time with many plugins — never do it on the
        main thread or the whole window freezes.
        """
        self._load_plugins_async(self._on_plugins_refreshed)

    def _on_plugins_refreshed(self, plugins: List[Plugin]) -> None:
        self.enabled_plugins = [p for p in plugins if p.enabled]
        self._setup_columns()
        self.status_var.set('Ready.')

    def _load_plugins_async(self, on_done) -> None:
        """
        Run get_enabled_plugins() off the main thread, updating the status
        bar with per-plugin progress, then deliver the result back via
        root.after() (on_done runs on the main thread).
        """
        def progress(idx: int, total: int, name: str) -> None:
            self.root.after(
                0, self.status_var.set,
                f'Loading plugin info… ({idx}/{total}: {name})',
            )

        def worker() -> None:
            plugins = get_enabled_plugins(progress_callback=progress)
            self.root.after(0, on_done, plugins)

        self.status_var.set('Loading plugin info…')
        threading.Thread(target=worker, daemon=True).start()

    def _setup_columns(self) -> None:
        plugin_cols = [p.name for p in self.enabled_plugins]
        all_cols = ['ip', 'hostname', 'status'] + plugin_cols
        self.tree['columns'] = all_cols

        # All columns are resizable (stretch=True is the default)
        self.tree.heading('ip', text='IP Address',
                          command=lambda: self._sort_column('ip'))
        self.tree.column('ip', width=130, minwidth=90)

        self.tree.heading('hostname', text='Hostname',
                          command=lambda: self._sort_column('hostname'))
        self.tree.column('hostname', width=200, minwidth=100)

        self.tree.heading('status', text='Status',
                          command=lambda: self._sort_column('status'))
        self.tree.column('status', width=65, minwidth=50)

        for p in self.enabled_plugins:
            self.tree.heading(p.name, text=p.column_title or p.name.upper())
            self.tree.column(p.name, width=120, minwidth=60)

        # Clamp the window to screen bounds after every column rebuild.
        # Use after() so tkinter first processes the geometry change from the
        # new columns, then we cap the window — preventing off-screen growth.
        self.root.after(0, self._clamp_to_screen)

    def _open_config(self) -> None:
        if self._loading_plugins:
            return
        self._loading_plugins = True
        self.plugins_btn.configure(state=tk.DISABLED)
        self._load_plugins_async(self._show_config_dialog)

    def _show_config_dialog(self, plugins: List[Plugin]) -> None:
        self._loading_plugins = False
        self.plugins_btn.configure(state=tk.NORMAL)
        self.status_var.set('Ready.')

        dlg = ConfigDialog(self.root, plugins)
        self.root.wait_window(dlg.top)
        self._refresh_plugins()

    # ------------------------------------------------------------------
    # Scan lifecycle — main thread entry points
    # ------------------------------------------------------------------

    def _start_scan(self) -> None:
        if self.scan_active:
            return

        raw = self.target_var.get().strip()
        if not raw:
            messagebox.showwarning('Input required', 'Please enter a target.')
            return

        try:
            targets = parse_targets(raw)
        except ValueError as exc:
            messagebox.showerror('Invalid target', str(exc))
            return

        if not targets:
            messagebox.showwarning('No targets', 'The target range produced no hosts.')
            return

        # Persist this target and refresh the dropdown history
        add_recent_target(raw)
        self.target_entry['values'] = get_recent_targets()

        self.results.clear()
        self._clear_tree()
        self.stop_event.clear()
        self.scan_active   = True
        self.total_count   = len(targets)
        self.scanned_count = 0
        self.alive_count   = 0
        self.plugin_total  = 0
        self.plugin_done   = 0

        self._setup_columns()
        self._set_ui_scanning(True)
        self.status_var.set(f'Pinging {len(targets)} hosts…')
        self.progress_var.set(0)

        workers = max(1, self.workers_var.get())
        timeout = self.timeout_var.get()
        resolve = self.resolve_var.get()

        # Hand off everything to a coordinator thread so the main thread
        # stays free to process GUI events throughout the scan.
        threading.Thread(
            target=self._scan_coordinator,
            args=(targets, workers, timeout, resolve),
            daemon=True,
        ).start()

    def _stop_scan(self) -> None:
        self.stop_event.set()
        self.status_var.set('Stopping…')

    def _set_ui_scanning(self, scanning: bool) -> None:
        on  = tk.NORMAL if not scanning else tk.DISABLED
        off = tk.DISABLED if not scanning else tk.NORMAL
        self.scan_btn.configure(state=on)
        self.stop_btn.configure(state=off)
        self.target_entry.configure(state=on)

    # Called on main thread when everything is finished
    def _finish_scan(self) -> None:
        self.scan_active = False
        self._set_ui_scanning(False)
        self.progress_var.set(100)
        self._sort_column('ip')   # default sort; also restripes
        suffix = ' (stopped)' if self.stop_event.is_set() else ''
        self.status_var.set(
            f'Done{suffix}. '
            f'{self.alive_count} alive of {self.scanned_count} scanned.'
        )

    # ------------------------------------------------------------------
    # Coordinator thread — never touches tkinter widgets directly
    # ------------------------------------------------------------------

    def _scan_coordinator(
        self,
        targets: list,
        workers: int,
        timeout_ms: int,
        resolve: bool,
    ) -> None:
        alive_ips: List[str] = []

        # ── Phase 1: ping ───────────────────────────────────────────
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_ip = {
                executor.submit(self._do_ping, ip, timeout_ms, resolve): ip
                for ip in targets
            }
            for future in as_completed(future_to_ip):
                if self.stop_event.is_set():
                    break
                ip = future_to_ip[future]
                try:
                    rtt, hostname = future.result()
                except Exception:
                    rtt, hostname = None, ''

                if rtt is not None:
                    alive_ips.append(ip)
                self.root.after(0, self._on_ping_result, ip, rtt, hostname)

        if self.stop_event.is_set() or not self.enabled_plugins or not alive_ips:
            self.root.after(0, self._finish_scan)
            return

        # ── Phase 2: plugins (starts only after all pings are done) ─
        plugin_tasks = [(ip, p) for ip in alive_ips for p in self.enabled_plugins]

        # ── Adaptive concurrency & timeout ──────────────────────────
        # Spawning too many Python subprocesses at once causes high OS
        # scheduling pressure: each interpreter takes longer to start,
        # burning the timeout before the plugin does any real work.
        # Cap concurrent processes so the OS stays comfortable, then
        # scale the per-task timeout up to absorb any remaining queue lag.
        PLUGIN_WORKER_CAP = 25
        plugin_workers = min(workers, PLUGIN_WORKER_CAP)

        # Each worker processes ceil(tasks/workers) tasks in sequence.
        # Base: 15 s (generous process-start + network probe margin).
        # Extra: +1 s per 8 tasks queued behind each worker slot.
        tasks_per_worker = max(1, len(plugin_tasks) / plugin_workers)
        plugin_timeout = int(15 + tasks_per_worker / 8)
        plugin_timeout = min(plugin_timeout, 90)   # hard cap

        self.root.after(0, self._on_plugins_phase_start,
                        len(plugin_tasks), plugin_workers, plugin_timeout)

        with ThreadPoolExecutor(max_workers=plugin_workers) as executor:
            future_map = {
                executor.submit(self._do_plugin, ip, plugin, plugin_timeout): (ip, plugin)
                for ip, plugin in plugin_tasks
            }
            for future in as_completed(future_map):
                if self.stop_event.is_set():
                    break
                ip, plugin = future_map[future]
                try:
                    short, long_ = future.result()
                except Exception as exc:
                    short, long_ = 'ERR', str(exc)
                self.root.after(0, self._on_plugin_result, ip, plugin.name, short, long_)

        self.root.after(0, self._finish_scan)

    # ------------------------------------------------------------------
    # Worker functions — run inside thread pool, return plain values
    # ------------------------------------------------------------------

    def _do_ping(self, ip: str, timeout_ms: int, resolve: bool):
        rtt = ping_host(ip, timeout_ms)   # int ms if alive, None if not
        hostname = ''
        if rtt is not None and resolve:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
        return rtt, hostname

    def _do_plugin(self, ip: str, plugin: Plugin, timeout: int = 15):
        return run_plugin(plugin.path, ip, timeout=timeout, options=plugin.selected_options)

    # ------------------------------------------------------------------
    # Main-thread callbacks — only called via root.after()
    # ------------------------------------------------------------------

    def _on_ping_result(self, ip: str, rtt: Optional[int], hostname: str) -> None:
        self.scanned_count += 1

        if rtt is not None:
            self.alive_count += 1
            stripe = 'even' if self._row_index % 2 == 0 else 'odd'
            self._row_index += 1
            status = f'{rtt} ms'
            self.results[ip] = {'status': status, 'hostname': hostname, 'plugins': {}}
            self.tree.insert('', 'end', iid=ip, values=self._row_values(ip),
                             tags=('alive', stripe))
            self.alive_lbl.configure(text=f'Alive: {self.alive_count}')

        pct = (self.scanned_count / self.total_count * 100) if self.total_count else 0
        self.progress_var.set(pct)
        self.progress_lbl.configure(text=f'{self.scanned_count} / {self.total_count}')
        self.status_var.set(
            f'Pinging… {self.scanned_count} / {self.total_count}   '
            f'Alive: {self.alive_count}'
        )

    def _on_plugins_phase_start(self, total: int,
                                workers: int, timeout: int) -> None:
        self.plugin_total   = total
        self.plugin_done    = 0
        self._plugin_workers = workers
        self._plugin_timeout = timeout
        self.progress_var.set(0)
        self.status_var.set(
            f'Plugins… 0 / {total}'
            f'  |  {workers} workers  |  {timeout}s / task'
        )

    def _on_plugin_result(self, ip: str, plugin_name: str, short: str, long_: str) -> None:
        self.plugin_done += 1
        if ip in self.results:
            self.results[ip]['plugins'][plugin_name] = (short, long_)
            try:
                self.tree.item(ip, values=self._row_values(ip))
            except tk.TclError:
                pass

        pct = (self.plugin_done / self.plugin_total * 100) if self.plugin_total else 0
        self.progress_var.set(pct)
        self.status_var.set(
            f'Plugins… {self.plugin_done} / {self.plugin_total}'
            f'  |  {getattr(self, "_plugin_workers", "?")} workers'
            f'  |  {getattr(self, "_plugin_timeout", "?")}s / task'
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _row_values(self, ip: str) -> list:
        r = self.results[ip]
        row = [ip, r.get('hostname', ''), r['status']]
        for p in self.enabled_plugins:
            short, _ = r['plugins'].get(p.name, ('', ''))
            row.append(short)
        return row

    def _clear_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._row_index = 0

    def _restripe(self) -> None:
        """Reassign odd/even background tags to match the current row order."""
        for idx, iid in enumerate(self.tree.get_children('')):
            stripe = 'even' if idx % 2 == 0 else 'odd'
            # Keep all existing tags except the old stripe, then add the new one
            tags = [t for t in self.tree.item(iid, 'tags') if t not in ('odd', 'even')]
            tags.append(stripe)
            self.tree.item(iid, tags=tags)

    def _clear_results(self) -> None:
        if self.scan_active:
            return
        self.results.clear()
        self._clear_tree()
        self.progress_var.set(0)
        self.progress_lbl.configure(text='0 / 0')
        self.alive_lbl.configure(text='Alive: 0')
        self.status_var.set('Ready.')

    def _sort_column(self, col: str) -> None:
        def sort_key(iid):
            val = self.tree.set(iid, col)
            if col == 'ip':
                try:
                    return (0, [int(x) for x in val.split('.')])
                except Exception:
                    pass
            if col == 'status':
                # Sort "4 ms", "12 ms", "1 ms" numerically; empty / non-RTT last
                try:
                    return (0, [int(val.split()[0])])
                except Exception:
                    pass
            return (1, [val])

        items = sorted(self.tree.get_children(''), key=sort_key)
        for idx, iid in enumerate(items):
            self.tree.move(iid, '', idx)
        self._restripe()

    def _clamp_to_screen(self) -> None:
        """Keep the window within screen bounds; let the treeview scroll instead."""
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        # Hard cap: window never exceeds screen dimensions
        self.root.maxsize(sw, sh)
        cur_w = self.root.winfo_width()
        cur_h = self.root.winfo_height()
        # Leave a small margin (taskbar / window chrome)
        max_w = int(sw * 0.95)
        max_h = int(sh * 0.92)
        new_w = max(900,  min(cur_w, max_w))
        new_h = max(540, min(cur_h, max_h))
        if new_w != cur_w or new_h != cur_h:
            self.root.geometry(f'{new_w}x{new_h}')

    # ------------------------------------------------------------------
    # Double-click → details panel
    # ------------------------------------------------------------------

    def _on_double_click(self, _event: tk.Event) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        ip = sel[0]
        if ip in self.results:
            DetailsDialog(self.root, ip, self.results[ip])

    # ------------------------------------------------------------------
    # Right-click context menu
    # ------------------------------------------------------------------

    def _on_right_click(self, event: tk.Event) -> None:
        # Select the row under the cursor before showing the menu
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        self.tree.focus(iid)
        self._ctx_menu.tk_popup(event.x_root, event.y_root)

    def _selected_ip(self) -> Optional[str]:
        sel = self.tree.selection()
        return sel[0] if sel else None

    def _ctx_copy_ip(self) -> None:
        ip = self._selected_ip()
        if ip:
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)

    def _ctx_open_browser(self) -> None:
        ip = self._selected_ip()
        if ip:
            webbrowser.open(f'http://{ip}')

    def _ctx_open_details(self) -> None:
        ip = self._selected_ip()
        if ip and ip in self.results:
            DetailsDialog(self.root, ip, self.results[ip])

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _export_csv(self) -> None:
        if not self.results:
            messagebox.showinfo('No data', 'Nothing to export yet.')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.csv',
            filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
        )
        if not path:
            return
        plugin_names = [p.name for p in self.enabled_plugins]
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(['ip', 'hostname', 'status'] + plugin_names)
                for ip, data in self.results.items():
                    row = [ip, data.get('hostname', ''), data['status']]
                    for name in plugin_names:
                        short, _ = data['plugins'].get(name, ('', ''))
                        row.append(short)
                    w.writerow(row)
            messagebox.showinfo('Exported', f'CSV saved to:\n{path}')
        except OSError as exc:
            messagebox.showerror('Export failed', str(exc))

    def _export_json(self) -> None:
        if not self.results:
            messagebox.showinfo('No data', 'Nothing to export yet.')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON files', '*.json'), ('All files', '*.*')],
        )
        if not path:
            return
        export_data = {
            ip: {
                'hostname': data.get('hostname', ''),
                'status':   data['status'],
                'plugins':  {
                    name: {'short': s, 'long': l}
                    for name, (s, l) in data['plugins'].items()
                },
            }
            for ip, data in self.results.items()
        }
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            messagebox.showinfo('Exported', f'JSON saved to:\n{path}')
        except OSError as exc:
            messagebox.showerror('Export failed', str(exc))
