from __future__ import annotations

"""Tkinter GUI wrapper around the async recon engine.

All async work runs in a dedicated background thread with its own event loop.
Progress messages arrive via a thread-safe queue and are drained by the Tkinter
after() poll — zero direct Tkinter calls from the worker thread.
"""

import asyncio
import os
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

# ── Dark theme palette (matches DeepWebRecon.py) ─────────────────────────────
DARK = {
    "bg":         "#1e1e1e",
    "bg_widget":  "#2a2a2a",
    "fg":         "#d4d4d4",
    "fg_dim":     "#888888",
    "accent":     "#00c896",
    "neon":       "#39ff14",
    "btn_bg":     "#2e2e2e",
    "btn_fg":     "#d4d4d4",
    "btn_active": "#3a3a3a",
    "danger":     "#e05c5c",
    "border":     "#3c3c3c",
    "cursor":     "#39ff14",
}

# ── Module definitions: (engine_key, display_label, phase_label, default_on) ─
MODULE_DEFS = [
    ("ip_whois",      "IP / RDAP",            "Foundation",   True),
    ("dns",           "DNS Records",           "Foundation",   True),
    ("axfr",          "Zone Transfer",         "Foundation",   True),
    ("domain_whois",  "Domain WHOIS",          "Foundation",   True),
    ("ct_logs",       "CT Logs",               "Passive OSINT",True),
    ("wayback",       "Wayback Machine",       "Passive OSINT",True),
    ("api_sources",   "API Sources",           "Passive OSINT",True),
    ("subdomains",    "Subdomain Enum",        "Enumeration",  True),
    ("geo",           "Geolocation",           "Network",      True),
    ("cdn",           "CDN Detection",         "Network",      True),
    ("ports",         "Port Scan",             "Active",       True),
    ("tls",           "TLS / SSL",             "Active",       True),
    ("headers",       "HTTP Headers",          "Active",       True),
    ("tech_detect",   "Tech Fingerprint",      "Active",       True),
    ("js_analysis",   "JS Analysis",           "Active",       True),
    ("dir_scan",      "Dir / Path Scan",       "Active",       True),
    ("email_harvest", "Email Harvest",         "Active",       True),
    ("ping",          "Ping",                  "Diagnostics",  True),
    ("traceroute",    "Traceroute",             "Diagnostics",  True),
]

PLACEHOLDER = "enter target domain or URL"

_LEVEL_PREFIX = {
    "info":    "[*]",
    "success": "[+]",
    "warn":    "[!]",
    "error":   "[✗]",
}


class ReconApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Surface Recon")
        self.root.geometry("820x920")
        self.root.configure(bg=DARK["bg"])
        self.root.resizable(True, True)
        self.root.minsize(660, 700)

        self._try_load_icon()

        self._log_queue: queue.Queue = queue.Queue()
        self._cancel_event: asyncio.Event | None = None
        self._cancel_thread: threading.Event = threading.Event()
        self._last_output_dir: Path | None = None
        self._last_stem: str = ""

        # ── Build UI ──────────────────────────────────────────────────────────
        self._build_controls()
        self._build_advanced()
        self._build_status()
        self._build_log()

        root.bind("<Button-1>", self._on_root_click, add="+")
        self._poll_log_queue()

    # ── Icon ──────────────────────────────────────────────────────────────────

    def _try_load_icon(self) -> None:
        try:
            icon_path = Path(__file__).parent.parent / "assets" / "radar.png"
            self._icon = tk.PhotoImage(file=str(icon_path))
            self.root.iconphoto(True, self._icon)
        except Exception:
            pass

    # ── Widget factories ──────────────────────────────────────────────────────

    def _label(self, parent, text, dim=True):
        fg = DARK["fg_dim"] if dim else DARK["fg"]
        return tk.Label(parent, text=text, bg=DARK["bg"], fg=fg,
                        font=("Segoe UI", 9), anchor="w")

    def _entry(self, parent):
        return tk.Entry(parent,
                        bg=DARK["bg_widget"], fg=DARK["fg"],
                        insertbackground=DARK["cursor"],
                        relief="flat", highlightthickness=1,
                        highlightbackground=DARK["border"],
                        highlightcolor=DARK["accent"],
                        font=("Consolas", 9))

    def _btn(self, parent, text, command, color=None, fg=None, **kw):
        return tk.Button(parent, text=text, command=command,
                         bg=color or DARK["btn_bg"],
                         fg=fg or DARK["btn_fg"],
                         activebackground=DARK["btn_active"],
                         activeforeground=DARK["fg"],
                         relief="flat", bd=0, padx=12, pady=6,
                         font=("Segoe UI", 9), cursor="hand2", **kw)

    # ── Control panel ─────────────────────────────────────────────────────────

    def _build_controls(self) -> None:
        panel = tk.Frame(self.root, bg=DARK["bg"])
        panel.pack(fill=tk.X, padx=18, pady=(16, 0))
        panel.columnconfigure(1, weight=1)

        self._label(panel, "Target Domain / URL:").grid(row=0, column=0, columnspan=2,
                                                         sticky="w", pady=(0, 2))
        self.url_entry = self._entry(panel)
        self.url_entry.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 8), ipady=4)
        self.url_entry.insert(0, PLACEHOLDER)
        self.url_entry.config(fg=DARK["fg_dim"])
        self.url_entry.bind("<FocusIn>",  self._url_focus_in)
        self.url_entry.bind("<FocusOut>", self._url_focus_out)
        self.url_entry.bind("<Return>",   lambda e: self.start_scan())

        self._label(panel, "Output Directory:").grid(row=2, column=0, columnspan=2,
                                                      sticky="w", pady=(0, 2))
        self.outdir_entry = self._entry(panel)
        self.outdir_entry.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 8), ipady=4)
        default_out = Path(__file__).parent.parent / "results"
        default_out.mkdir(exist_ok=True)
        self.outdir_entry.insert(0, str(default_out))

        # Output format row
        fmt_frame = tk.Frame(panel, bg=DARK["bg"])
        fmt_frame.grid(row=4, column=0, columnspan=2, sticky="w", pady=(0, 10))
        self._label(fmt_frame, "Output format:", dim=True).pack(side=tk.LEFT)
        self._fmt_vars: dict[str, tk.BooleanVar] = {
            "text": tk.BooleanVar(value=True),
            "json": tk.BooleanVar(value=False),
            "csv":  tk.BooleanVar(value=False),
        }
        for fmt, var in self._fmt_vars.items():
            tk.Checkbutton(fmt_frame, text=fmt.upper(), variable=var,
                           bg=DARK["bg"], fg=DARK["fg"],
                           selectcolor=DARK["bg_widget"],
                           activebackground=DARK["bg"],
                           activeforeground=DARK["accent"],
                           font=("Segoe UI", 9), cursor="hand2").pack(side=tk.LEFT, padx=(8, 0))

        # Buttons
        btn_frame = tk.Frame(self.root, bg=DARK["bg"])
        btn_frame.pack(fill=tk.X, padx=18, pady=(0, 6))

        self.start_btn = self._btn(btn_frame, "▶  Start Recon",
                                   self.start_scan, color=DARK["accent"], fg="#0a0a0a")
        self.start_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.cancel_btn = self._btn(btn_frame, "✕  Cancel",
                                    self.cancel_scan, color=DARK["danger"], state="disabled")
        self.cancel_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.clear_btn = self._btn(btn_frame, "⌫  Clear", self.clear_output)
        self.clear_btn.pack(side=tk.RIGHT, padx=(6, 0))

        self.open_dir_btn = self._btn(btn_frame, "📂  Open Results",
                                      self._open_results_dir, state="disabled")
        self.open_dir_btn.pack(side=tk.RIGHT, padx=(6, 0))

    def _url_focus_in(self, e):
        if self.url_entry.get() == PLACEHOLDER:
            self.url_entry.delete(0, tk.END)
            self.url_entry.config(fg=DARK["fg"])

    def _url_focus_out(self, e):
        if not self.url_entry.get().strip():
            self.url_entry.insert(0, PLACEHOLDER)
            self.url_entry.config(fg=DARK["fg_dim"])

    # ── Advanced (collapsible) ────────────────────────────────────────────────

    def _build_advanced(self) -> None:
        self._adv_open = False

        self._adv_container = tk.Frame(self.root, bg=DARK["bg"])
        self._adv_container.pack(fill=tk.X, padx=18, pady=(0, 4))

        self._adv_toggle_btn = tk.Button(
            self._adv_container, text="▸  Module Selection",
            command=self._toggle_advanced,
            bg=DARK["bg"], fg=DARK["fg_dim"],
            activebackground=DARK["bg"], activeforeground=DARK["fg"],
            relief="flat", bd=0, padx=0, pady=4,
            font=("Segoe UI", 9, "italic"), cursor="hand2"
        )
        self._adv_toggle_btn.pack(side=tk.LEFT)
        tk.Frame(self._adv_container, bg=DARK["border"], height=1).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0)
        )

        self._adv_inner = tk.Frame(self.root, bg=DARK["bg"])

        self._mod_vars: dict[str, tk.BooleanVar] = {}

        # Group modules by phase
        from collections import OrderedDict
        phases: dict[str, list] = OrderedDict()
        for key, label, phase, default in MODULE_DEFS:
            phases.setdefault(phase, []).append((key, label, default))

        cb_frame = tk.Frame(self._adv_inner, bg=DARK["bg"])
        cb_frame.pack(fill=tk.X, padx=4, pady=(6, 2))

        col = 0
        row = 0
        COLS = 4
        for phase, mods in phases.items():
            # Phase header spanning all columns
            ph_label = tk.Label(cb_frame, text=phase.upper(),
                                bg=DARK["bg"], fg=DARK["accent"],
                                font=("Segoe UI", 8, "bold"), anchor="w")
            ph_label.grid(row=row, column=0, columnspan=COLS, sticky="w",
                          padx=(0, 0), pady=(8, 2))
            row += 1
            for i, (key, label, default) in enumerate(mods):
                var = tk.BooleanVar(value=default)
                self._mod_vars[key] = var
                cb = tk.Checkbutton(
                    cb_frame, text=label, variable=var,
                    bg=DARK["bg"], fg=DARK["fg"],
                    selectcolor=DARK["bg_widget"],
                    activebackground=DARK["bg"],
                    activeforeground=DARK["accent"],
                    font=("Segoe UI", 9), cursor="hand2"
                )
                cb.grid(row=row + i // COLS, column=i % COLS,
                        sticky="w", padx=(0, 16), pady=2)
            row += (len(mods) + COLS - 1) // COLS

        ctrl_row = tk.Frame(self._adv_inner, bg=DARK["bg"])
        ctrl_row.pack(anchor="w", pady=(6, 8), padx=4)
        for txt, val in [("Select All", True), ("Clear All", False)]:
            tk.Button(
                ctrl_row, text=txt,
                command=lambda v=val: [var.set(v) for var in self._mod_vars.values()],
                bg=DARK["btn_bg"], fg=DARK["fg_dim"],
                activebackground=DARK["btn_active"], activeforeground=DARK["fg"],
                relief="flat", bd=0, padx=10, pady=4,
                font=("Segoe UI", 8), cursor="hand2"
            ).pack(side=tk.LEFT, padx=(0, 6))

    def _is_inside_adv(self, widget) -> bool:
        w = widget
        while w is not None:
            if w is self._adv_inner or w is self._adv_container:
                return True
            try:
                w = w.master
            except Exception:
                break
        return False

    def _on_root_click(self, event) -> None:
        if self._adv_open and not self._is_inside_adv(event.widget):
            self._toggle_advanced()

    def _toggle_advanced(self) -> None:
        if self._adv_open:
            self._adv_inner.pack_forget()
            self._adv_toggle_btn.config(text="▸  Module Selection")
            self._adv_open = False
        else:
            self._adv_inner.pack(fill=tk.X, padx=18, pady=(0, 4),
                                 before=self.status_label)
            self._adv_toggle_btn.config(text="▾  Module Selection")
            self._adv_open = True

    # ── Status bar & log ──────────────────────────────────────────────────────

    def _build_status(self) -> None:
        self.status_label = tk.Label(
            self.root, text="", fg=DARK["accent"], bg=DARK["bg"],
            font=("Segoe UI", 9, "italic"), anchor="w"
        )
        self.status_label.pack(fill=tk.X, padx=20, pady=(2, 4))

    def _build_log(self) -> None:
        log_frame = tk.Frame(self.root, bg=DARK["border"])
        log_frame.pack(fill=tk.BOTH, expand=True, padx=18, pady=(0, 14))

        self.log_text = tk.Text(
            log_frame,
            bg=DARK["bg_widget"], fg=DARK["neon"],
            insertbackground=DARK["cursor"],
            selectbackground=DARK["accent"], selectforeground="#0a0a0a",
            relief="flat", bd=0, highlightthickness=0,
            font=("Consolas", 9), padx=10, pady=8, wrap=tk.WORD
        )
        sb = tk.Scrollbar(log_frame, command=self.log_text.yview,
                          bg=DARK["bg_widget"], troughcolor=DARK["bg"],
                          relief="flat", bd=0, width=10)
        self.log_text.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # ── Queue poll ───────────────────────────────────────────────────────────

    def _poll_log_queue(self) -> None:
        try:
            while True:
                item = self._log_queue.get_nowait()
                if isinstance(item, dict):
                    if item["type"] == "done":
                        self._on_scan_done(item["result"], item["output_dir"], item["stem"])
                    elif item["type"] == "status":
                        self.status_label.config(text=item["text"])
                else:
                    self.log_text.insert(tk.END, item)
                    if self.log_text.yview()[1] >= 0.99:
                        self.log_text.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(50, self._poll_log_queue)

    # ── Scan lifecycle ────────────────────────────────────────────────────────

    def start_scan(self) -> None:
        if self._adv_open:
            self._toggle_advanced()

        target = self.url_entry.get().strip()
        if not target or target == PLACEHOLDER:
            messagebox.showerror("Error", "Please enter a valid domain or URL.")
            return

        outdir_str = self.outdir_entry.get().strip()
        if not outdir_str:
            messagebox.showerror("Error", "Please enter an output directory.")
            return
        outdir = Path(outdir_str)
        outdir.mkdir(parents=True, exist_ok=True)

        enabled_mods = [k for k, var in self._mod_vars.items() if var.get()]
        if not enabled_mods:
            messagebox.showwarning("No Modules", "Select at least one module.")
            return

        fmts = [f for f, var in self._fmt_vars.items() if var.get()]
        if not fmts:
            fmts = ["text"]

        self._cancel_thread.clear()
        self.url_entry.config(state="disabled")
        self.outdir_entry.config(state="disabled")
        self.start_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")
        self.clear_btn.config(state="disabled")
        self.open_dir_btn.config(state="disabled")
        self.status_label.config(text="Starting…")

        threading.Thread(
            target=self._run_worker,
            args=(target, outdir, enabled_mods, fmts),
            daemon=True,
        ).start()

    def cancel_scan(self) -> None:
        self._cancel_thread.set()
        if self._cancel_event is not None:
            # Signal the asyncio event from outside the loop
            loop = getattr(self, "_worker_loop", None)
            if loop and loop.is_running():
                loop.call_soon_threadsafe(self._cancel_event.set)
        self.cancel_btn.config(state="disabled")
        self.status_label.config(text="Cancelling…")

    def clear_output(self) -> None:
        self.log_text.delete("1.0", tk.END)

    def _open_results_dir(self) -> None:
        if self._last_output_dir and self._last_output_dir.exists():
            p = str(self._last_output_dir)
            if os.name == "nt":
                os.startfile(p)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", p])
            else:
                subprocess.Popen(["xdg-open", p])

    def _on_scan_done(self, result, output_dir: Path, stem: str) -> None:
        self._last_output_dir = output_dir
        self._last_stem = stem
        self.url_entry.config(state="normal")
        self.outdir_entry.config(state="normal")
        self.start_btn.config(state="normal")
        self.cancel_btn.config(state="disabled")
        self.clear_btn.config(state="normal")
        self.open_dir_btn.config(state="normal" if output_dir else "disabled")

        cancelled = self._cancel_thread.is_set()
        if cancelled:
            self.status_label.config(text="Cancelled.")
            messagebox.showinfo("Cancelled", f"Scan cancelled.\nPartial results saved to:\n{output_dir}")
        else:
            mods_run = len(result.modules_run) if result else 0
            self.status_label.config(text=f"Complete — {mods_run} module(s) ran.")
            messagebox.showinfo("Done", f"Recon finished!\nResults saved to:\n{output_dir}")

    # ── Worker (runs in background thread) ────────────────────────────────────

    def _run_worker(self, target: str, outdir: Path, modules: list[str], fmts: list[str]) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._worker_loop = loop

        cancel_ev = asyncio.Event()
        self._cancel_event = cancel_ev

        def _progress_cb(module: str, level: str, message: str) -> None:
            prefix = _LEVEL_PREFIX.get(level, "   ")
            self._log_queue.put(f"{prefix} [{module}] {message}\n")
            if level in ("info",):
                self._log_queue.put({"type": "status", "text": f"[{module}] {message[:80]}"})

        try:
            result = loop.run_until_complete(
                self._async_scan(target, modules, cancel_ev, _progress_cb)
            )
        except Exception as exc:
            self._log_queue.put(f"[✗] Fatal engine error: {exc}\n")
            result = None
        finally:
            loop.close()

        if result is None:
            self._log_queue.put({"type": "done", "result": None, "output_dir": outdir, "stem": ""})
            return

        # ── Write output files ─────────────────────────────────────────────
        from recon.output import write_json, write_text, write_csv, write_subdomain_list

        norm = re.sub(r"[^\w.-]", "_", target.split("://")[-1].split("/")[0])
        ts = (result.started_at or datetime.utcnow()).strftime("%Y%m%d_%H%M%S")
        stem = f"{norm}_{ts}"
        target_dir = outdir / norm
        target_dir.mkdir(parents=True, exist_ok=True)

        for fmt in fmts:
            try:
                if fmt == "json":
                    write_json(result, target_dir / f"{stem}.json")
                elif fmt == "text":
                    write_text(result, target_dir / f"{stem}.txt")
                elif fmt == "csv":
                    write_csv(result, target_dir)
            except Exception as exc:
                self._log_queue.put(f"[!] Output write ({fmt}) failed: {exc}\n")

        if result.subdomains:
            try:
                write_subdomain_list(result, target_dir / f"{stem}_subdomains.txt")
            except Exception:
                pass

        self._log_queue.put({"type": "done", "result": result,
                             "output_dir": target_dir, "stem": stem})

    async def _async_scan(self, target: str, modules: list[str],
                          cancel_ev: asyncio.Event, cb) -> object:
        from recon.config import Config
        from recon.engine import Engine

        config = Config.load()
        engine = Engine(config, progress_cb=cb, cancel_event=cancel_ev)
        return await engine.scan(target, modules=modules)


# ── Launch ────────────────────────────────────────────────────────────────────

def launch() -> None:
    root = tk.Tk()
    ReconApp(root)
    root.mainloop()


if __name__ == "__main__":
    launch()
