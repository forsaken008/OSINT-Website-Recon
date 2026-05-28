import tkinter as tk
from tkinter import messagebox
import requests
import socket
import subprocess
import sys
import datetime
import os
import threading
import ssl
import dns.resolver
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
import urllib.parse
import time
import re
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

EXTENDED_SUBDOMAINS = [
    "admin", "mail", "webmail", "vpn", "test", "dev", "portal",
    "cpanel", "login", "secure", "server", "mx", "api", "shop",
    "blog", "news", "staging", "beta", "demo", "forum", "support",
    "m", "cdn", "images", "static", "downloads",
    "ftp", "ssh", "smtp", "pop", "imap",
    "ns1", "ns2", "ns3",
    "db", "mysql", "remote", "vpn2", "office",
    "intranet", "internal", "git", "svn",
    "jenkins", "jira", "confluence",
    "monitor", "status", "phpmyadmin",
    "app", "apps", "www2", "old", "new",
    "backup", "files", "media", "img", "video",
    "auth", "sso", "account", "pay", "payment",
    "checkout", "store", "cart", "help",
    "cp", "whm", "webdisk", "autodiscover", "exchange"
]

ADMIN_PATHS = [
    "/admin", "/administrator", "/adminpanel", "/cpanel", "/login",
    "/user", "/wp-admin", "/manager", "/secure", "/admin/login"
]

EXPOSED_PATHS = [
    "/.git/", "/.env", "/config.php", "/db_backup.sql", "/backup.zip"
]

# archive.org supports HTTPS on the free tier
WAYBACK_API = "https://archive.org/wayback/available?url={}"

HEADERS_USER_AGENT = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/114.0.0.0 Safari/537.36"
}

MAX_THREADS = 15
TOTAL_PORTS = 65535

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

PLACEHOLDER = "enter target URL / domain here"

# Ordered list of every scan section: (key, display label)
SCAN_SECTIONS = [
    ("dns",        "DNS Records"),
    ("whois",      "IP & WHOIS"),
    ("geo",        "Geolocation"),
    ("ping",       "Ping"),
    ("traceroute", "Traceroute"),
    ("subdomains", "Subdomain Enumeration"),
    ("admin",      "Admin Panel Detection"),
    ("exposed",    "Exposed Files"),
    ("ssl",        "SSL Certificate"),
    ("ports",      "Port Scanner (quick)"),
    ("headers",    "HTTP & Security Headers"),
    ("wayback",    "Wayback Machine"),
    ("cms",        "CMS Detection"),
    ("robots",     "robots.txt & Sitemap"),
    ("email",      "Email Harvesting"),
    ("fullports",  "Full Port Scan (1–65535)"),
]

# ── Dark theme palette ────────────────────────────────────────────────────────
DARK = {
    "bg":         "#1e1e1e",   # window / frame background
    "bg_widget":  "#2a2a2a",   # entry / text box background
    "fg":         "#d4d4d4",   # primary text
    "fg_dim":     "#888888",   # labels / dim text
    "accent":     "#00c896",   # green accent (status, start button)
    "neon":       "#39ff14",   # neon green — output log text
    "btn_bg":     "#2e2e2e",   # regular button background
    "btn_fg":     "#d4d4d4",   # regular button text
    "btn_active": "#3a3a3a",   # button hover/active background
    "danger":     "#e05c5c",   # cancel button
    "border":     "#3c3c3c",   # entry/text borders
    "cursor":     "#39ff14",   # text cursor
}


class ReconApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Deep Web Recon")
        self.root.geometry("760x860")
        self.root.configure(bg=DARK["bg"])
        self.root.resizable(True, True)

        # ── app icon ──────────────────────────────────────────────────────────
        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "radar.png")
            self._icon = tk.PhotoImage(file=icon_path)
            self.root.iconphoto(True, self._icon)
        except Exception:
            pass  # icon missing or unsupported format — fail silently
        self._log_queue = queue.Queue()
        self._cancel_event = threading.Event()
        self._last_log_file = None

        # ── helper factories ──────────────────────────────────────────────────
        def label(parent, text, dim=True):
            fg = DARK["fg_dim"] if dim else DARK["fg"]
            return tk.Label(parent, text=text, bg=DARK["bg"], fg=fg,
                            font=("Segoe UI", 9), anchor="w")

        def entry(parent):
            return tk.Entry(parent,
                            bg=DARK["bg_widget"], fg=DARK["fg"],
                            insertbackground=DARK["cursor"],
                            relief="flat",
                            highlightthickness=1,
                            highlightbackground=DARK["border"],
                            highlightcolor=DARK["accent"],
                            font=("Consolas", 9))

        def btn(parent, text, command, color=None, fg=None, **kw):
            bg = color or DARK["btn_bg"]
            return tk.Button(parent, text=text, command=command,
                             bg=bg, fg=fg or DARK["btn_fg"],
                             activebackground=DARK["btn_active"],
                             activeforeground=DARK["fg"],
                             relief="flat", bd=0,
                             padx=12, pady=6,
                             font=("Segoe UI", 9),
                             cursor="hand2", **kw)

        # ── top control panel (grid) ──────────────────────────────────────────
        panel = tk.Frame(root, bg=DARK["bg"])
        panel.pack(fill=tk.X, padx=18, pady=(16, 0))
        panel.columnconfigure(1, weight=1)   # entries stretch horizontally

        label(panel, "Target Domain / URL:").grid(
            row=0, column=0, sticky="w", pady=(0, 2))
        self.url_entry = entry(panel)
        self.url_entry.grid(row=1, column=0, columnspan=2,
                            sticky="ew", pady=(0, 10), ipady=4)

        # placeholder behaviour
        self.url_entry.insert(0, PLACEHOLDER)
        self.url_entry.config(fg=DARK["fg_dim"])

        def _on_url_focus_in(e):
            if self.url_entry.get() == PLACEHOLDER:
                self.url_entry.delete(0, tk.END)
                self.url_entry.config(fg=DARK["fg"])

        def _on_url_focus_out(e):
            if not self.url_entry.get().strip():
                self.url_entry.insert(0, PLACEHOLDER)
                self.url_entry.config(fg=DARK["fg_dim"])

        self.url_entry.bind("<FocusIn>",  _on_url_focus_in)
        self.url_entry.bind("<FocusOut>", _on_url_focus_out)
        self.url_entry.bind("<Return>",   lambda e: self.start_investigation())

        label(panel, "Output Directory:").grid(
            row=2, column=0, sticky="w", pady=(0, 2))
        self.output_dir_entry = entry(panel)
        self.output_dir_entry.grid(row=3, column=0, columnspan=2,
                                   sticky="ew", pady=(0, 14), ipady=4)
        default_logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
        os.makedirs(default_logs_dir, exist_ok=True)
        self.output_dir_entry.insert(0, default_logs_dir)

        # ── button rows ───────────────────────────────────────────────────────
        btn_frame = tk.Frame(root, bg=DARK["bg"])
        btn_frame.pack(fill=tk.X, padx=18, pady=(0, 6))

        self.start_btn = btn(btn_frame, "▶  Start Deep Recon",
                             self.start_investigation, color=DARK["accent"],
                             fg="#0a0a0a")
        self.start_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.cancel_btn = btn(btn_frame, "✕  Cancel",
                              self.cancel_scan, color=DARK["danger"],
                              state="disabled")
        self.cancel_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.clear_btn = btn(btn_frame, "⌫  Clear", self.clear_output)
        self.clear_btn.pack(side=tk.RIGHT, padx=(6, 0))

        self.open_log_btn = btn(btn_frame, "📄  Open Log",
                                self._open_log_file, state="disabled")
        self.open_log_btn.pack(side=tk.RIGHT, padx=(6, 0))

        self.delete_logs_btn = btn(btn_frame, "🗑  Delete Logs",
                                   self._delete_logs, color="#5a2a2a", fg="#ff9090")
        self.delete_logs_btn.pack(side=tk.RIGHT, padx=(6, 0))

        # ── advanced options (collapsible) ────────────────────────────────────
        self._section_vars = {key: tk.BooleanVar(value=True) for key, _ in SCAN_SECTIONS}
        self._adv_open = False

        self._adv_container = tk.Frame(root, bg=DARK["bg"])
        adv_container = self._adv_container
        adv_container.pack(fill=tk.X, padx=18, pady=(0, 4))

        self._adv_toggle_btn = tk.Button(
            adv_container,
            text="▸  Advanced Options",
            command=self._toggle_advanced,
            bg=DARK["bg"], fg=DARK["fg_dim"],
            activebackground=DARK["bg"], activeforeground=DARK["fg"],
            relief="flat", bd=0,
            padx=0, pady=4,
            font=("Segoe UI", 9, "italic"),
            cursor="hand2"
        )
        self._adv_toggle_btn.pack(side=tk.LEFT)

        # separator line
        tk.Frame(adv_container, bg=DARK["border"], height=1).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0), pady=0
        )

        self._adv_inner = tk.Frame(root, bg=DARK["bg"])
        # not packed yet — shown only when expanded

        # checkboxes in a 4-column grid
        cb_grid = tk.Frame(self._adv_inner, bg=DARK["bg"])
        cb_grid.pack(fill=tk.X, pady=(6, 2))
        COLS = 4
        for i, (key, lbl_text) in enumerate(SCAN_SECTIONS):
            var = self._section_vars[key]
            cb = tk.Checkbutton(
                cb_grid, text=lbl_text, variable=var,
                bg=DARK["bg"], fg=DARK["fg"],
                selectcolor=DARK["bg_widget"],
                activebackground=DARK["bg"],
                activeforeground=DARK["accent"],
                font=("Segoe UI", 9),
                cursor="hand2"
            )
            cb.grid(row=i // COLS, column=i % COLS, sticky="w", padx=(0, 18), pady=2)

        # select-all / clear-all convenience buttons
        ctrl_row = tk.Frame(self._adv_inner, bg=DARK["bg"])
        ctrl_row.pack(anchor="w", pady=(4, 6))
        tk.Button(
            ctrl_row, text="Select All",
            command=lambda: [v.set(True) for v in self._section_vars.values()],
            bg=DARK["btn_bg"], fg=DARK["fg_dim"],
            activebackground=DARK["btn_active"], activeforeground=DARK["fg"],
            relief="flat", bd=0, padx=10, pady=4,
            font=("Segoe UI", 8), cursor="hand2"
        ).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(
            ctrl_row, text="Clear All",
            command=lambda: [v.set(False) for v in self._section_vars.values()],
            bg=DARK["btn_bg"], fg=DARK["fg_dim"],
            activebackground=DARK["btn_active"], activeforeground=DARK["fg"],
            relief="flat", bd=0, padx=10, pady=4,
            font=("Segoe UI", 8), cursor="hand2"
        ).pack(side=tk.LEFT)

        # ── status bar ────────────────────────────────────────────────────────
        self.status_label = tk.Label(root, text="", fg=DARK["accent"],
                                     bg=DARK["bg"], font=("Segoe UI", 9, "italic"),
                                     anchor="w")
        self.status_label.pack(fill=tk.X, padx=20, pady=(2, 4))

        # ── output log ───────────────────────────────────────────────────────
        log_frame = tk.Frame(root, bg=DARK["border"])
        log_frame.pack(fill=tk.BOTH, expand=True, padx=18, pady=(0, 14))

        self.log_text = tk.Text(
            log_frame,
            bg=DARK["bg_widget"], fg=DARK["neon"],
            insertbackground=DARK["cursor"],
            selectbackground=DARK["accent"], selectforeground="#0a0a0a",
            relief="flat", bd=0,
            highlightthickness=0,
            font=("Consolas", 9),
            padx=10, pady=8,
            wrap=tk.WORD
        )
        scrollbar = tk.Scrollbar(log_frame, command=self.log_text.yview,
                                 bg=DARK["bg_widget"], troughcolor=DARK["bg"],
                                 relief="flat", bd=0, width=10)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # collapse advanced panel on any click outside it
        root.bind("<Button-1>", self._on_root_click, add="+")

        self._poll_log_queue()

    # ── advanced options toggle ───────────────────────────────────────────────
    def _is_inside_adv(self, widget):
        """Return True if widget is a descendant of the advanced options panel."""
        w = widget
        while w is not None:
            if w is self._adv_inner or w is self._adv_container:
                return True
            try:
                w = w.master
            except Exception:
                break
        return False

    def _on_root_click(self, event):
        """Collapse advanced panel when clicking anywhere outside it."""
        if self._adv_open and not self._is_inside_adv(event.widget):
            self._toggle_advanced()

    def _toggle_advanced(self):
        if self._adv_open:
            self._adv_inner.pack_forget()
            self._adv_toggle_btn.config(text="▸  Advanced Options")
            self._adv_open = False
        else:
            self._adv_inner.pack(fill=tk.X, padx=18, pady=(0, 4),
                                 before=self.status_label)
            self._adv_toggle_btn.config(text="▾  Advanced Options")
            self._adv_open = True

    def _poll_log_queue(self):
        """Drain the log queue and update the widget — always runs on the main thread."""
        try:
            while True:
                item = self._log_queue.get_nowait()
                if isinstance(item, dict):
                    if item.get('type') == 'done':
                        self._on_scan_done(item['log_file'])
                        break
                    if item.get('type') == 'status':
                        self.status_label.config(text=item['text'])
                        continue
                self.log_text.insert(tk.END, item)
                if self.log_text.yview()[1] >= 0.99:
                    self.log_text.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(50, self._poll_log_queue)

    def _on_scan_done(self, log_file):
        """Re-enable controls and show completion dialog — always called on the main thread."""
        self._last_log_file = log_file
        self.url_entry.config(state='normal')
        self.output_dir_entry.config(state='normal')
        self.start_btn.config(state='normal')
        self.cancel_btn.config(state='disabled')
        self.clear_btn.config(state='normal')
        self.open_log_btn.config(state='normal')
        if self._cancel_event.is_set():
            self.status_label.config(text="Cancelled.")
            messagebox.showinfo("Cancelled", f"Scan cancelled.\nPartial log saved to {log_file}")
        else:
            self.status_label.config(text="Scan complete.")
            messagebox.showinfo("Done", f"Deep recon finished!\nLog saved to {log_file}")

    def log(self, message, animate=True, delay=0.01):
        """Queue a line of text for the main thread."""
        self._log_queue.put(message + "\n")

    def write_section_header(self, logf, title):
        sep = "=" * 40
        header = f"\n{sep}\n[ {title.upper()} ]\n{sep}\n"
        self._log_queue.put(header + "\n")
        logf.write(header + "\n")

    def cancel_scan(self):
        self._cancel_event.set()
        self.cancel_btn.config(state='disabled')
        self.status_label.config(text="Cancelling...")

    def clear_output(self):
        self.log_text.delete('1.0', tk.END)

    def _open_log_file(self):
        if not self._last_log_file:
            return
        if os.name == 'nt':
            os.startfile(self._last_log_file)
        elif sys.platform == 'darwin':
            subprocess.Popen(['open', self._last_log_file])
        else:
            subprocess.Popen(['xdg-open', self._last_log_file])

    def _delete_logs(self):
        logs_dir = self.output_dir_entry.get().strip()
        if not os.path.isdir(logs_dir):
            messagebox.showerror("Error", "Logs directory not found.")
            return
        files = [f for f in os.listdir(logs_dir)
                 if os.path.isfile(os.path.join(logs_dir, f)) and f != ".gitkeep"]
        if not files:
            messagebox.showinfo("Delete Logs", "No log files to delete.")
            return
        confirm = messagebox.askyesno(
            "Delete Logs",
            f"Delete {len(files)} log file(s) from:\n{logs_dir}\n\nThis cannot be undone."
        )
        if not confirm:
            return
        errors = 0
        for f in files:
            try:
                os.remove(os.path.join(logs_dir, f))
            except Exception:
                errors += 1
        self._last_log_file = None
        self.open_log_btn.config(state="disabled")
        if errors:
            messagebox.showwarning("Delete Logs", f"Done — {errors} file(s) could not be deleted.")
        else:
            self.status_label.config(text=f"Deleted {len(files)} log file(s).")

    def start_investigation(self):
        # Collapse advanced panel (also fires when Enter is pressed in URL field)
        if self._adv_open:
            self._toggle_advanced()

        domain = self.url_entry.get().strip()
        outdir = self.output_dir_entry.get().strip()
        if not domain or domain == PLACEHOLDER:
            messagebox.showerror("Error", "Please enter a valid domain or URL.")
            return
        if not os.path.isdir(outdir):
            messagebox.showerror("Error", "Output directory does not exist.")
            return

        # Collect enabled flags on the main thread (BooleanVar must stay on main thread)
        enabled = {key: var.get() for key, var in self._section_vars.items()}
        if not any(enabled.values()):
            messagebox.showwarning(
                "No Tools Selected",
                "No scanning tools selected, please select a scanning tool and run again."
            )
            return

        self._cancel_event.clear()
        self.url_entry.config(state='disabled')
        self.output_dir_entry.config(state='disabled')
        self.start_btn.config(state='disabled')
        self.cancel_btn.config(state='normal')
        self.clear_btn.config(state='disabled')
        self.open_log_btn.config(state='disabled')
        self.status_label.config(text="Starting...")

        threading.Thread(target=self.deep_recon, args=(domain, outdir, enabled), daemon=True).start()

    def deep_recon(self, domain, outdir, enabled):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        safe_domain = re.sub(r'[\\/:*?"<>|]', '_', domain)
        log_file = os.path.join(outdir, f"deep_recon_{safe_domain}_{timestamp}.txt")

        self._log_queue.put(f"[*] Starting deep recon for: {domain}\n")
        try:
            _logf_handle = open(log_file, "w", encoding="utf-8")
        except Exception as e:
            self._log_queue.put(f"[!] Could not create log file: {e}\n")
            self._log_queue.put({'type': 'done', 'log_file': log_file})
            return
        with _logf_handle as logf:

            def write_log(m, animated=True):
                self.log(m, animate=animated)
                try:
                    logf.write(m + "\n")
                except Exception:
                    pass

            def is_cancelled():
                return self._cancel_event.is_set()

            def set_status(text):
                self._log_queue.put({'type': 'status', 'text': text})

            def on(key):
                """Return True if this section is enabled and scan is not cancelled."""
                return enabled.get(key, True) and not is_cancelled()

            if domain.startswith("http"):
                domain = urllib.parse.urlparse(domain).netloc

            write_log(f"Target domain: {domain}")

            # ── Resolve IP (shared dependency — always attempted) ─────────────
            ip = None
            try:
                ip = socket.gethostbyname(domain)
            except Exception as e:
                write_log(f"[!] Could not resolve IP: {e}")

            # ── DNS Records ───────────────────────────────────────────────────
            if on('dns'):
                set_status("Running: DNS Records...")
                self.write_section_header(logf, "DNS Records")
                for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
                    try:
                        answers = dns.resolver.resolve(domain, record_type, lifetime=5)
                        for rdata in answers:
                            write_log(f"{record_type}: {rdata.to_text()}")
                    except Exception as e:
                        write_log(f"{record_type}: No records found or error - {e}")

            # ── IP & WHOIS ────────────────────────────────────────────────────
            if on('whois'):
                set_status("Running: IP & WHOIS...")
                self.write_section_header(logf, "IP and WHOIS Info")
                if ip:
                    write_log(f"IP Address: {ip}")
                    try:
                        whois_obj = IPWhois(ip)
                        res = whois_obj.lookup_rdap(depth=1)
                        net = res.get('network', {})
                        for line in [
                            f"Network Name: {net.get('name', 'N/A')}",
                            f"Country: {net.get('country', 'N/A')}",
                            f"CIDR: {net.get('cidr', 'N/A')}",
                            f"ASN: {res.get('asn', 'N/A')}",
                            f"ASN Description: {res.get('asn_description', 'N/A')}"
                        ]:
                            write_log(line)
                    except IPDefinedError:
                        write_log("WHOIS info not available for private/reserved IP.")
                    except Exception as e:
                        write_log(f"WHOIS lookup failed: {e}")
                else:
                    write_log("IP resolution failed — skipping WHOIS.")

            # ── Geolocation ───────────────────────────────────────────────────
            if ip and on('geo'):
                set_status("Running: Geolocation...")
                self.write_section_header(logf, "Geolocation Info")
                try:
                    geo = requests.get(f"https://ip-api.com/json/{ip}", timeout=7).json()
                    for line in [
                        f"City: {geo.get('city', 'N/A')}",
                        f"Region: {geo.get('regionName', 'N/A')}",
                        f"Country: {geo.get('country', 'N/A')}",
                        f"Latitude: {geo.get('lat', 'N/A')}",
                        f"Longitude: {geo.get('lon', 'N/A')}",
                        f"ISP: {geo.get('isp', 'N/A')}",
                        f"Map: https://www.google.com/maps?q={geo.get('lat','')},{geo.get('lon','')}"
                    ]:
                        write_log(line)
                except Exception as e:
                    write_log(f"Location fetch failed: {e}")

            # ── Ping ──────────────────────────────────────────────────────────
            if on('ping'):
                set_status("Running: Ping Test...")
                self.write_section_header(logf, "Ping Test")
                try:
                    param = "-n" if os.name == "nt" else "-c"
                    result = subprocess.run(
                        ["ping", param, "4", domain],
                        capture_output=True, text=True, timeout=30,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                    )
                    write_log(result.stdout or result.stderr, animated=False)
                except subprocess.TimeoutExpired:
                    write_log("Ping timed out after 30s.")
                except Exception as e:
                    write_log(f"Ping test failed: {e}")

            # ── Traceroute ────────────────────────────────────────────────────
            if on('traceroute'):
                set_status("Running: Traceroute...")
                self.write_section_header(logf, "Traceroute")
                try:
                    if os.name == "nt":
                        traceroute_cmd = ["tracert", "-h", "15", domain]
                    else:
                        traceroute_cmd = ["traceroute", "-m", "15", domain]
                    result = subprocess.run(
                        traceroute_cmd, capture_output=True, text=True, timeout=90,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                    )
                    write_log(result.stdout or result.stderr, animated=False)
                except subprocess.TimeoutExpired:
                    write_log("Traceroute timed out after 90s — target may be filtering ICMP TTL-exceeded.")
                except Exception as e:
                    write_log(f"Traceroute failed: {e}")

            # ── Subdomain Enumeration ─────────────────────────────────────────
            found_subdomains = []
            if on('subdomains'):
                set_status("Running: Subdomain Enumeration...")
                self.write_section_header(logf, "Subdomain Enumeration")

                def check_subdomain(sub):
                    fqdn = f"{sub}.{domain}"
                    try:
                        ip_sub = socket.gethostbyname(fqdn)
                        return fqdn, ip_sub
                    except Exception:
                        return None

                with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    results = executor.map(check_subdomain, EXTENDED_SUBDOMAINS)
                for result in results:
                    if result:
                        fqdn, ip_sub = result
                        write_log(f"Found subdomain: {fqdn} -> {ip_sub}")
                        found_subdomains.append(fqdn)
                if not found_subdomains:
                    write_log("No common subdomains found.")

            # ── Admin Panel URLs ──────────────────────────────────────────────
            session = requests.Session()
            if on('admin'):
                set_status("Running: Admin Panel Detection...")
                self.write_section_header(logf, "Admin Panel URLs")
                targets = found_subdomains if found_subdomains else [domain]
                for sub in targets:
                    for base_url in [f"https://{sub}", f"http://{sub}"]:
                        for path in ADMIN_PATHS:
                            url = base_url + path
                            try:
                                r = session.head(url, allow_redirects=True, timeout=5)
                                if r.status_code in [200, 301, 302, 401, 403]:
                                    write_log(f"Possible admin panel found: {url} (Status: {r.status_code})")
                            except Exception:
                                pass

            # ── Exposed Files ─────────────────────────────────────────────────
            if on('exposed'):
                set_status("Running: Exposed Files Check...")
                self.write_section_header(logf, "Exposed Files Check")
                for base_url in [f"https://{domain}", f"http://{domain}"]:
                    for path in EXPOSED_PATHS:
                        url = base_url + path
                        try:
                            r = session.head(url, allow_redirects=True, timeout=5)
                            if r.status_code == 200:
                                write_log(f"Exposed file found: {url} (Status: {r.status_code})")
                        except Exception:
                            pass

            # ── SSL Certificate ───────────────────────────────────────────────
            if on('ssl'):
                set_status("Running: SSL Certificate...")
                self.write_section_header(logf, "SSL Certificate Info")
                try:
                    ctx = ssl.create_default_context()
                    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                        s.settimeout(5)
                        s.connect((domain, 443))
                        cert = s.getpeercert()

                        def parse_cert_field(field):
                            result = {}
                            for rdn in field:
                                for attr in rdn:
                                    result[attr[0]] = attr[1]
                            return result

                        subject = parse_cert_field(cert.get('subject', ()))
                        issuer = parse_cert_field(cert.get('issuer', ()))
                        for line in [
                            f"Subject: {subject.get('commonName', 'N/A')}",
                            f"Issuer: {issuer.get('commonName', 'N/A')}",
                            f"Valid From: {cert.get('notBefore', 'N/A')}",
                            f"Valid Until: {cert.get('notAfter', 'N/A')}"
                        ]:
                            write_log(line)
                except Exception as e:
                    write_log(f"SSL info retrieval failed: {e}")

            # ── Port Scanner ──────────────────────────────────────────────────
            if ip and on('ports'):
                set_status("Running: Port Scanner...")
                self.write_section_header(logf, "Port Scanner")

                def check_port(port):
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(1)
                        open_ = s.connect_ex((ip, port)) == 0
                        s.close()
                        return port, COMMON_PORTS[port], open_
                    except Exception:
                        return port, COMMON_PORTS[port], False

                with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    port_results = list(executor.map(check_port, COMMON_PORTS.keys()))
                port_results.sort(key=lambda x: x[0])
                for port, service, open_ in port_results:
                    status_str = "OPEN" if open_ else "closed"
                    write_log(f"  {port:5d}/tcp  {status_str:8s}  {service}", animated=False)

            # ── HTTP & Security Headers ───────────────────────────────────────
            homepage_resp = None
            if on('headers'):
                set_status("Running: HTTP & Security Headers...")
                self.write_section_header(logf, "HTTP & Security Headers")
                try:
                    homepage_resp = session.get(f"http://{domain}", headers=HEADERS_USER_AGENT, timeout=7)
                    headers = homepage_resp.headers
                    for k, v in headers.items():
                        write_log(f"{k}: {v}")
                    for sh in ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security',
                               'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy']:
                        write_log(f"Security Header - {sh}: {headers.get(sh, 'Not Found')}")
                except Exception as e:
                    write_log(f"HTTP headers fetch failed: {e}")

            # ── Wayback Machine ───────────────────────────────────────────────
            if on('wayback'):
                set_status("Running: Wayback Machine Lookup...")
                self.write_section_header(logf, "Wayback Machine Snapshot Info")
                try:
                    wb_url = WAYBACK_API.format(urllib.parse.quote(domain))
                    wb_resp = requests.get(wb_url, timeout=7).json()
                    if 'archived_snapshots' in wb_resp and wb_resp['archived_snapshots']:
                        closest = wb_resp['archived_snapshots'].get('closest', {})
                        write_log(f"Latest snapshot: {closest.get('url', 'N/A')}")
                        write_log(f"Snapshot timestamp: {closest.get('timestamp', 'N/A')}")
                    else:
                        write_log("No snapshots found.")
                except Exception as e:
                    write_log(f"Wayback Machine fetch failed: {e}")

            # ── CMS & Technology Detection ────────────────────────────────────
            if on('cms'):
                set_status("Running: CMS & Technology Detection...")
                self.write_section_header(logf, "CMS & Technology Detection")
                try:
                    resp = homepage_resp if homepage_resp is not None else session.get(
                        f"http://{domain}", headers=HEADERS_USER_AGENT, timeout=7)
                    text = resp.text.lower()
                    cms_tech = []
                    if 'wp-content' in text or 'wordpress' in text:
                        cms_tech.append("WordPress")
                    if 'joomla' in text:
                        cms_tech.append("Joomla")
                    if 'drupal' in text:
                        cms_tech.append("Drupal")
                    if 'shopify' in text:
                        cms_tech.append("Shopify")
                    if 'asp.net' in text or 'microsoft' in resp.headers.get('server', '').lower():
                        cms_tech.append("ASP.NET")
                    for c in cms_tech or ["Unknown or Custom CMS"]:
                        write_log(f"Detected CMS/Tech: {c}")
                except Exception as e:
                    write_log(f"CMS detection failed: {e}")

            # ── robots.txt & Sitemap ──────────────────────────────────────────
            if on('robots'):
                set_status("Running: robots.txt & Sitemap...")
                self.write_section_header(logf, "robots.txt & Sitemap")
                for path in ["/robots.txt", "/sitemap.xml"]:
                    found = False
                    for scheme in ["https", "http"]:
                        if is_cancelled():
                            break
                        try:
                            url = f"{scheme}://{domain}{path}"
                            r = session.get(url, headers=HEADERS_USER_AGENT, timeout=7, allow_redirects=True)
                            if r.status_code == 200:
                                write_log(f"[+] {path} ({url}):", animated=False)
                                lines = [ln for ln in r.text[:2000].splitlines() if ln.strip()]
                                for line in lines[:30]:
                                    write_log(f"    {line}", animated=False)
                                found = True
                                break
                        except Exception:
                            continue
                    if not found:
                        write_log(f"{path}: Not found.")

            # ── Email Harvesting ──────────────────────────────────────────────
            if on('email'):
                set_status("Running: Email Harvesting...")
                self.write_section_header(logf, "Email Harvesting")
                try:
                    resp = homepage_resp if homepage_resp is not None else session.get(
                        f"http://{domain}", headers=HEADERS_USER_AGENT, timeout=7)
                    emails = set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', resp.text))
                    if emails:
                        for e in emails:
                            write_log(f"Found email: {e}")
                    else:
                        write_log("No emails found on homepage.")
                except Exception as e:
                    write_log(f"Email harvesting failed: {e}")

            # ── Full Port Scan (1–65535) ──────────────────────────────────────
            if ip and on('fullports'):
                set_status("Running: Full Port Scan (1–65535)...")
                self.write_section_header(logf, "Full Port Scan (1 – 65535)")

                def check_port_full(port):
                    if is_cancelled():
                        return port, False
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        open_ = s.connect_ex((ip, port)) == 0
                        s.close()
                        return port, open_
                    except Exception:
                        return port, False

                full_open_ports = []
                completed = 0
                with ThreadPoolExecutor(max_workers=500) as executor:
                    futures = [executor.submit(check_port_full, p) for p in range(1, TOTAL_PORTS + 1)]
                    for future in as_completed(futures):
                        if is_cancelled():
                            break
                        port, is_open = future.result()
                        completed += 1
                        if is_open:
                            service = COMMON_PORTS.get(port, "unknown")
                            write_log(f"  {port:5d}/tcp  OPEN      {service}", animated=False)
                            full_open_ports.append(port)
                        if completed % 2000 == 0 or completed == TOTAL_PORTS:
                            pct = int(completed / TOTAL_PORTS * 100)
                            set_status(f"Full port scan: {completed:,}/{TOTAL_PORTS:,} ({pct}%)")
                full_open_ports.sort()
                if full_open_ports:
                    write_log(f"[+] {len(full_open_ports)} open port(s): {', '.join(str(p) for p in full_open_ports)}", animated=False)
                else:
                    write_log("[–] No open ports found.", animated=False)

            # ── Completion ────────────────────────────────────────────────────
            if is_cancelled():
                write_log("[!] Scan cancelled by user.")
            else:
                write_log("\n[✔] Deep recon finished.")
            logf.flush()

        self._log_queue.put({'type': 'done', 'log_file': log_file})


if __name__ == "__main__":
    root = tk.Tk()
    app = ReconApp(root)
    root.mainloop()
