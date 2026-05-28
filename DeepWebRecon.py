"""
Deep Web Recon — domain reconnaissance tool.

Performs DNS, WHOIS, geolocation, port scanning, subdomain enumeration,
SSL inspection, HTTP header analysis, CMS detection, exposed file checks,
Wayback Machine lookup, robots.txt fetch, and email harvesting.

Scan logic runs in a background daemon thread. All Tkinter widget access
happens on the main thread via a queue.Queue drained by root.after(50).
"""

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
import html
import dns.resolver
import dns.zone
import dns.query
import dns.exception
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
import urllib.parse
import time
import re
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "0.2.0"

# ---------------------------------------------------------------------------
# Strict hostname validation — accepts only valid DNS labels.
# Rejects raw IPs, shell metacharacters, URLs with schemes, and IDN labels
# that haven't been Punycode-encoded.
# ---------------------------------------------------------------------------
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

# ---------------------------------------------------------------------------
# Subdomain wordlist — 130+ entries covering common infrastructure, DevOps,
# auth, CDN, monitoring, regional, and application prefixes.
# ---------------------------------------------------------------------------
EXTENDED_SUBDOMAINS = [
    # Core web
    "www", "www2", "m", "mobile",
    # Mail
    "mail", "mail2", "webmail", "webmail2", "smtp", "pop", "pop3", "imap",
    "mx", "mx1", "mx2", "relay", "email",
    # DNS
    "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    # Remote access
    "vpn", "vpn2", "remote", "rdp", "citrix", "gateway",
    # Admin / control panels
    "admin", "administrator", "adminpanel", "panel", "manage", "management",
    "dashboard", "cpanel", "whm", "webdisk", "plesk", "directadmin",
    # Development
    "dev", "development", "staging", "stage", "test", "testing", "qa", "uat",
    "sandbox", "preview", "demo", "beta", "alpha", "canary",
    # API & apps
    "api", "api2", "api-v1", "api-v2", "api-v3", "app", "apps", "v1", "v2",
    "service", "services", "backend", "frontend",
    # Auth
    "auth", "sso", "login", "logout", "oauth", "id", "identity", "account",
    "accounts", "secure", "security", "portal",
    # CDN / static
    "cdn", "static", "assets", "images", "img", "image", "media",
    "files", "downloads", "uploads", "dl", "data",
    # Content
    "blog", "news", "forum", "community", "help", "support", "docs",
    "documentation", "wiki", "kb", "faq", "shop", "store", "cart",
    "checkout", "pay", "payment", "billing",
    # Infrastructure
    "ftp", "ssh", "proxy", "server", "server1", "server2", "web", "web1", "web2",
    "db", "database", "mysql", "postgres", "mongodb", "redis", "memcache",
    "phpmyadmin", "adminer",
    # DevOps
    "git", "gitlab", "github", "bitbucket", "svn", "repo", "registry",
    "jenkins", "ci", "cd", "build", "deploy", "devops",
    "jira", "confluence", "sonar", "nexus", "artifactory",
    "monitor", "status", "metrics", "grafana",
    "kibana", "elastic", "logs", "logging", "sentry",
    # Cloud
    "cloud", "cluster", "k8s", "kubernetes", "docker",
    # Communication
    "chat", "video", "meet", "call",
    # Office / internal
    "intranet", "internal", "office", "hr", "erp", "crm",
    # Misc legacy
    "old", "new", "legacy", "archive", "backup",
    "cp", "autodiscover", "exchange", "owa",
    # Regional
    "us", "eu", "uk", "asia", "au", "ca", "de", "fr",
]

ADMIN_PATHS = [
    "/admin", "/administrator", "/adminpanel", "/cpanel", "/login",
    "/user", "/wp-admin", "/manager", "/secure", "/admin/login",
    "/dashboard", "/manage", "/control", "/panel",
]

# ---------------------------------------------------------------------------
# Expanded exposed-file path list.  HEAD is tried first; if the server
# blocks HEAD, the caller notes it and moves on (no silent GET fallback that
# could download large files).
# ---------------------------------------------------------------------------
EXPOSED_PATHS = [
    # Git exposure
    "/.git/", "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
    # SVN exposure
    "/.svn/entries", "/.svn/wc.db",
    # Environment / config files
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.php", "/config.yml", "/config.yaml", "/config.json",
    "/web.config", "/.htaccess",
    # Database dumps
    "/db_backup.sql", "/dump.sql", "/backup.sql", "/database.sql",
    # Archives
    "/backup.zip", "/backup.tar.gz", "/site_backup.zip",
    # PHP info pages
    "/phpinfo.php", "/info.php", "/test.php",
    # macOS metadata (reveals directory structure)
    "/.DS_Store",
    # Package manifests (reveal tech stack)
    "/package.json", "/composer.json",
    # Package manager credentials
    "/.npmrc", "/.pypirc",
    # SSH keys accidentally committed
    "/id_rsa", "/id_rsa.pub",
    # WordPress config backups
    "/wp-config.php.bak", "/wp-config.php~", "/wp-config.txt",
    # Flash/Silverlight legacy policy files
    "/crossdomain.xml", "/clientaccesspolicy.xml",
]

# CDX API returns up to 10 unique archived URLs for the domain and all subdomains.
WAYBACK_CDX_API = (
    "https://web.archive.org/cdx/search/cdx"
    "?url={domain}&output=json&fl=original,statuscode,timestamp"
    "&limit=10&collapse=urlkey&matchType=domain"
)

HEADERS_USER_AGENT = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/114.0.0.0 Safari/537.36"
    )
}

MAX_THREADS = 15          # subdomain enumeration / quick port scan
TOTAL_PORTS = 65535
FULL_SCAN_WORKERS = 100   # reduced from 500 — prevents accidental DoS behaviour

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

# Security headers to check — includes COOP/COEP/CORP (added in this revision)
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
]

PLACEHOLDER = "enter target URL / domain here"

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


class ReconApp:
    """Main application window for Deep Web Recon.

    All scan logic runs in a background daemon thread.  Widget updates are
    delivered via a queue.Queue that the main thread drains every 50 ms using
    root.after().  BooleanVar values are read on the main thread before the
    worker starts — never inside the worker.
    """

    def __init__(self, root):
        """Build all widgets and start the log-queue poller."""
        self.root = root
        self.root.title("Deep Web Recon")
        self.root.geometry("760x860")
        self.root.configure(bg=DARK["bg"])
        self.root.resizable(True, True)

        try:
            icon_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "assets", "radar.png"
            )
            self._icon = tk.PhotoImage(file=icon_path)
            self.root.iconphoto(True, self._icon)
        except Exception:
            pass  # icon missing or unsupported — fail silently

        self._log_queue = queue.Queue()
        self._cancel_event = threading.Event()
        self._last_log_file = None
        self._log_write_failed = False  # set once when the first log write fails

        # ── widget factories ──────────────────────────────────────────────────
        def label(parent, text, dim=True):
            fg = DARK["fg_dim"] if dim else DARK["fg"]
            return tk.Label(parent, text=text, bg=DARK["bg"], fg=fg,
                            font=("Segoe UI", 9), anchor="w")

        def entry(parent):
            return tk.Entry(parent,
                            bg=DARK["bg_widget"], fg=DARK["fg"],
                            insertbackground=DARK["cursor"],
                            relief="flat", highlightthickness=1,
                            highlightbackground=DARK["border"],
                            highlightcolor=DARK["accent"],
                            font=("Consolas", 9))

        def btn(parent, text, command, color=None, fg=None, **kw):
            bg = color or DARK["btn_bg"]
            return tk.Button(parent, text=text, command=command,
                             bg=bg, fg=fg or DARK["btn_fg"],
                             activebackground=DARK["btn_active"],
                             activeforeground=DARK["fg"],
                             relief="flat", bd=0, padx=12, pady=6,
                             font=("Segoe UI", 9), cursor="hand2", **kw)

        # ── top control panel ─────────────────────────────────────────────────
        panel = tk.Frame(root, bg=DARK["bg"])
        panel.pack(fill=tk.X, padx=18, pady=(16, 0))
        panel.columnconfigure(1, weight=1)

        label(panel, "Target Domain / URL:").grid(
            row=0, column=0, sticky="w", pady=(0, 2))
        self.url_entry = entry(panel)
        self.url_entry.grid(row=1, column=0, columnspan=2,
                            sticky="ew", pady=(0, 10), ipady=4)
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
        default_logs_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "logs"
        )
        os.makedirs(default_logs_dir, exist_ok=True)
        self.output_dir_entry.insert(0, default_logs_dir)

        # ── button row ────────────────────────────────────────────────────────
        btn_frame = tk.Frame(root, bg=DARK["bg"])
        btn_frame.pack(fill=tk.X, padx=18, pady=(0, 6))

        self.start_btn = btn(btn_frame, "▶  Start Deep Recon",
                             self.start_investigation,
                             color=DARK["accent"], fg="#0a0a0a")
        self.start_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.cancel_btn = btn(btn_frame, "✕  Cancel",
                              self.cancel_scan,
                              color=DARK["danger"], state="disabled")
        self.cancel_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.clear_btn = btn(btn_frame, "⌫  Clear", self.clear_output)
        self.clear_btn.pack(side=tk.RIGHT, padx=(6, 0))

        self.open_log_btn = btn(btn_frame, "\U0001f4c4  Open Log",
                                self._open_log_file, state="disabled")
        self.open_log_btn.pack(side=tk.RIGHT, padx=(6, 0))

        self.delete_logs_btn = btn(btn_frame, "\U0001f5d1  Delete Logs",
                                   self._delete_logs,
                                   color="#5a2a2a", fg="#ff9090")
        self.delete_logs_btn.pack(side=tk.RIGHT, padx=(6, 0))

        # ── advanced options (collapsible) ────────────────────────────────────
        # BooleanVars are created here on the main thread and ONLY read on the
        # main thread (in start_investigation) before the worker starts.
        self._section_vars = {key: tk.BooleanVar(value=True) for key, _ in SCAN_SECTIONS}
        self._adv_open = False

        self._adv_container = tk.Frame(root, bg=DARK["bg"])
        self._adv_container.pack(fill=tk.X, padx=18, pady=(0, 4))

        self._adv_toggle_btn = tk.Button(
            self._adv_container,
            text="▸  Advanced Options",
            command=self._toggle_advanced,
            bg=DARK["bg"], fg=DARK["fg_dim"],
            activebackground=DARK["bg"], activeforeground=DARK["fg"],
            relief="flat", bd=0, padx=0, pady=4,
            font=("Segoe UI", 9, "italic"), cursor="hand2",
        )
        self._adv_toggle_btn.pack(side=tk.LEFT)

        tk.Frame(self._adv_container, bg=DARK["border"], height=1).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0), pady=0
        )

        self._adv_inner = tk.Frame(root, bg=DARK["bg"])

        cb_grid = tk.Frame(self._adv_inner, bg=DARK["bg"])
        cb_grid.pack(fill=tk.X, pady=(6, 2))
        COLS = 4
        for i, (key, lbl_text) in enumerate(SCAN_SECTIONS):
            cb = tk.Checkbutton(
                cb_grid, text=lbl_text, variable=self._section_vars[key],
                bg=DARK["bg"], fg=DARK["fg"],
                selectcolor=DARK["bg_widget"],
                activebackground=DARK["bg"], activeforeground=DARK["accent"],
                font=("Segoe UI", 9), cursor="hand2",
            )
            cb.grid(row=i // COLS, column=i % COLS,
                    sticky="w", padx=(0, 18), pady=2)

        ctrl_row = tk.Frame(self._adv_inner, bg=DARK["bg"])
        ctrl_row.pack(anchor="w", pady=(4, 6))
        for txt, val in [("Select All", True), ("Clear All", False)]:
            tk.Button(
                ctrl_row, text=txt,
                command=lambda v=val: [var.set(v) for var in self._section_vars.values()],
                bg=DARK["btn_bg"], fg=DARK["fg_dim"],
                activebackground=DARK["btn_active"], activeforeground=DARK["fg"],
                relief="flat", bd=0, padx=10, pady=4,
                font=("Segoe UI", 8), cursor="hand2",
            ).pack(side=tk.LEFT, padx=(0, 6))

        # ── status bar ────────────────────────────────────────────────────────
        self.status_label = tk.Label(
            root, text="", fg=DARK["accent"], bg=DARK["bg"],
            font=("Segoe UI", 9, "italic"), anchor="w"
        )
        self.status_label.pack(fill=tk.X, padx=20, pady=(2, 4))

        # ── output log ────────────────────────────────────────────────────────
        log_frame = tk.Frame(root, bg=DARK["border"])
        log_frame.pack(fill=tk.BOTH, expand=True, padx=18, pady=(0, 14))

        self.log_text = tk.Text(
            log_frame,
            bg=DARK["bg_widget"], fg=DARK["neon"],
            insertbackground=DARK["cursor"],
            selectbackground=DARK["accent"], selectforeground="#0a0a0a",
            relief="flat", bd=0, highlightthickness=0,
            font=("Consolas", 9), padx=10, pady=8, wrap=tk.WORD,
        )
        scrollbar = tk.Scrollbar(
            log_frame, command=self.log_text.yview,
            bg=DARK["bg_widget"], troughcolor=DARK["bg"],
            relief="flat", bd=0, width=10,
        )
        self.log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        root.bind("<Button-1>", self._on_root_click, add="+")
        self._poll_log_queue()

    # ── advanced options toggle ───────────────────────────────────────────────

    def _is_inside_adv(self, widget):
        """Return True if *widget* is a descendant of the advanced-options panel."""
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
        """Collapse the advanced panel when the user clicks outside it."""
        if self._adv_open and not self._is_inside_adv(event.widget):
            self._toggle_advanced()

    def _toggle_advanced(self):
        """Show or hide the advanced-options section."""
        if self._adv_open:
            self._adv_inner.pack_forget()
            self._adv_toggle_btn.config(text="▸  Advanced Options")
            self._adv_open = False
        else:
            self._adv_inner.pack(fill=tk.X, padx=18, pady=(0, 4),
                                 before=self.status_label)
            self._adv_toggle_btn.config(text="▾  Advanced Options")
            self._adv_open = True

    # ── queue / UI plumbing ───────────────────────────────────────────────────

    def _poll_log_queue(self):
        """Drain the log queue and update the widget — always runs on the main thread."""
        try:
            while True:
                item = self._log_queue.get_nowait()
                if isinstance(item, dict):
                    if item.get("type") == "done":
                        self._on_scan_done(item["log_file"])
                        break
                    if item.get("type") == "status":
                        self.status_label.config(text=item["text"])
                        continue
                self.log_text.insert(tk.END, item)
                if self.log_text.yview()[1] >= 0.99:
                    self.log_text.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(50, self._poll_log_queue)

    def _on_scan_done(self, log_file):
        """Re-enable controls after the scan completes or is cancelled."""
        self._last_log_file = log_file
        self.url_entry.config(state="normal")
        self.output_dir_entry.config(state="normal")
        self.start_btn.config(state="normal")
        self.cancel_btn.config(state="disabled")
        self.clear_btn.config(state="normal")
        self.open_log_btn.config(state="normal")
        if self._cancel_event.is_set():
            self.status_label.config(text="Cancelled.")
            messagebox.showinfo("Cancelled",
                                f"Scan cancelled.\nPartial log saved to {log_file}")
        else:
            self.status_label.config(text="Scan complete.")
            messagebox.showinfo("Done",
                                f"Deep recon finished!\nLog saved to {log_file}")

    def _safe_log_write(self, logf, text):
        """Write *text* to the log file; warn once in the status bar on failure."""
        try:
            logf.write(text + "\n")
        except Exception:
            if not self._log_write_failed:
                self._log_write_failed = True
                self._log_queue.put({
                    "type": "status",
                    "text": "[!] Log write failed — disk full or permission error",
                })

    def write_section_header(self, logf, title):
        """Write a visual section divider to both the GUI queue and the log file."""
        sep = "=" * 40
        header = f"\n{sep}\n[ {title.upper()} ]\n{sep}\n"
        self._log_queue.put(header + "\n")
        self._safe_log_write(logf, header)

    # ── controls ──────────────────────────────────────────────────────────────

    def log(self, message, animate=True, delay=0.01):
        """Queue a line of text for display on the main thread."""
        self._log_queue.put(message + "\n")

    def cancel_scan(self):
        """Signal the background thread to stop after its current operation."""
        self._cancel_event.set()
        self.cancel_btn.config(state="disabled")
        self.status_label.config(text="Cancelling...")

    def clear_output(self):
        """Clear the on-screen log text widget."""
        self.log_text.delete("1.0", tk.END)

    def _open_log_file(self):
        """Open the last-written log file in the system default text viewer."""
        if not self._last_log_file:
            return
        if os.name == "nt":
            os.startfile(self._last_log_file)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", self._last_log_file])
        else:
            subprocess.Popen(["xdg-open", self._last_log_file])

    def _delete_logs(self):
        """Delete all log files in the output directory after user confirmation."""
        logs_dir = self.output_dir_entry.get().strip()
        if not os.path.isdir(logs_dir):
            messagebox.showerror("Error", "Logs directory not found.")
            return
        files = [f for f in os.listdir(logs_dir)
                 if os.path.isfile(os.path.join(logs_dir, f))]
        if not files:
            messagebox.showinfo("Delete Logs", "No log files to delete.")
            return
        if not messagebox.askyesno(
            "Delete Logs",
            f"Delete {len(files)} log file(s) from:\n{logs_dir}\n\nThis cannot be undone.",
        ):
            return
        errors = sum(
            1 for f in files
            if not self._try_delete(os.path.join(logs_dir, f))
        )
        self._last_log_file = None
        self.open_log_btn.config(state="disabled")
        if errors:
            messagebox.showwarning("Delete Logs",
                                   f"Done — {errors} file(s) could not be deleted.")
        else:
            self.status_label.config(text=f"Deleted {len(files)} log file(s).")

    @staticmethod
    def _try_delete(path):
        """Delete *path*; return True on success, False on failure."""
        try:
            os.remove(path)
            return True
        except Exception:
            return False

    # ── scan entry point ─────────────────────────────────────────────────────

    def start_investigation(self):
        """Validate inputs on the main thread and launch the background scan."""
        if self._adv_open:
            self._toggle_advanced()

        raw = self.url_entry.get().strip()
        if not raw or raw == PLACEHOLDER:
            messagebox.showerror("Error", "Please enter a valid domain or URL.")
            return

        # Strip scheme / port so we validate only the hostname component.
        if raw.startswith(("http://", "https://")):
            hostname = urllib.parse.urlparse(raw).netloc.split(":")[0]
        else:
            hostname = raw.split(":")[0]

        if not _DOMAIN_RE.match(hostname):
            messagebox.showerror(
                "Invalid Domain",
                f"'{hostname}' is not a valid hostname.\n\n"
                "Enter a domain like example.com or sub.example.com.\n"
                "IP addresses and shell characters are not accepted.",
            )
            return

        outdir = self.output_dir_entry.get().strip()
        if not os.path.isdir(outdir):
            messagebox.showerror("Error", "Output directory does not exist.")
            return

        # BooleanVars MUST be read on the main thread before the worker starts.
        enabled = {key: var.get() for key, var in self._section_vars.items()}
        if not any(enabled.values()):
            messagebox.showwarning(
                "No Tools Selected",
                "No scanning tools selected. Please select at least one and try again.",
            )
            return

        self._cancel_event.clear()
        self._log_write_failed = False
        for widget in (self.url_entry, self.output_dir_entry):
            widget.config(state="disabled")
        self.start_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")
        self.clear_btn.config(state="disabled")
        self.open_log_btn.config(state="disabled")
        self.status_label.config(text="Starting...")

        threading.Thread(
            target=self.deep_recon,
            args=(hostname, outdir, enabled),
            daemon=True,
        ).start()

    # ── background scan ───────────────────────────────────────────────────────

    def deep_recon(self, domain, outdir, enabled):
        """Open the log file and run all enabled scan sections.

        The try/finally block guarantees that the 'done' sentinel is always
        put on the queue so the GUI never gets stuck in the scanning state,
        even if an unexpected exception escapes _run_scan().
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        # Strip every character that isn't a word char, hyphen, or dot to
        # prevent filesystem issues on any platform (Windows, macOS, Linux).
        safe_domain = re.sub(r"[^\w\-.]", "_", domain)
        log_file = os.path.join(outdir, f"deep_recon_{safe_domain}_{timestamp}.txt")

        self._log_queue.put(f"[*] Starting deep recon for: {domain}\n")
        try:
            logf_handle = open(log_file, "w", encoding="utf-8")
        except Exception as e:
            self._log_queue.put(f"[!] Could not create log file: {e}\n")
            self._log_queue.put({"type": "done", "log_file": log_file})
            return

        try:
            with logf_handle as logf:
                self._run_scan(domain, logf, enabled)
        except Exception as e:
            self._log_queue.put(f"[!] Unexpected scan error: {e}\n")
        finally:
            self._log_queue.put({"type": "done", "log_file": log_file})

    def _run_scan(self, domain, logf, enabled):
        """Execute each enabled scan section sequentially inside the worker thread."""

        def write_log(m):
            self._log_queue.put(m + "\n")
            self._safe_log_write(logf, m)

        def is_cancelled():
            return self._cancel_event.is_set()

        def set_status(text):
            self._log_queue.put({"type": "status", "text": text})

        def on(key):
            """Return True when section *key* is enabled and the scan is not cancelled."""
            return enabled.get(key, True) and not is_cancelled()

        write_log(f"Target domain : {domain}")
        write_log(f"Tool version  : Deep Web Recon v{__version__}")
        write_log(f"Scan started  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # ── Resolve IP (shared by geo / ports / fullports) ────────────────────
        ip = None
        try:
            ip = socket.gethostbyname(domain)
        except Exception as e:
            write_log(f"[!] Could not resolve IP: {e}")

        # ── DNS Records ───────────────────────────────────────────────────────
        if on("dns"):
            set_status("Running: DNS Records...")
            self.write_section_header(logf, "DNS Records")
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5

            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"):
                try:
                    for rdata in resolver.resolve(domain, rtype):
                        write_log(f"{rtype}: {rdata.to_text()}")
                except dns.resolver.NXDOMAIN:
                    write_log(f"{rtype}: Domain does not exist (NXDOMAIN)")
                except dns.resolver.NoAnswer:
                    write_log(f"{rtype}: No records found")
                except dns.resolver.NoNameservers:
                    write_log(f"{rtype}: No nameservers available")
                except Exception as e:
                    write_log(f"{rtype}: Error — {e}")

            # DMARC TXT lives at _dmarc.<domain>
            try:
                for rdata in resolver.resolve(f"_dmarc.{domain}", "TXT"):
                    write_log(f"DMARC: {rdata.to_text()}")
            except Exception:
                write_log("DMARC: No _dmarc record found")

            # AXFR zone transfer attempt — succeeds only on misconfigured servers
            try:
                ns_answers = resolver.resolve(domain, "NS")
                nameservers = [str(ns.target).rstrip(".") for ns in ns_answers]
                axfr_succeeded = False
                for ns in nameservers[:3]:
                    try:
                        xfr_gen = dns.query.xfr(ns, domain, timeout=5)
                        z = dns.zone.from_xfr(xfr_gen)
                        write_log(
                            f"[!] AXFR SUCCEEDED on {ns} — zone transfer is ALLOWED! Full zone:"
                        )
                        for name in sorted(z.nodes.keys()):
                            node = z[name]
                            for rdataset in node.rdatasets:
                                write_log(f"  {name} {rdataset}")
                        axfr_succeeded = True
                        break
                    except (dns.exception.FormError, EOFError,
                            ConnectionRefusedError, OSError, TimeoutError):
                        pass  # refused — expected on properly secured servers
                    except Exception:
                        pass
                if not axfr_succeeded:
                    write_log("AXFR: Zone transfer not permitted (expected on secure servers)")
            except Exception:
                pass

        # ── IP & WHOIS ────────────────────────────────────────────────────────
        if on("whois"):
            set_status("Running: IP & WHOIS...")
            self.write_section_header(logf, "IP and WHOIS Info")
            if ip:
                write_log(f"IP Address: {ip}")
                try:
                    res = IPWhois(ip).lookup_rdap(depth=1)
                    net = res.get("network", {})
                    for line in (
                        f"Network Name: {net.get('name', 'N/A')}",
                        f"Country: {net.get('country', 'N/A')}",
                        f"CIDR: {net.get('cidr', 'N/A')}",
                        f"ASN: {res.get('asn', 'N/A')}",
                        f"ASN Description: {res.get('asn_description', 'N/A')}",
                    ):
                        write_log(line)
                except IPDefinedError:
                    write_log("WHOIS: Not available for private/reserved IP.")
                except Exception as e:
                    write_log(f"WHOIS lookup failed: {e}")
            else:
                write_log("IP resolution failed — skipping WHOIS.")

        # ── Geolocation ───────────────────────────────────────────────────────
        if ip and on("geo"):
            set_status("Running: Geolocation...")
            self.write_section_header(logf, "Geolocation Info")
            try:
                geo = requests.get(
                    f"https://ip-api.com/json/{ip}", timeout=7
                ).json()
                for line in (
                    f"City: {geo.get('city', 'N/A')}",
                    f"Region: {geo.get('regionName', 'N/A')}",
                    f"Country: {geo.get('country', 'N/A')}",
                    f"Latitude: {geo.get('lat', 'N/A')}",
                    f"Longitude: {geo.get('lon', 'N/A')}",
                    f"ISP: {geo.get('isp', 'N/A')}",
                    f"Map: https://www.google.com/maps?q={geo.get('lat','')},{geo.get('lon','')}",
                ):
                    write_log(line)
            except Exception as e:
                write_log(f"Geolocation fetch failed: {e}")

        # ── Ping ──────────────────────────────────────────────────────────────
        if on("ping"):
            set_status("Running: Ping Test...")
            self.write_section_header(logf, "Ping Test")
            try:
                param = "-n" if os.name == "nt" else "-c"
                result = subprocess.run(
                    ["ping", param, "4", domain],
                    capture_output=True, text=True, timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                write_log(result.stdout or result.stderr)
            except subprocess.TimeoutExpired:
                write_log("Ping timed out after 30 s.")
            except Exception as e:
                write_log(f"Ping failed: {e}")

        # ── Traceroute ────────────────────────────────────────────────────────
        if on("traceroute"):
            set_status("Running: Traceroute...")
            self.write_section_header(logf, "Traceroute")
            try:
                cmd = (["tracert", "-h", "15", domain] if os.name == "nt"
                       else ["traceroute", "-m", "15", domain])
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=90,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                write_log(result.stdout or result.stderr)
            except subprocess.TimeoutExpired:
                write_log("Traceroute timed out after 90 s — target may filter ICMP TTL-exceeded.")
            except Exception as e:
                write_log(f"Traceroute failed: {e}")

        # ── Subdomain Enumeration ─────────────────────────────────────────────
        found_subdomains = []
        if on("subdomains"):
            set_status("Running: Subdomain Enumeration...")
            self.write_section_header(logf, "Subdomain Enumeration")

            def check_subdomain(sub):
                fqdn = f"{sub}.{domain}"
                try:
                    answers = dns.resolver.resolve(fqdn, "A", lifetime=3)
                    return fqdn, answers[0].to_text()
                except dns.resolver.NXDOMAIN:
                    return None  # expected — subdomain doesn't exist
                except dns.resolver.NoAnswer:
                    return None
                except dns.resolver.NoNameservers:
                    write_log("[!] DNS resolver unavailable during subdomain check")
                    return None
                except Exception:
                    return None

            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                results = list(executor.map(check_subdomain, EXTENDED_SUBDOMAINS))

            for result in results:
                if result:
                    fqdn, ip_sub = result
                    write_log(f"Found: {fqdn} -> {ip_sub}")
                    found_subdomains.append(fqdn)

            if not found_subdomains:
                write_log("No common subdomains resolved.")

        # ── Admin Panel Detection ─────────────────────────────────────────────
        if on("admin"):
            set_status("Running: Admin Panel Detection...")
            self.write_section_header(logf, "Admin Panel URLs")
            # Fresh session per section — no cookie state carried in from earlier
            admin_session = requests.Session()
            targets = found_subdomains if found_subdomains else [domain]
            for sub in targets:
                for base_url in (f"https://{sub}", f"http://{sub}"):
                    for path in ADMIN_PATHS:
                        if is_cancelled():
                            break
                        url = base_url + path
                        try:
                            # No redirect following: a redirect to another domain
                            # would leak the scan to a third-party server.
                            r = admin_session.head(
                                url, allow_redirects=False, timeout=5,
                                headers=HEADERS_USER_AGENT,
                            )
                            if r.status_code in (200, 401, 403):
                                write_log(f"Possible admin panel: {url} (HTTP {r.status_code})")
                            elif r.status_code in (301, 302, 307, 308):
                                dest = r.headers.get("Location", "unknown")
                                write_log(
                                    f"Redirect: {url} -> {dest} (HTTP {r.status_code})"
                                )
                        except Exception:
                            pass

        # ── Exposed Files ─────────────────────────────────────────────────────
        if on("exposed"):
            set_status("Running: Exposed Files Check...")
            self.write_section_header(logf, "Exposed Files Check")
            exposed_session = requests.Session()
            for base_url in (f"https://{domain}", f"http://{domain}"):
                for path in EXPOSED_PATHS:
                    if is_cancelled():
                        break
                    url = base_url + path
                    try:
                        r = exposed_session.head(
                            url, allow_redirects=False, timeout=5,
                            headers=HEADERS_USER_AGENT,
                        )
                        if r.status_code == 200:
                            write_log(f"[!] EXPOSED (200 OK): {url}")
                        elif r.status_code == 403:
                            # 403 means the file exists but access is restricted
                            write_log(f"[~] Likely exists (403 Forbidden): {url}")
                    except Exception:
                        pass

        # ── SSL Certificate ───────────────────────────────────────────────────
        if on("ssl"):
            set_status("Running: SSL Certificate...")
            self.write_section_header(logf, "SSL Certificate Info")
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                    s.settimeout(5)
                    s.connect((domain, 443))
                    cert = s.getpeercert()
                    tls_version = s.version()
                    cipher_name, cipher_proto, cipher_bits = s.cipher()

                def _parse_rdn(field):
                    out = {}
                    for rdn in field:
                        for attr in rdn:
                            out[attr[0]] = attr[1]
                    return out

                subject = _parse_rdn(cert.get("subject", ()))
                issuer = _parse_rdn(cert.get("issuer", ()))
                sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

                for line in (
                    f"Subject    : {subject.get('commonName', 'N/A')}",
                    f"Issuer     : {issuer.get('commonName', 'N/A')}",
                    f"Valid From : {cert.get('notBefore', 'N/A')}",
                    f"Valid Until: {cert.get('notAfter', 'N/A')}",
                    f"TLS Version: {tls_version}",
                    f"Cipher     : {cipher_name} ({cipher_proto}, {cipher_bits}-bit)",
                    f"SANs ({len(sans)}): {', '.join(sans[:10])}"
                    + (" ..." if len(sans) > 10 else ""),
                ):
                    write_log(line)

                if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    write_log(
                        f"[!] WARNING: {tls_version} is deprecated and insecure"
                    )

            except ssl.SSLCertVerificationError as e:
                write_log(f"[!] Certificate verification failed: {e}")
            except Exception as e:
                write_log(f"SSL info retrieval failed: {e}")

        # ── Port Scanner (quick) ──────────────────────────────────────────────
        if ip and on("ports"):
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
            for port, service, open_ in sorted(port_results, key=lambda x: x[0]):
                write_log(f"  {port:5d}/tcp  {'OPEN' if open_ else 'closed':8s}  {service}")

        # ── HTTP & Security Headers ───────────────────────────────────────────
        # homepage_resp is captured here and reused by CMS / email sections
        # when they are also enabled, to avoid a redundant fetch.
        homepage_resp = None
        if on("headers"):
            set_status("Running: HTTP & Security Headers...")
            self.write_section_header(logf, "HTTP & Security Headers")
            header_session = requests.Session()
            try:
                # Prefer HTTPS — warn explicitly when falling back to HTTP so
                # the operator knows HSTS/COEP/COOP results may be misleading.
                try:
                    homepage_resp = header_session.get(
                        f"https://{domain}", headers=HEADERS_USER_AGENT, timeout=7
                    )
                    write_log(f"Fetched via HTTPS (HTTP {homepage_resp.status_code})")
                except Exception:
                    write_log(
                        "[!] HTTPS fetch failed — falling back to HTTP "
                        "(HSTS and HTTPS-only headers cannot be evaluated correctly)"
                    )
                    homepage_resp = header_session.get(
                        f"http://{domain}", headers=HEADERS_USER_AGENT, timeout=7
                    )
                    write_log(f"Fetched via HTTP (HTTP {homepage_resp.status_code})")

                for k, v in homepage_resp.headers.items():
                    write_log(f"{k}: {v}")

                write_log("\n--- Security Header Audit ---")
                for sh in SECURITY_HEADERS:
                    val = homepage_resp.headers.get(sh)
                    if val:
                        write_log(f"  [+] {sh}: {val}")
                        if (sh == "Content-Security-Policy"
                                and "default-src *" in val.replace(" ", "")):
                            write_log(
                                "  [!] CSP WARNING: 'default-src *' is present "
                                "— this policy provides no protection"
                            )
                    else:
                        write_log(f"  [-] {sh}: NOT SET")

            except Exception as e:
                write_log(f"HTTP headers fetch failed: {e}")

        # ── Wayback Machine (CDX API) ─────────────────────────────────────────
        if on("wayback"):
            set_status("Running: Wayback Machine Lookup...")
            self.write_section_header(logf, "Wayback Machine Snapshot Info")
            try:
                cdx_url = WAYBACK_CDX_API.format(
                    domain=urllib.parse.quote(domain)
                )
                rows = requests.get(cdx_url, timeout=10).json()
                if len(rows) > 1:
                    keys = rows[0]   # header row: ["original","statuscode","timestamp"]
                    data_rows = rows[1:]
                    write_log(f"Found {len(data_rows)} archived URL(s) in Wayback Machine:")
                    for row in data_rows:
                        entry = dict(zip(keys, row))
                        ts = entry.get("timestamp", "")
                        fmt_ts = (f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
                                  if len(ts) >= 8 else ts)
                        write_log(
                            f"  [{entry.get('statuscode','?')}] {fmt_ts}  "
                            f"{entry.get('original','')}"
                        )
                else:
                    write_log("No archived snapshots found in Wayback Machine.")
            except Exception as e:
                write_log(f"Wayback Machine fetch failed: {e}")

        # ── CMS & Technology Detection ────────────────────────────────────────
        if on("cms"):
            set_status("Running: CMS & Technology Detection...")
            self.write_section_header(logf, "CMS & Technology Detection")
            try:
                cms_session = requests.Session()
                if homepage_resp is not None:
                    resp = homepage_resp
                else:
                    try:
                        resp = cms_session.get(
                            f"https://{domain}", headers=HEADERS_USER_AGENT, timeout=7
                        )
                    except Exception:
                        resp = cms_session.get(
                            f"http://{domain}", headers=HEADERS_USER_AGENT, timeout=7
                        )

                body = resp.text.lower()
                hdrs = {k.lower(): v.lower() for k, v in resp.headers.items()}
                detected = []

                def body_has(s):
                    return s in body

                def hdr_has(name, fragment=""):
                    return fragment in hdrs.get(name, "")

                # WordPress
                if body_has("wp-content") or body_has("/wp-includes/") or body_has("wp-json"):
                    detected.append("WordPress")
                # Joomla
                if body_has("/components/com_") or body_has("joomla"):
                    detected.append("Joomla")
                # Drupal
                if body_has("drupal") or hdr_has("x-drupal-cache") or hdr_has("x-generator", "drupal"):
                    detected.append("Drupal")
                # Shopify
                if body_has("shopify") or body_has("cdn.shopify.com"):
                    detected.append("Shopify")
                # Magento
                if body_has("mage.cookies") or body_has("/skin/frontend/") or body_has("magento"):
                    detected.append("Magento")
                # PrestaShop
                if body_has("prestashop") or body_has("/themes/default/css/"):
                    detected.append("PrestaShop")
                # TYPO3
                if body_has("typo3") or body_has("/typo3conf/"):
                    detected.append("TYPO3")
                # Ghost
                if body_has("ghost.io") or hdr_has("x-ghost-cache-status"):
                    detected.append("Ghost")
                # Wix
                if body_has("wixsite.com") or body_has("static.wix.com"):
                    detected.append("Wix")
                # Squarespace
                if body_has("squarespace.com") or body_has("static.squarespace.com"):
                    detected.append("Squarespace")
                # Webflow
                if body_has("webflow.com") or body_has("assets-global.website-files.com"):
                    detected.append("Webflow")
                # Next.js
                if body_has("__next_data__") or body_has("/_next/static/"):
                    detected.append("Next.js")
                # Nuxt.js
                if body_has("__nuxt__") or body_has("/_nuxt/"):
                    detected.append("Nuxt.js")
                # Angular
                if body_has("ng-version=") or body_has("ng-app"):
                    detected.append("Angular")
                # React (generic — not already detected via Next.js)
                if body_has("react-dom") and "next.js" not in [c.lower() for c in detected]:
                    detected.append("React")
                # Laravel
                if body_has("laravel") or (hdr_has("x-powered-by", "php") and body_has("_token")):
                    detected.append("Laravel")
                # Django
                if body_has("csrfmiddlewaretoken") or body_has("django"):
                    detected.append("Django")
                # Ruby on Rails
                if hdr_has("x-runtime") or hdr_has("x-powered-by", "phusion passenger"):
                    detected.append("Ruby on Rails")
                # ASP.NET — check specific header, not a generic 'microsoft' string
                if hdr_has("x-aspnet-version") or hdr_has("x-powered-by", "asp.net"):
                    detected.append("ASP.NET")
                # Symfony
                if body_has("symfony") or hdr_has("x-debug-token"):
                    detected.append("Symfony")

                # Header hints
                for hdr_name in ("x-powered-by", "server", "x-generator", "x-cms"):
                    val = resp.headers.get(hdr_name.title()) or resp.headers.get(hdr_name)
                    if val:
                        write_log(f"Header hint — {hdr_name}: {val}")

                # Meta generator tag
                mg = re.search(
                    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                    resp.text, re.I,
                )
                if mg:
                    write_log(f"Meta generator: {html.unescape(mg.group(1))}")

                for tech in detected or ["Unknown or Custom CMS/Framework"]:
                    write_log(f"Detected: {tech}")

            except Exception as e:
                write_log(f"CMS detection failed: {e}")

        # ── robots.txt & Sitemap ──────────────────────────────────────────────
        if on("robots"):
            set_status("Running: robots.txt & Sitemap...")
            self.write_section_header(logf, "robots.txt & Sitemap")
            robots_session = requests.Session()
            for path in ("/robots.txt", "/sitemap.xml"):
                found = False
                for scheme in ("https", "http"):
                    if is_cancelled():
                        break
                    try:
                        url = f"{scheme}://{domain}{path}"
                        r = robots_session.get(
                            url, headers=HEADERS_USER_AGENT, timeout=7,
                            allow_redirects=True,
                        )
                        if r.status_code == 200:
                            if scheme == "http":
                                write_log(f"[!] {path} served over HTTP (unencrypted)")
                            write_log(f"[+] {path} ({url}):")
                            for line in r.text[:2000].splitlines()[:30]:
                                if line.strip():
                                    write_log(f"    {line}")
                            found = True
                            break
                    except Exception:
                        continue
                if not found:
                    write_log(f"{path}: Not found.")

        # ── Email Harvesting ──────────────────────────────────────────────────
        if on("email"):
            set_status("Running: Email Harvesting...")
            self.write_section_header(logf, "Email Harvesting")
            email_pat = re.compile(
                r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
            )
            all_emails: set = set()
            email_session = requests.Session()

            for page in ("/", "/contact", "/about", "/contact-us", "/about-us"):
                if is_cancelled():
                    break
                for scheme in ("https", "http"):
                    try:
                        r = email_session.get(
                            f"{scheme}://{domain}{page}",
                            headers=HEADERS_USER_AGENT, timeout=7,
                            allow_redirects=True,
                        )
                        if r.status_code == 200:
                            found_here = {
                                e for e in email_pat.findall(r.text)
                                if "." in e.split("@")[1]
                            }
                            if found_here:
                                write_log(
                                    f"  {page}: {', '.join(sorted(found_here))}"
                                )
                                all_emails |= found_here
                            break
                    except Exception:
                        continue

            if all_emails:
                write_log(f"\n[+] {len(all_emails)} unique email(s) found:")
                for addr in sorted(all_emails):
                    write_log(f"  {addr}")
            else:
                write_log("No emails found on checked pages.")
            write_log(
                "Note: obfuscated addresses (e.g. 'user [at] example [dot] com') "
                "are not detected by this method."
            )

        # ── Full Port Scan (1–65535) ──────────────────────────────────────────
        if ip and on("fullports"):
            set_status("Running: Full Port Scan (1–65535)...")
            self.write_section_header(logf, "Full Port Scan (1 – 65535)")
            write_log(
                "[!] WARNING: The full port scan is aggressive. "
                "Only run it against targets you are explicitly authorised to test."
            )

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

            # The executor is NOT used as a context manager here because the
            # context manager's __exit__ calls shutdown(wait=True), which would
            # block until all 65k futures finish even after cancel is requested.
            executor = ThreadPoolExecutor(max_workers=FULL_SCAN_WORKERS)
            futures = [
                executor.submit(check_port_full, p)
                for p in range(1, TOTAL_PORTS + 1)
            ]
            try:
                for future in as_completed(futures):
                    if is_cancelled():
                        for f in futures:
                            f.cancel()  # cancel pending (not-yet-running) futures
                        break
                    port, is_open = future.result()
                    completed += 1
                    if is_open:
                        service = COMMON_PORTS.get(port, "unknown")
                        write_log(f"  {port:5d}/tcp  OPEN      {service}")
                        full_open_ports.append(port)
                    if completed % 2000 == 0 or completed == TOTAL_PORTS:
                        pct = int(completed / TOTAL_PORTS * 100)
                        set_status(
                            f"Full port scan: {completed:,}/{TOTAL_PORTS:,} ({pct}%)"
                        )
            finally:
                executor.shutdown(wait=False)

            full_open_ports.sort()
            if full_open_ports:
                write_log(
                    f"[+] {len(full_open_ports)} open port(s): "
                    f"{', '.join(str(p) for p in full_open_ports)}"
                )
            else:
                write_log("[–] No open ports found.")

        # ── Completion ────────────────────────────────────────────────────────
        if is_cancelled():
            write_log("[!] Scan cancelled by user.")
        else:
            write_log("\n[✔] Deep recon finished.")
        logf.flush()


if __name__ == "__main__":
    root = tk.Tk()
    app = ReconApp(root)
    root.mainloop()
