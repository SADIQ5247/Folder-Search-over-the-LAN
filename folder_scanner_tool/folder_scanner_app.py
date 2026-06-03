#!/usr/bin/env python3
"""
Folder Scanner & Copier
Scans a drive or root directory for a folder name (case-insensitive),
lists location chains and subfolders, saves reports, and copies matches.
"""

from __future__ import annotations

import os
import re
import shutil
import string
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import keyboard

    HAS_KEYBOARD = True
except ImportError:
    HAS_KEYBOARD = False


APP_TITLE = "Folder Scanner & Copier"
APP_VERSION = "1.3.2"
DEFAULT_HOTKEY = "ctrl+shift+h"
SAVED_NETWORK_PATHS_FILE = "network_paths.txt"


def _is_windows() -> bool:
    return sys.platform == "win32"


def _set_window_taskbar_visible(window: tk.Misc, visible: bool) -> None:
    """Show or hide a Tk window from the Windows taskbar and Alt+Tab."""
    if _is_windows():
        try:
            window.attributes("-toolwindow", not visible)
            window.update_idletasks()
            import ctypes

            hwnd = ctypes.windll.user32.GetParent(window.winfo_id()) or window.winfo_id()
            gwl_exstyle = -20
            ws_ex_toolwindow = 0x00000080
            ws_ex_appwindow = 0x00040000
            style = ctypes.windll.user32.GetWindowLongW(hwnd, gwl_exstyle)
            if visible:
                style = (style & ~ws_ex_toolwindow) | ws_ex_appwindow
            else:
                style = (style | ws_ex_toolwindow) & ~ws_ex_appwindow
            ctypes.windll.user32.SetWindowLongW(hwnd, gwl_exstyle, style)
            swp_nomove = 0x0002
            swp_nosize = 0x0001
            swp_nozorder = 0x0004
            swp_framechanged = 0x0020
            ctypes.windll.user32.SetWindowPos(
                hwnd, 0, 0, 0, 0, 0, swp_nomove | swp_nosize | swp_nozorder | swp_framechanged
            )
            return
        except Exception:
            pass
    window.attributes("-toolwindow", not visible)


def get_windows_drives() -> list[str]:
    """Local drive letters (includes mapped network drives such as Z:)."""
    drives: list[str] = []
    for letter in string.ascii_uppercase:
        path = f"{letter}:\\"
        if os.path.exists(path):
            drives.append(path)
    return drives


def _parse_net_use_output(text: str) -> list[str]:
    """Extract UNC paths and mapped drive letters from `net use` output."""
    locations: list[str] = []
    seen: set[str] = set()
    row_re = re.compile(
        r"^\s*(?:OK|Disconnected|Unavailable|Reconnecting)\s+(\S*)\s+(\\\\[^\s]+)",
        re.IGNORECASE,
    )
    for line in text.splitlines():
        match = row_re.match(line)
        if not match:
            continue
        local, remote = match.group(1).strip(), match.group(2).strip()
        for path in (local, remote):
            if not path:
                continue
            if len(path) == 2 and path[1] == ":":
                path = f"{path}\\"
            if path not in seen:
                seen.add(path)
                locations.append(path)
    return locations


def get_network_locations() -> list[str]:
    """Return UNC paths and mapped network drives from `net use`."""
    if not _is_windows():
        return []
    try:
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        result = subprocess.run(
            ["net", "use"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=flags,
            timeout=30,
        )
        if result.returncode != 0:
            return []
        return _parse_net_use_output(result.stdout)
    except (OSError, subprocess.TimeoutExpired):
        return []


def get_app_dir() -> Path:
    """Folder containing the EXE (portable) or the script."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def get_saved_network_paths_file() -> Path:
    return get_app_dir() / SAVED_NETWORK_PATHS_FILE


def load_saved_network_paths() -> list[str]:
    """Load user-saved UNC paths from network_paths.txt next to the program."""
    path_file = get_saved_network_paths_file()
    if not path_file.is_file():
        return []
    paths: list[str] = []
    seen: set[str] = set()
    try:
        for line in path_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            norm = normalize_scan_path(line)
            if norm and norm.startswith("\\\\") and norm.lower() not in seen:
                seen.add(norm.lower())
                paths.append(norm)
    except OSError:
        return []
    return paths


def save_saved_network_paths(paths: list[str]) -> None:
    path_file = get_saved_network_paths_file()
    unique: list[str] = []
    seen: set[str] = set()
    for path in paths:
        norm = normalize_scan_path(path)
        if norm and norm.startswith("\\\\") and norm.lower() not in seen:
            seen.add(norm.lower())
            unique.append(norm)
    lines = [
        "# Saved network paths — one per line (copy this file with the program to another PC)",
        "# Example: \\\\192.168.1.10\\Forensics",
        "",
    ]
    lines.extend(unique)
    path_file.write_text("\n".join(lines) + ("\n" if unique else ""), encoding="utf-8")


def add_saved_network_path(path: str) -> bool:
    norm = normalize_scan_path(path)
    if not norm or not norm.startswith("\\\\"):
        return False
    paths = load_saved_network_paths()
    if norm.lower() not in {p.lower() for p in paths}:
        paths.append(norm)
        save_saved_network_paths(paths)
    return True


def build_unc_path(server: str, share: str) -> str:
    server = server.strip().strip("\\/")
    share = share.strip().strip("\\/")
    if not server or not share:
        return ""
    return f"\\\\{server}\\{share}"


def is_unc_path(path: str) -> bool:
    path = normalize_scan_path(path)
    if not path.startswith("\\\\"):
        return False
    parts = path[2:].split("\\")
    return len(parts) >= 2 and bool(parts[0]) and bool(parts[1])


def get_all_scan_locations() -> list[str]:
    """Local drives, mapped network paths, and saved UNC paths from network_paths.txt."""
    locations: list[str] = []
    seen: set[str] = set()
    for path in get_windows_drives() + get_network_locations() + load_saved_network_paths():
        norm = normalize_scan_path(path)
        if not norm:
            continue
        key = norm.lower()
        if key not in seen:
            seen.add(key)
            locations.append(norm)
    return locations


def normalize_scan_path(path: str) -> str:
    path = path.strip().strip('"')
    if not path:
        return ""
    if path.startswith("\\\\"):
        return path.rstrip("\\") if len(path) > 2 else path
    if len(path) == 2 and path[1] == ":":
        return f"{path}\\"
    return path


def normalize_scan_root(root: str) -> Path:
    root = normalize_scan_path(root)
    p = Path(root)
    if str(p).startswith("\\\\"):
        return p
    try:
        return p.resolve()
    except OSError:
        return p


def path_is_accessible(path: str) -> bool:
    """Check local, mapped, or UNC path without forcing resolve on network shares."""
    path = normalize_scan_path(path)
    if not path:
        return False
    if path.startswith("\\\\"):
        return os.path.exists(path)
    try:
        return Path(path).exists()
    except OSError:
        return False


def parse_target_folder_names(text: str) -> list[str]:
    """Split folder names by semicolon: Evidence; Backup; logs"""
    names: list[str] = []
    seen: set[str] = set()
    for part in text.split(";"):
        name = part.strip()
        if not name:
            continue
        key = name.lower()
        if key not in seen:
            seen.add(key)
            names.append(name)
    return names


def unique_destination(base_dest: Path, folder_name: str, source_path: Path) -> Path:
    safe_hint = source_path.parent.name or "root"
    for ch in '<>:"/\\|?*':
        safe_hint = safe_hint.replace(ch, "_")

    candidate = base_dest / f"{folder_name}_{safe_hint}"
    if not candidate.exists():
        return candidate

    counter = 1
    while True:
        candidate = base_dest / f"{folder_name}_{safe_hint}_{counter}"
        if not candidate.exists():
            return candidate
        counter += 1


def build_location_chain(scan_root: Path, parent_dir: Path) -> list[str]:
    """Folder path for each level from scan root down to the parent of the match."""
    chain: list[str] = []
    try:
        if str(scan_root).startswith("\\\\"):
            scan_root_s = str(scan_root)
        else:
            scan_root = scan_root.resolve()
            scan_root_s = str(scan_root)

        if str(parent_dir).startswith("\\\\"):
            parent_s = str(parent_dir)
        else:
            parent_dir = parent_dir.resolve()
            parent_s = str(parent_dir)

        if parent_s == scan_root_s:
            return [scan_root_s]

        rel = Path(parent_s).relative_to(scan_root_s)
        current = Path(scan_root_s)
        chain.append(scan_root_s)
        for part in rel.parts:
            current = current / part
            chain.append(str(current))
    except ValueError:
        chain.append(str(parent_dir))
    return chain


def list_all_subfolders(folder_path: Path | str, stop_event: threading.Event) -> list[str]:
    """List subfolder paths under a match — folders only, files are skipped."""
    subfolders: list[str] = []
    root = normalize_scan_path(str(folder_path))
    if not root:
        return subfolders

    stack = [root]
    while stack:
        if stop_event.is_set():
            break
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if stop_event.is_set():
                        break
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            subfolders.append(entry.path)
                            stack.append(entry.path)
                    except OSError:
                        continue
        except OSError:
            continue
    return subfolders


def enrich_matches_with_subfolders(
    results: list[dict], stop_event: threading.Event, on_progress=None
) -> None:
    """Fill subfolder lists for matches (folder-only walk under each match)."""
    for match in results:
        if stop_event.is_set():
            break
        if match.get("subfolders_loaded"):
            continue
        if on_progress:
            on_progress(match["folder_path"])
        match["subfolders"] = list_all_subfolders(match["folder_path"], stop_event)
        match["subfolders_loaded"] = True
        match["all_folder_paths"] = collect_all_folder_paths(match)


def collect_all_folder_paths(match: dict) -> list[str]:
    """Unique ordered list: location chain + matched folder + all subfolders."""
    seen: set[str] = set()
    ordered: list[str] = []
    for path in match.get("location_chain", []) + [match["folder_path"]] + match.get("subfolders", []):
        if path not in seen:
            seen.add(path)
            ordered.append(path)
    return ordered


def scan_for_folder(
    root: str, target_names: list[str], on_progress, stop_event: threading.Event
) -> list[dict]:
    """Find folders by name — traverses directories only; files are never opened."""
    if not target_names:
        return []

    target_lowers = {name.lower() for name in target_names}
    results: list[dict] = []
    scan_root = normalize_scan_root(root)
    walk_root = normalize_scan_path(root)
    stack = [walk_root]

    while stack:
        if stop_event.is_set():
            break

        dirpath = stack.pop()
        on_progress(dirpath)

        try:
            with os.scandir(dirpath) as entries:
                for entry in entries:
                    if stop_event.is_set():
                        break
                    try:
                        if not entry.is_dir(follow_symlinks=False):
                            continue
                    except OSError:
                        continue

                    stack.append(entry.path)
                    if entry.name.lower() not in target_lowers:
                        continue

                    parent_resolved = Path(dirpath)
                    folder_resolved = Path(entry.path)
                    location_chain = build_location_chain(scan_root, parent_resolved)

                    results.append(
                        {
                            "matched_name": entry.name,
                            "folder_path": str(folder_resolved),
                            "parent_dir": str(parent_resolved),
                            "location_chain": location_chain,
                            "subfolders": [],
                            "subfolders_loaded": False,
                            "all_folder_paths": [],
                        }
                    )
        except OSError:
            continue

    for match in results:
        match["all_folder_paths"] = collect_all_folder_paths(match)

    return results


def copy_tree_with_progress(src: Path, dst: Path, on_file, on_count=None) -> int:
    dst.mkdir(parents=True, exist_ok=True)
    file_count = 0
    for root, dirs, files in os.walk(src):
        rel = Path(root).relative_to(src)
        dest_root = dst / rel
        dest_root.mkdir(parents=True, exist_ok=True)
        for d in dirs:
            (dest_root / d).mkdir(exist_ok=True)
        for f in files:
            src_file = Path(root) / f
            dest_file = dest_root / f
            shutil.copy2(src_file, dest_file)
            file_count += 1
            on_file(str(src_file))
            if on_count:
                on_count(file_count)
    return file_count


def parse_folder_list_file(path: str) -> list[str]:
    """Read one folder path per line from a text file."""
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    paths: list[str] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        paths.append(line)
    return paths


class FolderScannerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_TITLE} v{APP_VERSION}")
        self.minsize(980, 720)
        self.geometry("1060x820")

        self._scan_thread: threading.Thread | None = None
        self._copy_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._results: list[dict] = []
        self._is_hidden = False
        self._busy = False
        self._copy_progress = {"current": 0, "total": 0, "folder": "", "files": 0}
        self._hotkey_handle = None

        self._mini_window: tk.Toplevel | None = None
        self._mini_status: tk.StringVar | None = None
        self._mini_progress: ttk.Progressbar | None = None
        self._mini_detail: tk.StringVar | None = None
        self._mini_hotkey_label: ttk.Label | None = None

        self._build_styles()
        self._build_ui()
        self._refresh_drives(silent=True)
        self._setup_hotkey()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, lambda: _set_window_taskbar_visible(self, True))

    def _build_styles(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Subtitle.TLabel", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=12)
        outer.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(outer)
        header.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(header, text=APP_TITLE, style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(
            header,
            text="Scan local or network paths. Fast folder-only scan — files are skipped. Use ; for multiple names.",
            style="Subtitle.TLabel",
        ).pack(anchor=tk.W)

        hotkey_row = ttk.Frame(header)
        hotkey_row.pack(anchor=tk.W, pady=(4, 0))
        ttk.Label(hotkey_row, text="Hide / Show hotkey:").pack(side=tk.LEFT)
        self.hotkey_var = tk.StringVar(value=DEFAULT_HOTKEY)
        ttk.Entry(hotkey_row, textvariable=self.hotkey_var, width=18).pack(side=tk.LEFT, padx=6)
        ttk.Button(hotkey_row, text="Apply Hotkey", command=self._setup_hotkey).pack(side=tk.LEFT)
        ttk.Button(hotkey_row, text="Hide Now", command=self._hide_window).pack(side=tk.LEFT, padx=6)

        self._build_main_panel(outer)

        log_frame = ttk.LabelFrame(outer, text="Activity Log", padding=8)
        log_frame.pack(fill=tk.BOTH, expand=False, pady=(10, 0))

        self.log_text = tk.Text(log_frame, height=5, wrap=tk.WORD, font=("Consolas", 9))
        scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(outer, textvariable=self.status_var).pack(anchor=tk.W, pady=(6, 0))

        prog_row = ttk.Frame(outer)
        prog_row.pack(fill=tk.X, pady=(4, 0))
        self.progress = ttk.Progressbar(prog_row, mode="indeterminate")
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress_detail_var = tk.StringVar(value="")
        ttk.Label(prog_row, textvariable=self.progress_detail_var, width=28).pack(side=tk.LEFT, padx=(8, 0))

    def _build_main_panel(self, parent: ttk.Frame) -> None:
        settings = ttk.LabelFrame(parent, text="Search & output settings", padding=10)
        settings.pack(fill=tk.X, pady=(0, 8))

        row1 = ttk.Frame(settings)
        row1.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(row1, text="Location:", width=14).pack(side=tk.LEFT)
        self.drive_var = tk.StringVar()
        self.drive_combo = ttk.Combobox(row1, textvariable=self.drive_var, width=36, state="readonly")
        self.drive_combo.pack(side=tk.LEFT, padx=(0, 6))
        self.drive_combo.bind("<<ComboboxSelected>>", self._on_drive_selected)
        ttk.Button(row1, text="Refresh", command=self._refresh_drives).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(row1, text="Add network…", command=self._add_network_path_dialog).pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(row1, text="Scan path:").pack(side=tk.LEFT)
        self.source_var = tk.StringVar()
        ttk.Entry(row1, textvariable=self.source_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        ttk.Button(row1, text="Test", command=self._test_scan_path).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(row1, text="Browse…", command=self._browse_source).pack(side=tk.LEFT)

        row1b = ttk.Frame(settings)
        row1b.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(
            row1b,
            text=(
                "Network paths are saved in network_paths.txt next to the program — copy that file to another PC. "
                "On a new PC use Add network… or type \\\\server\\share in Scan path."
            ),
            style="Subtitle.TLabel",
            wraplength=980,
        ).pack(anchor=tk.W, padx=(14, 0))

        row2 = ttk.Frame(settings)
        row2.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(row2, text="Find folder(s):", width=14).pack(side=tk.LEFT)
        self.target_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.target_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Label(row2, text="(use ; for multiple, not case sensitive)", style="Subtitle.TLabel").pack(side=tk.LEFT)

        row3 = ttk.Frame(settings)
        row3.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(row3, text="Report file:", width=14).pack(side=tk.LEFT)
        self.report_var = tk.StringVar()
        ttk.Entry(row3, textvariable=self.report_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Button(row3, text="Browse…", command=self._browse_report).pack(side=tk.LEFT)
        ttk.Button(row3, text="Default", command=self._default_report_path).pack(side=tk.LEFT, padx=(6, 0))

        row4 = ttk.Frame(settings)
        row4.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(row4, text="Copy destination:", width=14).pack(side=tk.LEFT)
        self.dest_var = tk.StringVar()
        ttk.Entry(row4, textvariable=self.dest_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Button(row4, text="Browse…", command=self._browse_dest).pack(side=tk.LEFT)

        row5 = ttk.Frame(settings)
        row5.pack(fill=tk.X)
        ttk.Label(row5, text="Copy list file:", width=14).pack(side=tk.LEFT)
        self.copy_list_var = tk.StringVar()
        ttk.Entry(row5, textvariable=self.copy_list_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Button(row5, text="Browse…", command=self._browse_copy_list).pack(side=tk.LEFT)
        ttk.Label(
            row5,
            text="(one folder path per line)",
            style="Subtitle.TLabel",
        ).pack(side=tk.LEFT, padx=(8, 0))

        actions = ttk.LabelFrame(parent, text="Actions", padding=10)
        actions.pack(fill=tk.X, pady=(0, 8))

        scan_row = ttk.Frame(actions)
        scan_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(scan_row, text="Scan:", width=8).pack(side=tk.LEFT)
        ttk.Button(scan_row, text="Start Scan", style="Accent.TButton", command=self._start_scan).pack(side=tk.LEFT)
        ttk.Button(scan_row, text="Stop Scan", command=self._stop_scan).pack(side=tk.LEFT, padx=6)
        ttk.Button(scan_row, text="Save Report", command=self._save_report).pack(side=tk.LEFT, padx=6)
        ttk.Button(scan_row, text="Export Folder List", command=self._export_folder_list).pack(side=tk.LEFT)

        copy_row = ttk.Frame(actions)
        copy_row.pack(fill=tk.X)
        ttk.Label(copy_row, text="Copy:", width=8).pack(side=tk.LEFT)
        ttk.Button(copy_row, text="Copy Selected", style="Accent.TButton", command=self._start_copy).pack(side=tk.LEFT)
        ttk.Button(copy_row, text="Copy from List File", command=self._copy_from_list_file).pack(side=tk.LEFT, padx=6)
        ttk.Button(copy_row, text="Stop Copy", command=self._stop_copy).pack(side=tk.LEFT, padx=6)
        ttk.Button(copy_row, text="Select All", command=self._select_all_results).pack(side=tk.LEFT, padx=6)
        ttk.Button(copy_row, text="Clear Selection", command=self._clear_result_selection).pack(side=tk.LEFT)

        res = ttk.LabelFrame(
            parent,
            text="Results — matched name and path (Subfolders: — until Save Report or Export)",
            padding=8,
        )
        res.pack(fill=tk.BOTH, expand=True)

        cols = ("matched_name", "parent_dir", "folder_path", "subfolder_count")
        self.tree = ttk.Treeview(res, columns=cols, show="headings", height=13, selectmode="extended")
        self.tree.heading("matched_name", text="Matched name")
        self.tree.heading("parent_dir", text="Parent directory")
        self.tree.heading("folder_path", text="Full path")
        self.tree.heading("subfolder_count", text="Subfolders")
        self.tree.column("matched_name", width=110)
        self.tree.column("parent_dir", width=280)
        self.tree.column("folder_path", width=380)
        self.tree.column("subfolder_count", width=80, anchor=tk.CENTER)
        tree_scroll = ttk.Scrollbar(res, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.result_count_var = tk.StringVar(value="0 matches — run a scan to populate results")
        ttk.Label(parent, textvariable=self.result_count_var, style="Header.TLabel").pack(anchor=tk.W, pady=(6, 0))

    # --- Hotkey & visibility ---

    def _setup_hotkey(self) -> None:
        if not HAS_KEYBOARD:
            self._log("Install 'keyboard' package for global hide/show hotkey (pip install keyboard).")
            return

        combo = self.hotkey_var.get().strip().lower() or DEFAULT_HOTKEY
        try:
            if self._hotkey_handle is not None:
                keyboard.remove_hotkey(self._hotkey_handle)
        except (KeyError, ValueError):
            pass

        try:
            self._hotkey_handle = keyboard.add_hotkey(combo, self._hotkey_toggle_threadsafe, suppress=False)
            self._log(f"Hotkey active: {combo} (hide from taskbar / show full window)")
        except Exception as exc:
            self._log(f"Could not register hotkey '{combo}': {exc}")

    def _hotkey_toggle_threadsafe(self) -> None:
        self.after(0, self._toggle_visibility)

    def _toggle_visibility(self) -> None:
        if self._is_hidden:
            self._show_window()
        else:
            self._hide_window()

    def _hide_window(self) -> None:
        self._is_hidden = True
        _set_window_taskbar_visible(self, False)
        self.withdraw()
        if self._busy:
            self._show_mini_progress()
        else:
            self._hide_mini_progress()

    def _show_window(self) -> None:
        self._is_hidden = False
        self._hide_mini_progress()
        _set_window_taskbar_visible(self, True)
        self.deiconify()
        self.lift()
        self.focus_force()
        self._update_progress_display()

    def _ensure_mini_progress(self) -> None:
        if self._mini_window is not None:
            return

        mini = tk.Toplevel(self)
        mini.withdraw()
        mini.overrideredirect(True)
        mini.attributes("-topmost", True)
        _set_window_taskbar_visible(mini, False)
        mini.configure(bg="#2b2b2b")
        mini.geometry("340x96")

        frame = ttk.Frame(mini, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        self._mini_status = tk.StringVar(value="Working…")
        self._mini_detail = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self._mini_status, font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        self._mini_progress = ttk.Progressbar(frame, mode="indeterminate", length=300)
        self._mini_progress.pack(fill=tk.X, pady=6)
        ttk.Label(frame, textvariable=self._mini_detail, font=("Segoe UI", 8)).pack(anchor=tk.W)
        self._mini_hotkey_label = ttk.Label(
            frame, text=f"Press {self.hotkey_var.get()} to show full window", style="Subtitle.TLabel"
        )
        self._mini_hotkey_label.pack(anchor=tk.W)

        self._mini_window = mini
        self._position_mini_window()

    def _position_mini_window(self) -> None:
        if not self._mini_window:
            return
        self._mini_window.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w, h = 340, 96
        self._mini_window.geometry(f"{w}x{h}+{sw - w - 20}+{sh - h - 60}")

    def _show_mini_progress(self) -> None:
        if not self._is_hidden or not self._busy:
            return
        self._ensure_mini_progress()
        if self._mini_window:
            if self._mini_hotkey_label:
                self._mini_hotkey_label.configure(
                    text=f"Press {self.hotkey_var.get()} to show full window"
                )
            _set_window_taskbar_visible(self._mini_window, False)
            self._mini_window.deiconify()
            self._position_mini_window()
            if self._mini_progress:
                if self.progress["mode"] == "determinate":
                    self._mini_progress.configure(mode="determinate", maximum=100)
                    self._mini_progress["value"] = self.progress["value"]
                else:
                    self._mini_progress.configure(mode="indeterminate")
                    self._mini_progress.start(12)
            self._update_progress_display()

    def _hide_mini_progress(self) -> None:
        if self._mini_progress:
            self._mini_progress.stop()
        if self._mini_window:
            self._mini_window.withdraw()

    def _update_progress_display(self) -> None:
        status = self.status_var.get()
        detail = self.progress_detail_var.get()
        if self._mini_status:
            self._mini_status.set(status)
        if self._mini_detail:
            self._mini_detail.set(detail)

    def _set_busy(self, busy: bool, status: str = "") -> None:
        self._busy = busy
        if status:
            self.status_var.set(status)
        self._update_progress_display()
        if busy and self._is_hidden:
            self._show_mini_progress()
        elif not busy:
            self._hide_mini_progress()

    def _on_close(self) -> None:
        if HAS_KEYBOARD:
            try:
                keyboard.unhook_all()
            except Exception:
                pass
        self.destroy()

    # --- Logging & drives ---

    def _log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)

    def _refresh_drives(self, silent: bool = False) -> None:
        locations = get_all_scan_locations()
        self.drive_combo["values"] = locations
        current = normalize_scan_path(self.source_var.get())
        if current and current in locations:
            self.drive_var.set(current)
        elif locations:
            self.drive_var.set(locations[0])
            if not self.source_var.get().strip():
                self.source_var.set(locations[0])
        if not silent:
            saved = len(load_saved_network_paths())
            network_count = sum(1 for p in locations if p.startswith("\\\\"))
            self._log(
                f"Locations refreshed: {len(locations)} total "
                f"({network_count} network, {saved} saved in network_paths.txt)"
            )

    def _test_scan_path(self) -> None:
        path = normalize_scan_path(self.source_var.get())
        if not path:
            messagebox.showwarning("Test path", "Enter a scan path first.")
            return
        if not is_unc_path(path) and not path.endswith(":\\") and not os.path.isdir(path):
            messagebox.showwarning("Test path", "Path format looks invalid.")
            return
        self.status_var.set("Testing path…")
        self.update_idletasks()

        def worker() -> None:
            ok = path_is_accessible(path)
            msg = f"Path is reachable:\n{path}" if ok else (
                f"Cannot access path:\n{path}\n\n"
                "Check network/VPN, server name, share name, and your permissions.\n"
                "Try opening this path in File Explorer first."
            )
            self.after(0, lambda: self._test_path_finished(ok, msg))

        threading.Thread(target=worker, daemon=True).start()

    def _test_path_finished(self, ok: bool, message: str) -> None:
        self.status_var.set("Ready" if ok else "Path not reachable")
        if ok:
            if is_unc_path(normalize_scan_path(self.source_var.get())):
                add_saved_network_path(self.source_var.get())
                self._refresh_drives(silent=True)
            messagebox.showinfo("Test path", message)
        else:
            messagebox.showwarning("Test path", message)

    def _add_network_path_dialog(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Add network path")
        dialog.transient(self)
        dialog.grab_set()
        dialog.resizable(False, False)

        frame = ttk.Frame(dialog, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Add a network share to use on this PC (and save for next time).").pack(
            anchor=tk.W, pady=(0, 8)
        )

        ttk.Label(frame, text="Server name or IP:").pack(anchor=tk.W)
        server_var = tk.StringVar()
        ttk.Entry(frame, textvariable=server_var, width=50).pack(fill=tk.X, pady=(0, 6))

        ttk.Label(frame, text="Share name:").pack(anchor=tk.W)
        share_var = tk.StringVar()
        ttk.Entry(frame, textvariable=share_var, width=50).pack(fill=tk.X, pady=(0, 6))

        ttk.Label(frame, text="Or full UNC path:").pack(anchor=tk.W)
        unc_var = tk.StringVar()
        unc_entry = ttk.Entry(frame, textvariable=unc_var, width=50)
        unc_entry.pack(fill=tk.X, pady=(0, 6))

        def sync_unc_from_fields(*_args) -> None:
            built = build_unc_path(server_var.get(), share_var.get())
            if built:
                unc_var.set(built)

        server_var.trace_add("write", sync_unc_from_fields)
        share_var.trace_add("write", sync_unc_from_fields)

        hint = ttk.Label(
            frame,
            text=f"Saved to: {get_saved_network_paths_file()}",
            style="Subtitle.TLabel",
            wraplength=420,
        )
        hint.pack(anchor=tk.W, pady=(0, 8))

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill=tk.X)

        def on_add() -> None:
            path = normalize_scan_path(unc_var.get() or build_unc_path(server_var.get(), share_var.get()))
            if not is_unc_path(path):
                messagebox.showwarning("Add network", "Enter a valid UNC path like \\\\server\\share", parent=dialog)
                return
            if not path_is_accessible(path):
                if not messagebox.askyesno(
                    "Add network",
                    "Windows cannot reach this path right now.\nSave it anyway?",
                    parent=dialog,
                ):
                    return
            add_saved_network_path(path)
            self.source_var.set(path)
            self._refresh_drives(silent=True)
            self.drive_var.set(path)
            self._log(f"Network path saved: {path}")
            dialog.destroy()
            messagebox.showinfo("Add network", f"Saved and selected:\n{path}")

        ttk.Button(btn_row, text="Add & Save", command=on_add).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=8)

        dialog.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() // 2) - (dialog.winfo_width() // 2)
        y = self.winfo_rooty() + (self.winfo_height() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

    def _on_drive_selected(self, _event=None) -> None:
        self.source_var.set(self.drive_var.get())

    def _browse_source(self) -> None:
        path = filedialog.askdirectory(title="Select folder to scan (local or network)")
        if path:
            path = normalize_scan_path(path)
            self.source_var.set(path)
            if is_unc_path(path):
                add_saved_network_path(path)
            self._refresh_drives(silent=True)
            self.drive_var.set(path)

    def _browse_report(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save scan report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"folder_scan_report_{datetime.now():%Y%m%d_%H%M%S}.txt",
        )
        if path:
            self.report_var.set(path)

    def _default_report_path(self) -> None:
        desktop = Path.home() / "Desktop"
        if not desktop.exists():
            desktop = Path.home() / "Documents"
        default = desktop / f"folder_scan_report_{datetime.now():%Y%m%d_%H%M%S}.txt"
        self.report_var.set(str(default))

    def _browse_dest(self) -> None:
        path = filedialog.askdirectory(title="Select destination folder for copies")
        if path:
            self.dest_var.set(path)

    def _browse_copy_list(self) -> None:
        path = filedialog.askopenfilename(
            title="Select folder list text file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            self.copy_list_var.set(path)

    # --- Scan ---

    def _validate_scan_inputs(self) -> str | None:
        source = normalize_scan_path(self.source_var.get())
        targets = parse_target_folder_names(self.target_var.get())
        if not source or not path_is_accessible(source):
            return "Please select a valid local, mapped, or network path (e.g. D:\\ or \\\\server\\share)."
        if not targets:
            return "Please enter at least one folder name (separate multiple with ;)."
        return None

    def _start_scan(self) -> None:
        err = self._validate_scan_inputs()
        if err:
            messagebox.showwarning("Scan", err)
            return
        if self._scan_thread and self._scan_thread.is_alive():
            messagebox.showinfo("Scan", "A scan is already running.")
            return

        self._stop_event.clear()
        self._results.clear()
        self._clear_tree()
        self._progress_start()
        self._set_busy(True, "Scanning…")
        targets = parse_target_folder_names(self.target_var.get())
        source = normalize_scan_path(self.source_var.get())
        self._log(f"Scan started: {source} → {', '.join(targets)}")

        def worker() -> None:
            def on_progress(path: str) -> None:
                self.after(0, lambda p=path: self._set_scan_progress(p))

            found = scan_for_folder(source, targets, on_progress, self._stop_event)
            self.after(0, lambda: self._scan_finished(found))

        self._scan_thread = threading.Thread(target=worker, daemon=True)
        self._scan_thread.start()

    def _set_scan_progress(self, path: str) -> None:
        self.status_var.set(f"Scanning: {path}")
        short = path if len(path) <= 40 else "…" + path[-37:]
        self.progress_detail_var.set(short)
        self._update_progress_display()

    def _scan_finished(self, found: list[dict]) -> None:
        self._progress_stop()
        self._set_busy(False)
        self._results = found
        self._populate_tree(found)
        count = len(found)
        hint = " — select rows and copy" if count else ""
        self.result_count_var.set(
            f"{count} match{'es' if count != 1 else ''} (folder-only scan, files skipped){hint}"
        )
        if self._stop_event.is_set():
            self.status_var.set(f"Scan stopped — {count} matches")
            self._log(f"Scan stopped. Found {count} matches.")
        else:
            self.status_var.set(f"Scan complete — {count} matches")
            self._log(f"Scan complete. Found {count} matches (folders only, files not scanned).")

        if count and self.report_var.get().strip():
            self._save_report(silent=True, include_subfolders=False)

        if count and self.dest_var.get().strip() and not self._stop_event.is_set():
            self._auto_copy_matches()

    def _auto_copy_matches(self) -> None:
        """Automatically copy all matched folders without asking — runs after a scan."""
        err = self._validate_copy_dest()
        if err:
            self._log(f"Auto-copy skipped: {err}")
            return
        paths = [row["folder_path"] for row in self._results if row.get("folder_path")]
        if not paths:
            return
        self._log(f"Auto-copy: copying {len(paths)} matched folder(s) automatically.")
        self._run_copy(paths, source_label=f"auto-copy ({len(paths)} folders)")

    def _stop_scan(self) -> None:
        self._stop_event.set()
        self._log("Stop requested for scan.")

    def _clear_tree(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

    def _populate_tree(self, results: list[dict]) -> None:
        self._clear_tree()
        for row in results:
            if row.get("subfolders_loaded"):
                sub_count = len(row.get("subfolders", []))
            else:
                sub_count = "—"
            self.tree.insert(
                "",
                tk.END,
                values=(
                    row.get("matched_name", ""),
                    row["parent_dir"],
                    row["folder_path"],
                    sub_count,
                ),
            )

    def _enrich_and_refresh_subfolders(self, show_busy: bool = True) -> bool:
        if not self._results:
            return True
        needs = any(not r.get("subfolders_loaded") for r in self._results)
        if not needs:
            return True

        if show_busy:
            self._set_busy(True, "Listing subfolders…")

        def on_progress(path: str) -> None:
            short = path if len(path) <= 40 else "…" + path[-37:]
            self.after(0, lambda: self.status_var.set(f"Subfolders: {short}"))

        enrich_matches_with_subfolders(self._results, self._stop_event, on_progress)
        self._populate_tree(self._results)
        if show_busy:
            self._set_busy(False)
        return not self._stop_event.is_set()

    def _build_report_lines(self) -> list[str]:
        lines = [
            f"Folder Scanner Report — {datetime.now():%Y-%m-%d %H:%M:%S}",
            f"Source: {normalize_scan_path(self.source_var.get())}",
            f"Target folder name(s): {self.target_var.get()}",
            f"Total matches: {len(self._results)}",
            "",
        ]

        all_paths_flat: list[str] = []
        seen_flat: set[str] = set()

        for i, row in enumerate(self._results, start=1):
            lines.append("=" * 70)
            lines.append(f"Match #{i}: {row.get('matched_name', '')} — {row['folder_path']}")
            lines.append("")
            lines.append("Location chain (folders from scan root to parent):")
            for p in row.get("location_chain", []):
                lines.append(f"  {p}")
            lines.append("")
            lines.append(f"Matched folder: {row['folder_path']}")
            lines.append("")
            subs = row.get("subfolders", [])
            if not subs and not row.get("subfolders_loaded"):
                lines.append("Subfolders under match: (not listed — use Save Report for full tree)")
            else:
                lines.append(f"Subfolders under match ({len(subs)}):")
                if subs:
                    for p in subs:
                        lines.append(f"  {p}")
                else:
                    lines.append("  (none)")
            lines.append("")
            lines.append("All folder paths for this match (chain + match + subfolders):")
            for p in row.get("all_folder_paths", []):
                lines.append(f"  {p}")
                if p not in seen_flat:
                    seen_flat.add(p)
                    all_paths_flat.append(p)
            lines.append("")

        lines.append("=" * 70)
        lines.append(f"COMBINED LIST — all unique folder & subfolder paths ({len(all_paths_flat)}):")
        lines.append("-" * 70)
        lines.extend(all_paths_flat)
        lines.append("")
        return lines

    def _save_report(self, silent: bool = False, include_subfolders: bool = True) -> None:
        if not self._results:
            if not silent:
                messagebox.showinfo("Report", "No scan results to save. Run a scan first.")
            return

        report_path = self.report_var.get().strip()
        if not report_path:
            self._default_report_path()
            report_path = self.report_var.get().strip()

        if include_subfolders and not self._enrich_and_refresh_subfolders(show_busy=not silent):
            if not silent:
                messagebox.showinfo("Report", "Subfolder listing stopped.")
            return

        try:
            lines = self._build_report_lines()
            Path(report_path).parent.mkdir(parents=True, exist_ok=True)
            Path(report_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
            self._log(f"Report saved: {report_path}")
            if not silent:
                messagebox.showinfo("Report", f"Report saved to:\n{report_path}")
        except OSError as exc:
            messagebox.showerror("Report", f"Could not save report:\n{exc}")

    def _export_folder_list(self) -> None:
        if not self._results:
            messagebox.showinfo("Export", "No scan results. Run a scan first.")
            return
        if not self._enrich_and_refresh_subfolders(show_busy=True):
            messagebox.showinfo("Export", "Subfolder listing stopped.")
            return
        path = filedialog.asksaveasfilename(
            title="Export all folder paths (for copy list)",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"folders_to_copy_{datetime.now():%Y%m%d_%H%M%S}.txt",
        )
        if not path:
            return

        lines: list[str] = []
        seen: set[str] = set()
        for row in self._results:
            for folder_path in row.get("all_folder_paths", []):
                if folder_path not in seen:
                    seen.add(folder_path)
                    lines.append(folder_path)

        try:
            Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.copy_list_var.set(path)
            self._log(f"Folder list exported: {path} ({len(lines)} paths)")
            messagebox.showinfo("Export", f"Exported {len(lines)} folder paths.\nUse 'Copy from List File' to copy them.")
        except OSError as exc:
            messagebox.showerror("Export", str(exc))

    # --- Copy ---

    def _select_all_results(self) -> None:
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children)

    def _clear_result_selection(self) -> None:
        self.tree.selection_remove(self.tree.selection())

    def _get_selected_folder_paths(self) -> list[str]:
        paths: list[str] = []
        for item in self.tree.selection():
            values = self.tree.item(item, "values")
            if len(values) >= 3:
                paths.append(values[2])
        return paths

    def _validate_copy_dest(self) -> str | None:
        dest = self.dest_var.get().strip()
        if not dest:
            return "Please choose a destination folder."
        if not os.path.isdir(dest):
            return "Destination folder does not exist."
        return None

    def _resolve_paths_from_list_file(self, list_path: str) -> tuple[list[str], list[str]]:
        """
        Read text file and resolve folder paths to copy.
        Supports full paths to folders, or parent paths + target folder name lookup.
        """
        raw_lines = parse_folder_list_file(list_path)
        target_names = parse_target_folder_names(self.target_var.get())
        target_lowers = {name.lower() for name in target_names}
        resolved: list[str] = []
        skipped: list[str] = []

        for line in raw_lines:
            p = Path(line)
            if p.is_dir():
                if not target_lowers or p.name.lower() in target_lowers:
                    resolved.append(str(p.resolve()))
                    continue
                for name in target_names:
                    nested = p / name
                    if nested.is_dir():
                        resolved.append(str(nested.resolve()))
                        break
                else:
                    resolved.append(str(p.resolve()))
                continue
            skipped.append(line)

        return resolved, skipped

    def _copy_from_list_file(self) -> None:
        list_path = self.copy_list_var.get().strip()
        if not list_path or not os.path.isfile(list_path):
            messagebox.showwarning("Copy", "Select a valid text file with folder paths (one per line).")
            return

        err = self._validate_copy_dest()
        if err:
            messagebox.showwarning("Copy", err)
            return

        try:
            paths, skipped = self._resolve_paths_from_list_file(list_path)
        except OSError as exc:
            messagebox.showerror("Copy", f"Could not read list file:\n{exc}")
            return

        if skipped:
            self._log(f"List file: {len(skipped)} line(s) skipped (path not found).")

        if not paths:
            messagebox.showwarning("Copy", "No valid folder paths found in the list file.")
            return

        self._run_copy(paths, source_label=f"list file ({len(paths)} folders)")

    def _start_copy(self) -> None:
        err = self._validate_copy_dest()
        if err:
            messagebox.showwarning("Copy", err)
            return

        paths = self._get_selected_folder_paths()
        if not paths:
            messagebox.showwarning("Copy", "Select at least one result row to copy.")
            return

        self._run_copy(paths, source_label=f"selection ({len(paths)} folders)")

    def _run_copy(self, paths: list[str], source_label: str) -> None:
        if self._copy_thread and self._copy_thread.is_alive():
            messagebox.showinfo("Copy", "A copy operation is already running.")
            return

        dest = self.dest_var.get().strip()
        self._stop_event.clear()
        self._copy_progress = {"current": 0, "total": len(paths), "folder": "", "files": 0}
        self._progress_start(determinate=True)
        self._set_busy(True, "Copying…")
        self._log(f"Copy started ({source_label}) → {dest}")

        def worker() -> None:
            copied = 0
            errors: list[str] = []
            batch_dir = Path(dest) / f"FolderScan_Copy_{datetime.now():%Y%m%d_%H%M%S}"
            try:
                batch_dir.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                self.after(0, lambda: self._copy_finished(0, [str(exc)]))
                return

            for idx, src_str in enumerate(paths, start=1):
                if self._stop_event.is_set():
                    break
                src = Path(src_str)
                if not src.is_dir():
                    errors.append(f"Not found: {src}")
                    continue

                self._copy_progress["current"] = idx
                self._copy_progress["folder"] = src.name
                self.after(0, self._update_copy_progress_ui)

                dest_unique = unique_destination(batch_dir, src.name, src)
                try:

                    def on_file(fpath: str) -> None:
                        self._copy_progress["files"] += 1
                        self.after(0, self._update_copy_progress_ui)

                    copy_tree_with_progress(src, dest_unique, on_file)
                    copied += 1
                    self.after(0, lambda d=str(dest_unique): self._log(f"Copied to: {d}"))
                except OSError as exc:
                    errors.append(f"{src}: {exc}")

            self.after(0, lambda: self._copy_finished(copied, errors, str(batch_dir)))

        self._copy_thread = threading.Thread(target=worker, daemon=True)
        self._copy_thread.start()

    def _update_copy_progress_ui(self) -> None:
        prog = self._copy_progress
        total = prog["total"]
        current = prog["current"]
        folder = prog["folder"]
        files = prog["files"]
        self.status_var.set(f"Copying ({current}/{total}): {folder}")
        self.progress_detail_var.set(f"{files} files")
        if total > 0 and self.progress["mode"] == "determinate":
            self.progress["value"] = (current / total) * 100
        if self._mini_progress and self._is_hidden and self._busy:
            if total > 0:
                self._mini_progress.configure(mode="determinate", maximum=100)
                self._mini_progress["value"] = (current / total) * 100
            else:
                self._mini_progress.configure(mode="indeterminate")
        self._update_progress_display()

    def _copy_finished(self, copied: int, errors: list[str], batch_dir: str = "") -> None:
        self._progress_stop()
        self._set_busy(False)
        if self._stop_event.is_set():
            self.status_var.set(f"Copy stopped — {copied} copied")
            self._log(f"Copy stopped. {copied} folder(s) copied.")
        else:
            self.status_var.set(f"Copy complete — {copied} folder(s)")
            self._log(f"Copy complete. {copied} folder(s) copied.")
        self.progress_detail_var.set("")
        if batch_dir:
            self._log(f"Batch folder: {batch_dir}")
        if errors:
            self._log("Errors: " + "; ".join(errors[:5]))
            if len(errors) > 5:
                self._log(f"… and {len(errors) - 5} more errors.")
            messagebox.showwarning(
                "Copy finished with errors",
                f"Copied {copied} folder(s).\nSome items failed — see activity log.",
            )
        elif copied:
            messagebox.showinfo("Copy", f"Successfully copied {copied} folder(s).\n\nLocation:\n{batch_dir}")
        else:
            messagebox.showinfo("Copy", "No folders were copied.")

    def _stop_copy(self) -> None:
        self._stop_event.set()
        self._log("Stop requested for copy.")

    def _progress_start(self, determinate: bool = False) -> None:
        if determinate:
            self.progress.configure(mode="determinate", maximum=100, value=0)
        else:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
        if self._mini_progress and self._is_hidden and self._busy:
            if determinate:
                self._mini_progress.configure(mode="determinate", maximum=100, value=0)
            else:
                self._mini_progress.configure(mode="indeterminate")
                self._mini_progress.start(12)

    def _progress_stop(self) -> None:
        self.progress.stop()
        self.progress.configure(mode="indeterminate", value=0)
        if self._mini_progress:
            self._mini_progress.stop()
            self._mini_progress.configure(mode="indeterminate")


def main() -> None:
    app = FolderScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
