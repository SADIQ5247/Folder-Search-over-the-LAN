# Folder Scanner & Copier
A lightweight Windows desktop tool for **searching folders by name across a single host or an entire LAN**, then reporting and copying the matches. Built for forensics, IT, and data-collection workflows where the same folder (e.g. `Evidence`, `CaseData`, `Backup`) may live on many local drives or network shares.
## What it does
- **Search the host or the LAN** — Scans local drive letters (`D:\`), mapped network drives (`Z:\`), and direct UNC paths (`\\server\share` or `\\192.168.1.10\share`).
- **Case-insensitive, multi-name search** — Look for several folder names at once using semicolons: `Evidence; Backup; Logs`.
- **Full location reporting** — For every match it records the location chain (root → parent), the matched folder, and all subfolders, exportable to a text report.
- **Automatic copying** — When a copy destination is set, every matched folder (with its full contents) is copied automatically after the scan into a timestamped batch folder. You can also copy from a saved path list.
- **Portable network setup** — Saved shares live in `network_paths.txt` next to the EXE, so the same configuration moves with the tool to another PC.
- **Discreet operation** — A global hotkey (`Ctrl+Shift+H`) hides the window from the taskbar and shows a compact progress panel during long scans/copies.
## Why "host or LAN"
Each PC only auto-detects the drives mapped on that machine. This tool lets you go beyond that by adding UNC paths manually, saving them for reuse, and scanning network shares directly — turning a single-machine folder search into a LAN-wide one.
## Tech
Python 3.10+ • Tkinter GUI • packaged to a standalone Windows `.exe` with PyInstaller.
