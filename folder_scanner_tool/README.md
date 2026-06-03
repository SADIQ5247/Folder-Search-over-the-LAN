# Folder Scanner & Copier

Windows desktop tool to scan **local or network** paths for folder names (case-insensitive), list location chains and subfolders, save reports, and copy matches.

## Features

1. **Local & network scan** — Supports drive letters (`D:\`), mapped network drives (`Z:\`), and UNC paths (`\\server\share`).
2. **Multiple folder names** — Search for several folders at once using semicolons: `Evidence; Backup; Logs`
3. **Full folder tree in report** — Location chain, matched folder, and all subfolders.
4. **Copy from selection or text file**
5. **Hide from taskbar** — Hotkey `Ctrl+Shift+H`

## Run from source

```bat
cd folder_scanner_tool
pip install -r requirements.txt
python folder_scanner_app.py
```

## Build EXE

```bat
build_exe.bat
```

Output: `dist\FolderScannerCopier.exe`

## Usage

### Scan path (local or network)

**Important:** Each PC only auto-detects drives mapped on that machine. UNC paths like `\\server\share` are **not** discovered automatically on a new PC.

**On another computer, do one of these:**

1. Click **Add network…** and enter server + share (e.g. `192.168.1.10` + `Forensics`)
2. Type the full path in **Scan path**: `\\server\share`
3. Copy `network_paths.txt` next to the EXE (edit paths first — see `network_paths.example.txt`)

Then click **Refresh** and **Test** to confirm the path works.

1. Click **Refresh** to load local drives, mapped shares, and saved paths from `network_paths.txt`.
2. Pick a **Location** from the dropdown, or type/paste a path in **Scan path**:
   - Local: `D:\` or `D:\Cases`
   - Mapped network: `Z:\`
   - UNC network: `\\NAS\Forensics` or `\\192.168.1.10\share`
3. Use **Browse…** to pick a network folder from the folder dialog.

### Multiple folder names

Enter names separated by semicolon:

```
Evidence; Backup; CaseData; logs
```

The scan finds any folder whose name matches one of these (not case sensitive).

### Copy list file

One path per line. Lines starting with `#` are ignored.

## Hide / Show

- Default hotkey: **Ctrl+Shift+H**
- Hidden = no taskbar button; small progress panel during scan/copy

## Notes

- Network paths are stored in **`network_paths.txt`** in the same folder as the EXE — copy this file when moving to another PC.
- Network scans require access to the share (permissions / VPN connected). Open the path in File Explorer first if **Test** fails.
- Large network scans may be slower than local drives.
- Click **Refresh** after mapping a new network drive or editing `network_paths.txt`.
