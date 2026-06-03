@echo off
setlocal
cd /d "%~dp0"

echo ============================================
echo  Folder Scanner - Build Windows EXE
echo ============================================

where py >nul 2>&1 && set PY=py || set PY=python
%PY% --version
if errorlevel 1 (
    echo Python not found. Install Python 3.10+ from https://www.python.org/
    pause
    exit /b 1
)

echo.
echo Installing build dependencies...
%PY% -m pip install --upgrade pip
%PY% -m pip install -r requirements.txt

echo.
echo Building executable (one-file, no console)...
%PY% -m PyInstaller ^
    --noconfirm ^
    --clean ^
    --onefile ^
    --windowed ^
    --hidden-import keyboard ^
    --name "FolderScannerCopier" ^
    folder_scanner_app.py

if errorlevel 1 (
    echo Build FAILED.
    pause
    exit /b 1
)

echo.
echo ============================================
echo  SUCCESS
echo  EXE location: dist\FolderScannerCopier.exe
echo  Copy network_paths.example.txt to dist\network_paths.txt and edit paths.
if exist network_paths.example.txt copy /Y network_paths.example.txt dist\network_paths.example.txt >nul
echo ============================================
pause
