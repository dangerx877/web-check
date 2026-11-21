@echo off
cd /d "%~dp0"
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (echo Python 3.9+ not found. Install from https://www.python.org/downloads/ and tick "Add python.exe to PATH". & pause & exit /b 1)
%PY% -m venv .venv || (pause & exit /b 1)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt || (pause & exit /b 1)
rem Installs the `netcommander` console command too:
pip install -e .
echo.
echo Done. Start the app by double-clicking run.bat
pause
