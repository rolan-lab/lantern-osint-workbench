@echo off
setlocal
rem ------------------------------------------------------------------------------------------
rem  Builds ..\dist\Lantern.exe (single file, no console window).
rem  Build tools (venv, PyInstaller work files) live in %TEMP%\lantern-build, not in this folder,
rem  so nothing large gets synced to OneDrive. Re-run after editing the web app to rebuild.
rem ------------------------------------------------------------------------------------------
set "HERE=%~dp0"
for %%I in ("%HERE%..") do set "ROOT=%%~fI"
set "WORK=%TEMP%\lantern-build"
set "PY=%WORK%\venv\Scripts\python.exe"

if not exist "%PY%" (
  echo Creating build environment in %WORK% ...
  python -m venv "%WORK%\venv" || goto :fail
)
"%PY%" -m pip install --quiet --upgrade pip || goto :fail
"%PY%" -m pip install --quiet "pyinstaller>=6.10" "pywebview>=5.3" || goto :fail
"%PY%" "%HERE%make_icon.py" "%HERE%lantern.ico" || goto :fail

"%PY%" -m PyInstaller --noconfirm --clean --onefile --windowed --name Lantern ^
  --icon "%HERE%lantern.ico" ^
  --add-data "%ROOT%\index.html;web" ^
  --add-data "%ROOT%\css;web\css" ^
  --add-data "%ROOT%\js;web\js" ^
  --distpath "%ROOT%\dist" --workpath "%WORK%\work" --specpath "%WORK%" ^
  "%HERE%lantern_app.py" || goto :fail

echo.
echo Built: %ROOT%\dist\Lantern.exe
exit /b 0

:fail
echo.
echo Build failed.
exit /b 1
