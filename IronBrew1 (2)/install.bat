@echo off
py -m pip install -e . --no-build-isolation
if errorlevel 1 (
  echo.
  echo Editable install failed. You can still use: py ib1.py --help
  exit /b 1
)
echo.
echo Installed. Try: ib1 --help
