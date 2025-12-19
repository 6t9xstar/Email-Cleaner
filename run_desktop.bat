@echo off
echo Installing dependencies...
pip install -r requirements_desktop.txt
echo.
echo Starting Email List Cleaner...
python email_cleaner.py
pause
