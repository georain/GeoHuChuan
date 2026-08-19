@echo off
chcp 65001 >nul
title GeoRainCONNECT Signal Server
cd /d "%~dp0"
echo Starting GeoRainCONNECT signal server...
"C:\Users\Administrator\.workbuddy\binaries\node\versions\22.22.2\node.exe" server.js
echo.
echo Server stopped. Press any key to close.
pause >nul
