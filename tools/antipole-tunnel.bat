@echo off
rem antipoleBGP 隧道客户端 Windows 启动器：自动挑选可用的 Python 3
rem 用法：antipole-tunnel.bat --server [2600:1:2:ff00::1]:18281 --token xxx --map 8080
setlocal
set "SCRIPT=%~dp0antipole-tunnel.py"

where py >nul 2>nul
if not errorlevel 1 (
    py -3 "%SCRIPT%" %*
    goto :end
)

where python >nul 2>nul
if not errorlevel 1 (
    python "%SCRIPT%" %*
    goto :end
)

echo 未检测到 Python 3，请先安装：https://www.python.org/downloads/
echo 安装时勾选 "Add python.exe to PATH"。

:end
if "%~1"=="" pause