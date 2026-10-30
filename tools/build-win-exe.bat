@echo off
rem 打包 Windows 图形客户端为单文件 exe（需要 Python 3.8+ 与 pyinstaller）
rem   pip install pyinstaller
rem   tools\build-win-exe.bat
setlocal
cd /d "%~dp0.."

rem 隧道客户端由图形界面在运行时动态加载（importlib），PyInstaller 静态分析看不到
rem 它的依赖，必须逐个显式声明，否则打包后一运行就报 ModuleNotFoundError
python -m PyInstaller --noconfirm --onefile --windowed ^
    --name antipole-tunnel ^
    --hidden-import argparse ^
    --hidden-import base64 ^
    --hidden-import configparser ^
    --hidden-import signal ^
    --hidden-import socket ^
    --hidden-import ssl ^
    --hidden-import struct ^
    --add-data "%CD%\tools\antipole-tunnel.py;." ^
    --distpath dist --workpath build --specpath tools ^
    tools\antipole-tunnel-gui.py || goto :err

echo.
echo 打包完成：dist\antipole-tunnel.exe
echo 使用：双击运行，填接入地址与 UserID，端口映射每行一个。
goto :eof

:err
echo 打包失败，请确认已执行：pip install pyinstaller
exit /b 1