# antipoleBGP 隧道客户端 · Windows 一键安装
#
# 用法（PowerShell 里一行装完）：
#   irm https://raw.githubusercontent.com/Emccore/antipoleBGP/main/tools/install-client.ps1 | iex
#
# 卸载：
#   irm .../install-client.ps1 -OutFile "$env:TEMP\antipole-install.ps1"
#   powershell -ExecutionPolicy Bypass -File "$env:TEMP\antipole-install.ps1" -Uninstall
#
param([switch]$Uninstall)

$ErrorActionPreference = "Stop"
# 仓库原始文件地址前缀（fork 后改这里）
$Raw   = "https://raw.githubusercontent.com/Emccore/antipoleBGP/main"
$Dir   = Join-Path $env:LOCALAPPDATA "antipole"
$Exe   = Join-Path $Dir "antipole-tunnel.exe"

function Say($text, $color = "Gray") { Write-Host $text -ForegroundColor $color }
function Ok($text)  { Say "OK  $text" Green }
function Warn($text){ Say "!   $text" Yellow }
function Die($text) { Say "X   $text" Red; exit 1 }

# 桌面快捷方式
function New-Shortcut {
    $desktop = [Environment]::GetFolderPath("Desktop")
    $lnk = Join-Path $desktop "antipole 隧道客户端.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $sc = $shell.CreateShortcut($lnk)
    $sc.TargetPath = $Exe
    $sc.WorkingDirectory = $Dir
    $sc.IconLocation = $Exe
    $sc.Description = "antipoleBGP 隧道客户端"
    $sc.Save()
    Ok "桌面快捷方式已创建"
}

if ($Uninstall) {
    Say "`n▸ 卸载" -color DarkGray
    Get-Process antipole-tunnel -ErrorAction SilentlyContinue | Stop-Process -Force
    Remove-Item (Join-Path ([Environment]::GetFolderPath("Desktop")) "antipole 隧道客户端.lnk") -Force -ErrorAction SilentlyContinue
    # 只删程序，保留配置与证书（如需彻底清除请手动删目录）
    Remove-Item $Exe -Force -ErrorAction SilentlyContinue
    Ok "已卸载（配置与证书保留在 $Dir）"
    exit 0
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Say "`n▸ 检查环境" -color DarkGray
$v6 = Get-NetAdapterBinding -ComponentID "ms_tcpip6" -ErrorAction SilentlyContinue |
      Where-Object { $_.Enabled } | Select-Object -First 1
if (-not $v6) { Warn "检测到未启用 IPv6，隧道需要 IPv6 出网，请先在网络适配器里勾选 IPv6" }
Ok "Windows $([Environment]::OSVersion.Version.Major) · $($env:PROCESSOR_ARCHITECTURE)"

Say "`n▸ 下载客户端" -color DarkGray
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$url = "$Raw/dist/antipole-tunnel.exe"
try {
    Invoke-WebRequest -Uri $url -OutFile $Exe -UseBasicParsing -TimeoutSec 120
} catch {
    Die "下载失败：$url`n  可手动下载后放到 $Exe"
}
Unblock-File -Path $Exe -ErrorAction SilentlyContinue   # 去掉“来自网络”标记
Ok "已安装 $Exe"

New-Shortcut

Say "`n▸ 完成" -color DarkGray
Say "  双击桌面「antipole 隧道客户端」运行，填接入地址与令牌即可。" Cyan
Say "  配置与证书保存在 $Dir" -color DarkGray
