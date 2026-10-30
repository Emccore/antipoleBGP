# antipoleBGP 隧道客户端 · Windows 一键安装
#
# 用法（PowerShell 里一行装完）：
#   irm https://raw.githubusercontent.com/Emccore/antipoleBGP/main/tools/install-client.ps1 | iex
#
# 卸载：
#   irm https://raw.githubusercontent.com/Emccore/antipoleBGP/main/tools/install-client.ps1 -OutFile "$env:TEMP\antipole-install.ps1"
#   powershell -ExecutionPolicy Bypass -File "$env:TEMP\antipole-install.ps1" -Uninstall
#
# 说明：程序本体从 GitHub Releases 下载（仓库不放二进制），失败时回退到仓库原始路径；
#       下载后若存在 .sha256 校验文件会自动比对。
param([switch]$Uninstall)

$ErrorActionPreference = "Stop"
# fork 后改这两行
$Repo  = "Emccore/antipoleBGP"
$Raw   = "https://raw.githubusercontent.com/$Repo/main"
$Rel   = "https://github.com/$Repo/releases/latest/download"
$Dir   = Join-Path $env:LOCALAPPDATA "antipole"
$Exe   = Join-Path $Dir "antipole-tunnel.exe"
$Lnk   = Join-Path ([Environment]::GetFolderPath("Desktop")) "antipole 隧道客户端.lnk"

function Say($text, $color = "Gray") { Write-Host $text -ForegroundColor $color }
function Ok($text)  { Say "OK  $text" Green }
function Warn($text){ Say "!   $text" Yellow }
function Die($text) { Say "X   $text" Red; exit 1 }

function New-Shortcut {
    $shell = New-Object -ComObject WScript.Shell
    $sc = $shell.CreateShortcut($Lnk)
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
    Remove-Item $Lnk -Force -ErrorAction SilentlyContinue
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
$src = $null
foreach ($url in @("$Rel/antipole-tunnel.exe", "$Raw/dist/antipole-tunnel.exe")) {
    try {
        Invoke-WebRequest -Uri $url -OutFile $Exe -UseBasicParsing -TimeoutSec 180
        $src = $url; break
    } catch { Warn "下载失败：$url" }
}
if (-not $src) {
    Die "客户端下载失败。可手动从以下地址下载后放到：`n  $Rel/antipole-tunnel.exe`n  $Exe"
}
$size = [Math]::Round((Get-Item $Exe).Length / 1MB, 1)
Ok "已安装 $Exe（$size MB）"

# 校验（发布流程会一并上传 .sha256；没有则跳过）
try {
    $sha = (Invoke-WebRequest -Uri "$src.sha256" -UseBasicParsing -TimeoutSec 30).Content.Trim()
    $want = ($sha -split '\s+')[0].ToLower()
    $got  = (Get-FileHash $Exe -Algorithm SHA256).Hash.ToLower()
    if ($want -eq $got) { Ok "SHA256 校验通过" }
    else { Remove-Item $Exe -Force; Die "SHA256 校验失败，文件可能损坏，已删除；请重试" }
} catch { Warn "未取到校验文件，跳过完整性校验" }

Unblock-File -Path $Exe -ErrorAction SilentlyContinue   # 去掉“来自网络”标记
New-Shortcut

Say "`n▸ 完成" -color DarkGray
Say "  双击桌面「antipole 隧道客户端」运行，填接入地址与令牌即可。" Cyan
Say "  配置与证书保存在 $Dir" -color DarkGray
Say "  卸载：irm $Raw/tools/install-client.ps1 -OutFile `$env:TEMP\a.ps1; & `$env:TEMP\a.ps1 -Uninstall" -color DarkGray
