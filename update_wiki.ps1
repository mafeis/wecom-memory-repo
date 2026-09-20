# 企业微信记忆仓库 - 一键更新脚本
# 用法: 右键"使用 PowerShell 运行"，或执行  powershell -File update_wiki.ps1
# 前提: 企业微信 (WXWork.exe) 正在运行且已登录
# 说明: 全程只读取源数据库的共享只读快照，绝不修改企业微信源文件

$ErrorActionPreference = "Stop"
$env:PYTHONIOENCODING = "utf-8"

$Base = Split-Path -Parent $MyInvocation.MyCommand.Path   # 脚本所在目录 = 仓库根目录
$Raw  = "$Base\wxwork_data\raw"
$Vend = "$Base\vendors\wecom-reader"
$WxDocs = Join-Path $env:USERPROFILE "Documents\WXWork"

# 1) 快照所有账号的 Data 目录（共享只读复制）
$accounts = Get-ChildItem $WxDocs -Directory |
    Where-Object { $_.Name -match "^\d+$" -and (Test-Path (Join-Path $_.FullName "Data")) }
foreach ($acc in $accounts) {
    $src = Join-Path $acc.FullName "Data"
    $dst = Join-Path $Raw $acc.Name
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    Get-ChildItem $src -File -Filter "*.db*" | ForEach-Object {
        $fs = [System.IO.File]::Open($_.FullName, 'Open', 'Read', [System.IO.FileShare]::ReadWrite)
        $fo = [System.IO.File]::Open((Join-Path $dst $_.Name), 'Create', 'Write', 'Read')
        $fs.CopyTo($fo); $fs.Close(); $fo.Close()
    }
    Write-Host "[快照] $($acc.Name)"
}

# 2) 提取密钥（需要 WXWork.exe 运行中）
Push-Location $Vend
foreach ($acc in $accounts) {
    python -m wecom_reader.cli --db-dir "$Raw\$($acc.Name)" --decrypted-dir "$Base\wxwork_data\decrypted\$($acc.Name)" init --timeout 300
}
Pop-Location

# 3) 保存密钥 + 重建 wiki（含 WAL 合并）+ 生成 HTML
python "$Base\tools\save_keys.py"
python "$Base\tools\build_wiki.py"
python "$Base\tools\gen_html.py"

Write-Host ""
Write-Host "完成！打开 $Base\wiki\企业微信记忆仓库.html 搜索查阅"
