<#
.SYNOPSIS
    الوكيل الرئيسي الموحد: جرد → تحليل → (اختيارياً) مسح سريع للثغرات الشائعة.
.DESCRIPTION
    يشغّل الوكلاء الثلاثة بالترتيب:
      1) inventory_agent  — جرد البرامج المثبتة (Registry + Appx + اختصارات)
      2) analyze_agent    — تحليل PE متوازٍ + تقرير HTML
      3) تعديل يدوي       — عبر patch_agent (يتطلب --find/--replace صريحاً — لا تعديل تلقائي أبداً)
.EXAMPLE
    .\run_all.ps1                                   # جرد + تحليل Program Files
    .\run_all.ps1 -ScanPath "D:\portable"           # تحليل مجلد برامج محمولة
    .\run_all.ps1 -SkipInventory                    # تخطي الجرد
    .\run_all.ps1 -Workers 12                       # خيوط أكثر
#>
param(
    [string]$ScanPath = "",
    [int]$Workers = 8,
    [switch]$SkipInventory,
    [string]$Ext = ".exe,.dll,.sys,.scr"
)

[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
try { chcp 65001 | Out-Null } catch {}

$Agents = $PSScriptRoot
$Out = Join-Path $Agents "out"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$py = "python"

Write-Host "=== الوكيل الرئيسي: تحليل البرامج المثبتة وغير المثبتة ===" -ForegroundColor Cyan
$t0 = Get-Date

# 1) الجرد
if (-not $SkipInventory) {
    Write-Host "`n[1/3] وكيل الجرد ..." -ForegroundColor Yellow
    & (Join-Path $Agents "inventory_agent.ps1") -OutCsv (Join-Path $Out "installed.csv")
} else {
    Write-Host "`n[1/3] تخطي الجرد" -ForegroundColor DarkGray
}

# 2) تحليل مجلد محدد أو افتراضي
if (-not $ScanPath) {
    $cands = @("C:\Program Files", "C:\Program Files (x86)")
    $ScanPath = $cands | Where-Object { Test-Path $_ } | Select-Object -First 1
    Write-Host "`n[2/3] التحليل الافتراضي: $ScanPath (استخدم -ScanPath لتحديد مجلد آخر)" -ForegroundColor Yellow
} else {
    Write-Host "`n[2/3] التحليل: $ScanPath" -ForegroundColor Yellow
}

& $py (Join-Path $Agents "analyze_agent.py") $ScanPath `
    -o (Join-Path $Out "analysis.csv") `
    --html (Join-Path $Out "report.html") `
    --workers $Workers --ext $Ext

# 3) فتح التقرير
$html = Join-Path $Out "report.html"
$elapsed = (Get-Date) - $t0
Write-Host "`n[3/3] اكتمل في $([int]$elapsed.TotalSeconds) ث" -ForegroundColor Green
if (Test-Path $html) {
    Write-Host "افتح التقرير:" -ForegroundColor Green
    Write-Host "  $html"
    $open = Read-Host "هل تريد فتحه الآن؟ (y/n)"
    if ($open -eq "y") { Start-Process $html }
}

Write-Host @"

للتعديل الآمن على ملف محدد (معاينة أولاً ثم --apply):
  python agents\patch_agent.py <ملف.exe> --find "str:قديم" --replace "str:جديد"
  python agents\patch_agent.py <ملف.exe> --find "hex:90 90" --replace "hex:31 C0" --apply
"@ -ForegroundColor DarkGray
