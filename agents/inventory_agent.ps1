<#
.SYNOPSIS
    وكيل جرد البرامج المثبتة: Registry + Appx + اختصارات القائمة ابدأ و سطح المكتب.
.DESCRIPTION
    يجمع قائمة البرامج المثبتة من ثلاث مصادر ويخرجها CSV — يُستخدم كمدخل لوكيل التحليل.
.EXAMPLE
    .\inventory_agent.ps1
    .\inventory_agent.ps1 -OutCsv .\out\installed.csv
#>
param(
    [string]$OutCsv = (Join-Path $PSScriptRoot "out\installed.csv")
)

# ضبط الترميز لعرض العربية
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
try { chcp 65001 | Out-Null } catch {}

New-Item -ItemType Directory -Force -Path (Split-Path $OutCsv) | Out-Null
$rows = [System.Collections.Generic.List[object]]::new()

# 1) مفاتيح إلغاء التثبيت في Registry (64-bit + 32-bit + HKCU)
$keys = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"; View = "64" }
    @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"; View = "32" }
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"; View = "64" }
)
foreach ($k in $keys) {
    Get-ItemProperty $k.Path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
        $loc = $_.InstallLocation
        $mainExe = ""
        if ($loc -and (Test-Path $loc -PathType Container)) {
            $exe = Get-ChildItem $loc -Filter "*.exe" -File -ErrorAction SilentlyContinue |
                Sort-Object Length -Descending | Select-Object -First 1
            if ($exe) { $mainExe = $exe.FullName }
        }
        $rows.Add([pscustomobject]@{
            المصدر          = "registry"
            الاسم           = $_.DisplayName
            الناشر          = $_.Publisher
            الإصدار         = $_.DisplayVersion
            المعمارية       = $k.View
            الموقع          = $loc
            EXE_رئيسي       = $mainExe
            إلغاء_التثبيت   = $_.UninstallString
        })
    }
}

# 2) تطبيقات Microsoft Store (Appx)
Get-AppxPackage -ErrorAction SilentlyContinue | ForEach-Object {
    $ver = ($_.PackageFullName -split "_")[1]
    $rows.Add([pscustomobject]@{
        المصدر          = "appx"
        الاسم           = $_.Name
        الناشر          = $_.Publisher
        الإصدار         = $ver
        المعمارية       = ""
        الموقع          = $_.InstallLocation
        EXE_رئيسي       = ""
        إلغاء_التثبيت   = ""
    })
}

# 3) اختصارات سطح المكتب والقائمة ابدأ (تهدف للبرامج "غير المثبتة" أيضاً — portable)
$wsh = New-Object -ComObject WScript.Shell
$lnkDirs = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
    "$env:USERPROFILE\Desktop"
    "$env:PUBLIC\Desktop"
) | Where-Object { Test-Path $_ }

$seen = @{}
foreach ($dir in $lnkDirs) {
    Get-ChildItem $dir -Recurse -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $target = $wsh.CreateShortcut($_.FullName).TargetPath
        } catch { return }
        if (-not $target -or -not (Test-Path $target -PathType Leaf)) { return }
        if ($seen.ContainsKey($target.ToLower())) { return }
        $seen[$target.ToLower()] = $true
        $rows.Add([pscustomobject]@{
            المصدر          = "shortcut"
            الاسم           = [IO.Path]::GetFileNameWithoutExtension($target)
            الناشر          = ""
            الإصدار         = ""
            المعمارية       = ""
            الموقع          = [IO.Path]::GetDirectoryName($target)
            EXE_رئيسي       = $target
            إلغاء_التثبيت   = ""
        })
    }
}

$rows | Sort-Object المصدر, الاسم | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8

Write-Host "`n=== ملخص الجرد ===" -ForegroundColor Cyan
$rows | Group-Object المصدر | ForEach-Object {
    Write-Host ("  {0,-9}: {1}" -f $_.Name, $_.Count)
}
Write-Host ("  الإجمالي : {0}" -f $rows.Count) -ForegroundColor Green
Write-Host ("  الملف    : {0}" -f $OutCsv) -ForegroundColor Green
Write-Host "`nالخطوة التالية: حلّل الملفات المستهدفة بوكيل التحليل، مثلاً:" -ForegroundColor DarkGray
Write-Host '  python agents\analyze_agent.py "<مجلد>" -o agents\out\analysis.csv --html agents\out\report.html' -ForegroundColor DarkGray
