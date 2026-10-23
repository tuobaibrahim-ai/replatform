<#
.SYNOPSIS
    دورة عمل كاملة لـ APK: فك، (يدوي: تعديل)، إعادة بناء، توقيع.
.EXAMPLE
    .\apk-workflow.ps1 -Action decode -Apk .\app.apk
    .\apk-workflow.ps1 -Action build -Dir .\app_decoded
    .\apk-workflow.ps1 -Action sign -Apk .\app_modified.apk
    .\apk-workflow.ps1 -Action full -Apk .\app.apk   # فك فقط (عدّل ثم build)
    .\apk-workflow.ps1 -Action install -Apk .\app_modified-signed.apk
#>
param(
    [ValidateSet("decode", "build", "sign", "install", "java", "full")]
    [string]$Action = "decode",
    [string]$Apk,
    [string]$Dir,
    [string]$Java = "java"
)

# ضبط الترميز لعرض العربية بشكل صحيح
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
try { chcp 65001 | Out-Null } catch {}

$Tools = Join-Path $PSScriptRoot "..\tools"
$Apktool = Join-Path $Tools "apktool.jar"
$Signer = Join-Path $Tools "uber-apk-signer.jar"

function Require-File($p) {
    if (-not (Test-Path $p)) { throw "الملف غير موجود: $p" }
}

switch ($Action) {
    "decode" {
        if (-not $Apk) { throw "حدد -Apk" }
        Require-File $Apk
        $out = if ($Dir) { $Dir } else { [IO.Path]::GetFileNameWithoutExtension($Apk) + "_decoded" }
        & $Java -jar $Apktool d $Apk -o $out -f
        if ($LASTEXITCODE -ne 0) { throw "فشل فك APK" }
        Write-Host "✓ تم الفك في: $out" -ForegroundColor Green
        Write-Host "عدّل ملفات Smali في $out\smali ثم شغّل: .\apk-workflow.ps1 -Action build -Dir $out"
    }
    "build" {
        if (-not $Dir) { throw "حدد -Dir (مجلد المشروع المفكوك)" }
        Require-File $Dir
        $out = if ($Apk) { $Apk } else { "modified.apk" }
        & $Java -jar $Apktool b $Dir -o $out
        if ($LASTEXITCODE -ne 0) { throw "فشل بناء APK" }
        Write-Host "✓ تم البناء: $out" -ForegroundColor Green
        Write-Host "الخطوة التالية: .\apk-workflow.ps1 -Action sign -Apk $out"
    }
    "sign" {
        if (-not $Apk) { throw "حدد -Apk" }
        Require-File $Apk
        & $Java -jar $Signer --apks $Apk
        if ($LASTEXITCODE -ne 0) { throw "فشل التوقيع" }
        Write-Host "✓ تم التوقيع (الناتج بجانب الملف الأصلي بلاحقة -signed.apk)" -ForegroundColor Green
    }
    "install" {
        if (-not $Apk) { throw "حدد -Apk" }
        Require-File $Apk
        adb install -r $Apk
        if ($LASTEXITCODE -eq 0) { Write-Host "✓ تم التثبيت على الجهاز" -ForegroundColor Green }
    }
    "java" {
        if (-not $Apk) { throw "حدد -Apk" }
        Require-File $Apk
        $out = if ($Dir) { $Dir } else { [IO.Path]::GetFileNameWithoutExtension($Apk) + "_java" }
        jadx $Apk -d $out
        if ($LASTEXITCODE -ne 0) { throw "فشل jadx" }
        Write-Host "✓ كود Java في: $out\sources" -ForegroundColor Green
    }
    "full" {
        # فك فقط ثم تذكير بخطوات التعديل
        & $PSCommandPath -Action decode -Apk $Apk -Dir $Dir
    }
}
