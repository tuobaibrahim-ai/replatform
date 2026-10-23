<#
.SYNOPSIS
    تحليل سريع لملف EXE: التوقيع الثنائي، معلومات PE، وتحديد الأنواع.
.EXAMPLE
    .\analyze-exe.ps1 -Path .\file.exe
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

# ضبط الترميز لعرض العربية بشكل صحيح
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Text.UTF8Encoding]::new($false)
try { chcp 65001 | Out-Null } catch {}

if (-not (Test-Path $Path)) { Write-Error "الملف غير موجود: $Path"; exit 1 }
$file = Get-Item $Path

Write-Host "=== $($file.Name) ===" -ForegroundColor Cyan
Write-Host ("الحجم      : {0:N0} بايت" -f $file.Length)
Write-Host ("آخر تعديل  : {0}" -f $file.LastWriteTime)

# التوقيع الثنائي (Magic)
$bytes = [System.IO.File]::ReadAllBytes($file.FullName)
$magic = -join ($bytes[0..1] | ForEach-Object { [char]$_ })
switch ($magic) {
    "MZ" {
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        $sig = -join ($bytes[$peOffset..($peOffset + 3)] | ForEach-Object { [char]$_ })
        if ($sig -ne "PE`0`0") { Write-Error "ملف PE تالف"; exit 1 }
        $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
        $arch = switch ($machine) {
            0x014C { "x86 (32-bit)" }
            0x8664 { "x64 (64-bit)" }
            0xAA64 { "ARM64" }
            0x01C4 { "ARMv7" }
            default { "غير معروف (0x{0:X})" -f $machine }
        }
        Write-Host "النوع      : Windows PE executable ($arch)" -ForegroundColor Green
        # تعريف الم compil الشهيرة
        $text = -join ($bytes[0..([Math]::Min(4096, $bytes.Length - 1))] | ForEach-Object { [char]$_ })
        $hints = @(
            @{ P = "This program cannot be run in DOS mode"; N = ".NET / MSVC" },
            @{ P = "UPX0"; N = "UPX packer" },
            @{ P = ".rsrc"; N = "يحتوي موارد (رسائل/أيقونات/ترجمات)" },
            @{ P = "_GSHandlerCheck"; N = "حماية Stack Cookie (MSVC)" },
            @{ P = "nsis"; N = "مثبت NSIS" },
            @{ P = "Py_InitModule"; N = "Python (py2exe)" },
            @{ P = "This file requires the"; N = ".NET assemblies" }
        )
        $found = $hints | Where-Object { $text -match [regex]::Escape($_.P) } | ForEach-Object { $_.N }
        if ($found) { Write-Host "مؤشرات     : $($found -join ', ')" -ForegroundColor Yellow }
    }
    default {
        Write-Host "النوع      : ليس ملف Windows PE (magic='$magic')" -ForegroundColor Yellow
        if ($magic -eq "PK") { Write-Host "             → ملف ZIP/ARJ/JAR/APK مضغوط" }
        elseif ([BitConverter]::ToUInt32($bytes, 0) -eq 0x464C457F) { Write-Host "             → ELF (لينكس)" }
        elseif ($bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45) { Write-Host "             → ELF" }
    }
}

# توقيع DRM / باكرات شائعة
if ($magic -eq "MZ") {
    $sig = @(
        @{ Off = 0x3C; Text = ".NET" },
        @{ Off = 0x80; Text = "VS_VERSION_INFO" }
    )
}

# تجزئة SHA256 للرجوع إلى VirusTotal
$hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
Write-Host "SHA256      : $hash" -ForegroundColor DarkGray
$md5 = (Get-FileHash -Path $file.FullName -Algorithm MD5).Hash
Write-Host "MD5         : $md5" -ForegroundColor DarkGray
