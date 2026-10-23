/*
  قواعد REPLATFORM الأساسية — تحليلية/دفاعية عامة.
  لإضافة قواعدك: ضع ملفات *.yar في هذا المجلد وستُحمَّل تلقائياً.
*/

rule UPX_Packed
{
    meta:
        description = "ملف مضغوط بحزمة UPX"
        severity = "medium"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of ($upx*)
}

rule Suspicious_WinAPI_Combo
{
    meta:
        description = "مزيج APIs يُستخدم عادة في حقن العمليات"
        severity = "high"
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
        $d = "NtUnmapViewOfSection" ascii
    condition:
        3 of them
}

rule PowerShell_Encoded
{
    meta:
        description = "استدعاء PowerShell بترميز"
        severity = "medium"
    strings:
        $ps = "powershell" nocase ascii wide
        $enc = "-enc" ascii wide
        $b64 = "FromBase64String" ascii
    condition:
        $ps and ($enc or $b64)
}

rule PyInstaller_Bundle
{
    meta:
        description = "حزمة PyInstaller"
        severity = "info"
    strings:
        $a = "pyi-windows-manifest-filename" ascii
        $b = "MEIPASS" ascii
    condition:
        any of them
}

rule Electron_App
{
    meta:
        description = "تطبيق Electron"
        severity = "info"
    strings:
        $a = "electron.asar" ascii
        $b = "chrome_100_percent.pak" ascii
    condition:
        any of them
}

rule DotNet_Assembly
{
    meta:
        description = "تجميعة .NET"
        severity = "info"
    strings:
        $bsjb = "BSJB" ascii
    condition:
        uint16(0) == 0x5A4D and $bsjb
}

rule Android_DEX
{
    meta:
        description = "ملف DEX (داخل APK)"
        severity = "info"
    strings:
        $dex35 = "dex\n035" ascii
        $dex39 = "dex\n039" ascii
    condition:
        any of them
}

rule Android_Binary_Manifest
{
    meta:
        description = "AndroidManifest ثنائي"
        severity = "info"
    condition:
        uint32(0) == 0x00080003
}

rule Ransomware_Note_Generic
{
    meta:
        description = "نص مطالبة فدية عام"
        severity = "high"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "all your files are encrypted" nocase
        $c = "send bitcoin" nocase
        $d = "decryption key" nocase
    condition:
        any of them
}

rule Credential_Access_Strings
{
    meta:
        description = "نصوص ذات صلة بالوصول لبيانات حساسة"
        severity = "high"
    strings:
        $a = "Login Data" ascii wide
        $b = "Local State" ascii wide
        $c = "wallet.dat" ascii wide
        $d = "key4.db" ascii wide
    condition:
        3 of them
}
