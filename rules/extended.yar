/*
  REPLATFORM — extended YARA rules
  قواعد موسّعة لأكثر أنماط البرمجيات الخبيثة شيوعاً.
  كل القواعد تعمل بلا وحدات خارجية (pure YARA) لتبقى محمولة.
*/

rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download cradle (IEX/DownloadString/WebClient)"
        author = "REPLATFORM"
        severity = "high"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-enc" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "Invoke-WebRequest" nocase
        $dl4 = "Net.WebClient" nocase
        $iex = "IEX" nocase
    condition:
        ($ps1 or $ps2) and 2 of ($dl*) and $iex
}

rule Base64_Encoded_PowerShell
{
    meta:
        description = "Base64-encoded PowerShell payload (-enc / FromBase64String)"
        author = "REPLATFORM"
        severity = "medium"
    strings:
        $a = "-EncodedCommand" nocase
        $b = "FromBase64String" nocase
        $c = "powershell -e" nocase
        $d = "powershell.exe -e" nocase
    condition:
        any of them
}

rule Credential_Dumping_LSASS
{
    meta:
        description = "LSASS credential dumping indicators"
        author = "REPLATFORM"
        severity = "critical"
    strings:
        $lsass = "lsass.exe" nocase
        $dump1 = "MiniDumpWriteDump" nocase
        $dump2 = "dbghelp.dll" nocase
        $sekurlsa = "sekurlsa" nocase
        $procdump = "procdump" nocase
        $comsvcs = "comsvcs.dll" nocase
    condition:
        ($lsass and 1 of ($dump*)) or $sekurlsa or ($comsvcs and $lsass) or $procdump
}

rule Ransomware_Note_Indicators
{
    meta:
        description = "Ransom note / encryption extortion strings"
        author = "REPLATFORM"
        severity = "high"
    strings:
        $n1 = "your files have been encrypted" nocase
        $n2 = "all your files are encrypted" nocase
        $n3 = "to decrypt your files" nocase
        $n4 = "bitcoin" nocase
        $n5 = "ransom" nocase
        $n6 = ".onion" nocase
    condition:
        2 of ($n1, $n2, $n3) or (1 of ($n1, $n2, $n3) and 2 of ($n4, $n5, $n6))
}

rule UPX_Packed_Binary
{
    meta:
        description = "UPX-packed executable sections"
        author = "REPLATFORM"
        severity = "medium"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx_mark = "UPX!" 
    condition:
        ($upx0 and $upx1) or $upx_mark
}

rule Scheduled_Task_Persistence
{
    meta:
        description = "Scheduled task persistence via schtasks"
        author = "REPLATFORM"
        severity = "medium"
    strings:
        $sch = "schtasks" nocase
        $create = "/create" nocase
        $sc = "sc.exe create" nocase
        $run = "CurrentVersion\\Run" nocase
        $startup = "\\Startup\\" nocase
    condition:
        ($sch and $create) or $sc or $run or $startup
}

rule Anti_Debug_Checks
{
    meta:
        description = "Anti-debugging API combination"
        author = "REPLATFORM"
        severity = "medium"
    strings:
        $a = "IsDebuggerPresent"
        $b = "CheckRemoteDebuggerPresent"
        $c = "NtQueryInformationProcess"
        $d = "OutputDebugStringA"
    condition:
        2 of them
}

rule Process_Injection_Combo
{
    meta:
        description = "Classic process injection API sequence"
        author = "REPLATFORM"
        severity = "high"
    strings:
        $open = "OpenProcess"
        $alloc = "VirtualAllocEx"
        $write = "WriteProcessMemory"
        $thread = "CreateRemoteThread"
        $apc = "QueueUserAPC"
        $map = "MapViewOfFile"
    condition:
        $open and $alloc and ($write or $map) and ($thread or $apc)
}

rule Defender_Exclusion_Attempt
{
    meta:
        description = "Attempts to disable or exclude Windows Defender"
        author = "REPLATFORM"
        severity = "high"
    strings:
        $a = "Add-MpPreference" nocase
        $b = "-ExclusionPath" nocase
        $c = "Set-MpPreference" nocase
        $d = "-DisableRealtimeMonitoring" nocase
        $e = "AMSI" nocase
    condition:
        ($a or $c) and ($b or $d) or ($e and $a)
}
