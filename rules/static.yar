rule UPX_Packer {
    meta:
        description = "UPX packer detected"
        severity = "medium"
    strings:
        $a = "UPX0" ascii
        $b = "UPX1" ascii
        $c = "UPX!" ascii
    condition:
        any of them
}

rule MPRESS_Packer {
    meta:
        description = "MPRESS packer detected"
        severity = "medium"
    strings:
        $a = ".MPRESS1" ascii
        $b = ".MPRESS2" ascii
    condition:
        any of them
}

rule Themida_Packer {
    meta:
        description = "Themida/WinLicense protector detected"
        severity = "medium"
    strings:
        $a = ".themida" ascii nocase
        $b = "WinLicense" ascii
    condition:
        any of them
}

rule Process_Injection_APIs {
    meta:
        description = "Classic process-injection API triad present"
        severity = "high"
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
        $d = "NtUnmapViewOfSection" ascii
        $e = "RtlCreateUserThread" ascii
        $f = "SetThreadContext" ascii
    condition:
        2 of them
}

rule PEB_Traversal {
    meta:
        description = "PEB traversal pattern (shellcode / reflective loader)"
        severity = "high"
    strings:
        $peb32 = { 64 A1 30 00 00 00 }
        $peb64 = { 65 48 8B 04 25 60 00 00 00 }
        $peb_fs = { 64 8B 15 30 00 00 00 }
    condition:
        any of them
}

rule Powershell_Encoded_Command {
    meta:
        description = "Encoded / hidden PowerShell execution"
        severity = "high"
    strings:
        $enc  = "-EncodedCommand" nocase ascii wide
        $enc2 = "-EncodedC" nocase ascii wide
        $byp  = "bypass" nocase ascii wide
        $hid  = "Hidden" nocase ascii wide
        $exec = "ExecutionPolicy" nocase ascii wide
    condition:
        2 of them
}

rule AutoRun_Persistence {
    meta:
        description = "Registry autorun key write (persistence)"
        severity = "medium"
    strings:
        $run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $svc  = "CreateService" ascii
    condition:
        any of ($run1, $run2) or $svc
}

rule Suspicious_Download {
    meta:
        description = "HTTP download + execute pattern"
        severity = "medium"
    strings:
        $dl1 = "URLDownloadToFile" ascii
        $dl2 = "WinHttpOpen" ascii
        $dl3 = "InternetOpenUrl" ascii
        $ex1 = "ShellExecute" ascii
        $ex2 = "WinExec" ascii
        $ex3 = "CreateProcess" ascii
    condition:
        1 of ($dl1, $dl2, $dl3) and 1 of ($ex1, $ex2, $ex3)
}
