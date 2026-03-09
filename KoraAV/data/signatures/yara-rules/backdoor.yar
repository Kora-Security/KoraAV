/*
   YARA Rules - Backdoor/RAT Detection
   Compatible with: YARA v4.x
   Author: KoraAV Project Default
   Description: Detects Remote Access Trojans and backdoors
   Last Updated: 2025-02-23
*/

import "pe"

rule Generic_RAT {
    meta:
        description = "Generic Remote Access Trojan indicators"
        severity = "high"
        confidence = "medium"
        category = "backdoor"
        
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "/c" nocase
        $cmd3 = "powershell" nocase
        
        $net1 = "connect" nocase
        $net2 = "send" nocase
        $net3 = "recv" nocase
        
        $control1 = "screenshot" nocase
        $control2 = "keylog" nocase
        $control3 = "download" nocase
        $control4 = "upload" nocase
        $control5 = "execute" nocase
        
    condition:
        (2 of ($cmd*) and 2 of ($net*)) or
        (3 of ($control*) and 1 of ($net*))
}

rule Cobalt_Strike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon"
        severity = "critical"
        confidence = "high"
        category = "backdoor"
        family = "CobaltStrike"
        
    strings:
        $str1 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s"
        $str2 = "%s as %s\\%s: %d" nocase
        $str3 = "beacon.dll" nocase
        $str4 = "beacon.x64.dll" nocase
        $str5 = "ReflectiveLoader" nocase
        
        $config = { 00 01 00 01 00 02 }
        
    condition:
        2 of them
}

rule Metasploit_Meterpreter {
    meta:
        description = "Detects Metasploit Meterpreter payload"
        severity = "critical"
        confidence = "high"
        category = "backdoor"
        family = "Meterpreter"
        
    strings:
        $str1 = "metsrv.dll" nocase
        $str2 = "ext_server_" nocase
        $str3 = "stdapi_" nocase
        $str4 = "ReflectiveLoader" nocase
        $str5 = "meterpreter" nocase
        
    condition:
        2 of them
}

rule NjRAT {
    meta:
        description = "Detects NjRAT/Bladabindi"
        severity = "critical"
        confidence = "high"
        category = "backdoor"
        family = "NjRAT"
        
    strings:
        $str1 = "njRAT" nocase
        $str2 = "Bladabindi" nocase
        $str3 = "SEE_MASK_NOZONECHECKS" nocase
        $str4 = "ll.ant" nocase
        $str5 = "tcp://" nocase
        
        $cmd1 = "cmd.exe /c ping 0 -n 2 & del" nocase
        
    condition:
        2 of them
}

rule AsyncRAT {
    meta:
        description = "Detects AsyncRAT"
        severity = "critical"
        confidence = "high"
        category = "backdoor"
        family = "AsyncRAT"
        
    strings:
        $str1 = "AsyncRAT" nocase
        $str2 = "Pastebin" nocase
        $str3 = "Paste_bin" nocase
        $str4 = "pong" nocase
        $str5 = "Plugin" nocase
        
        $mutex = "AsyncMutex_" nocase
        
    condition:
        2 of ($str*) or $mutex
}

rule DarkComet_RAT {
    meta:
        description = "Detects DarkComet RAT"
        severity = "critical"
        confidence = "high"
        category = "backdoor"
        family = "DarkComet"
        
    strings:
        $str1 = "DarkComet" nocase
        $str2 = "DC_MUTEX-" nocase
        $str3 = "DCDATA" nocase
        $str4 = "StartREC" nocase
        
    condition:
        2 of them
}

rule QuasarRAT {
    meta:
        description = "Detects Quasar RAT"
        severity = "critical"
        confidence = "high"
        category = "backdoor"
        family = "QuasarRAT"
        
    strings:
        $str1 = "Quasar" nocase
        $str2 = "xRAT" nocase
        $str3 = "GetKeyloggerLogsResponse" nocase
        $str4 = "GetPasswordsResponse" nocase
        $str5 = "DoShellExecuteResponse" nocase
        
    condition:
        2 of them
}

rule RemcosRAT {
    meta:
        description = "Detects Remcos RAT"
        severity = "critical"
        confidence = "high"
        category = "backdoor"
        family = "Remcos"
        
    strings:
        $str1 = "Remcos" nocase
        $str2 = "RemoteControl" nocase
        $str3 = "Breaking-Security" nocase
        $str4 = "remcos_" nocase
        
    condition:
        2 of them
}

rule NetWire_RAT {
    meta:
        description = "Detects NetWire RAT"
        severity = "critical"
        confidence = "high"
        category = "backdoor"
        family = "NetWire"
        
    strings:
        $str1 = "NetWire" nocase
        $str2 = "HostId-%Rand%" nocase
        $str3 = "GetKeyState" nocase
        $str4 = "[%.2d:%.2d:%.2d]" nocase
        
    condition:
        2 of them
}

rule Generic_Reverse_Shell {
    meta:
        description = "Generic reverse shell detection"
        severity = "high"
        confidence = "medium"
        category = "backdoor"
        
    strings:
        $bash1 = "bash -i >& /dev/tcp/" nocase
        $bash2 = "bash -c 'bash -i" nocase
        $bash3 = "0<&196;exec 196<>/dev/tcp/" nocase
        
        $python1 = "import socket" nocase
        $python2 = "subprocess" nocase
        $python3 = "STDOUT" nocase
        
        $perl1 = "use Socket" nocase
        $perl2 = "STDIN->fdopen" nocase
        
        $nc1 = "nc -e" nocase
        $nc2 = "ncat -e" nocase
        
    condition:
        (2 of ($bash*)) or
        (all of ($python*)) or
        (all of ($perl*)) or
        (1 of ($nc*))
}

rule Web_Shell {
    meta:
        description = "Generic web shell detection"
        severity = "high"
        confidence = "medium"
        category = "backdoor"
        
    strings:
        $php1 = "<?php" nocase
        $php2 = "eval" nocase
        $php3 = "base64_decode" nocase
        $php4 = "system(" nocase
        $php5 = "shell_exec" nocase
        $php6 = "passthru" nocase
        
        $asp1 = "<%eval" nocase
        $asp2 = "execute" nocase
        
        $jsp1 = "Runtime.getRuntime()" nocase
        $jsp2 = ".exec(" nocase
        
    condition:
        ($php1 and 2 of ($php*)) or
        (all of ($asp*)) or
        (all of ($jsp*))
}

