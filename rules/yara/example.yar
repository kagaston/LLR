rule SuspiciousPowerShellEncoded
{
    meta:
        description = "Detects base64-encoded PowerShell commands in files"
        severity = "high"
        mitre_attack = "T1059.001"
        author = "IntrusionInspector"

    strings:
        $ps1 = "powershell" ascii nocase
        $ps2 = "pwsh" ascii nocase
        $enc1 = "-enc " ascii nocase
        $enc2 = "-encodedcommand " ascii nocase
        $enc3 = "-e " ascii nocase
        $b64 = /[A-Za-z0-9+\/]{60,}={0,2}/ ascii

    condition:
        ($ps1 or $ps2) and ($enc1 or $enc2 or $enc3) and $b64
}

rule WebShellIndicators
{
    meta:
        description = "Detects common web shell patterns"
        severity = "critical"
        mitre_attack = "T1505.003"
        author = "IntrusionInspector"

    strings:
        $php1 = "eval($_POST" ascii nocase
        $php2 = "eval($_GET" ascii nocase
        $php3 = "eval($_REQUEST" ascii nocase
        $php4 = "assert($_POST" ascii nocase
        $php5 = "system($_GET" ascii nocase
        $php6 = "passthru(" ascii nocase
        $php7 = "shell_exec(" ascii nocase
        $asp1 = "eval(Request" ascii nocase
        $asp2 = "Execute(Request" ascii nocase
        $jsp1 = "Runtime.getRuntime().exec" ascii

    condition:
        any of them
}

rule SuspiciousBatchCommands
{
    meta:
        description = "Detects suspicious batch file commands often used in attacks"
        severity = "medium"
        mitre_attack = "T1059.003"
        author = "IntrusionInspector"

    strings:
        $net1 = "net user /add" ascii nocase
        $net2 = "net localgroup administrators" ascii nocase
        $reg1 = "reg add" ascii nocase
        $reg2 = "reg delete" ascii nocase
        $fw1 = "netsh advfirewall set" ascii nocase
        $fw2 = "netsh firewall set" ascii nocase
        $del1 = "vssadmin delete shadows" ascii nocase
        $del2 = "wbadmin delete catalog" ascii nocase
        $del3 = "bcdedit /set" ascii nocase

    condition:
        2 of them
}
