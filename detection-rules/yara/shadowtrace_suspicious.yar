rule ShadowTrace_Suspicious_Behavior_Indicators
{
    meta:
        description = "Detects simulated suspicious behavior indicators"
        author = "ShadowTrace"
        severity = "high"

    strings:
        $indicator1 = "powershell encoded command" nocase
        $indicator2 = "disable security tools" nocase
        $indicator3 = "delete backup copies" nocase

    condition:
        2 of them
}
