Write-Host ""
Write-Host "Microsoft Security Baseline Recommendations:" -ForegroundColor Cyan
if ($spynetReporting -eq 0) {
    Write-Host "  • CRITICAL: Enable Cloud Protection immediately (Microsoft Baseline requirement)" -ForegroundColor Red
    Write-Host "  • Set SpynetReporting=2 and SubmitSamplesConsent=1 (Safe Samples)" -ForegroundColor Yellow
} elseif ($spynetReporting -in @(1,2) -and $submitSamplesConsent -eq 1) {
    Write-Host "  • Configuration aligns with Microsoft Security Baseline" -ForegroundColor Green
    Write-Host "  • Block at First Sight enabled for optimal protection" -ForegroundColor Green
    Write-Host "  • Meets NIST SP 800-53 SI-3 (Malicious Code Protection) requirements" -ForegroundColor Green
} elseif ($spynetReporting -in @(1,2) -and $submitSamplesConsent -eq 3) {
    Write-Host "  • Maximum protection enabled (Microsoft default baseline)" -ForegroundColor Green
    Write-Host "  • Consider privacy implications for sensitive environments" -ForegroundColor Yellow
    Write-Host "  • Exceeds NIST SP 800-53 SI-3 requirements" -ForegroundColor Green
} elseif ($submitSamplesConsent -eq 2) {
    Write-Host "  • 'Never Send' disables Block at First Sight (reduced protection)" -ForegroundColor Yellow
    Write-Host "  • Consider Safe Samples Auto (SubmitSamplesConsent=1) for better security" -ForegroundColor Yellow
    Write-Host "  • May not fully meet NIST SP 800-53 SI-3 collaborative defense requirements" -ForegroundColor Yellow
} elseif ($submitSamplesConsent -eq 0) {
    Write-Host "  • User prompts create inconsistent protection" -ForegroundColor Yellow
    Write-Host "  • Microsoft recommends automated sample submission" -Fore# NIST SP 800-92 Log Management Integration (if requested)
if ($ForwardToSIEM -and $SyslogServer) {
    Write-Host ""
    Write-Host "NIST SP 800-92 Log Management Integration:" -ForegroundColor Yellow
    try {
        # Collect MAPS-related events for SIEM forwarding
        $recentEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=(Get-Date).AddHours(-1); ID=1116,1117,1118,5007} -ErrorAction SilentlyContinue
        
        # Log integrity validation (basic check)
        $logIntegrityCheck = try {
            $totalLogSize = (Get-WinEvent -ListLog 'Microsoft-Windows-Windows Defender/Operational').FileSize
            $logIsWritable = (Get-WinEvent -ListLog 'Microsoft-Windows-Windows Defender/Operational').IsEnabled
            @{
                LogSize = [math]::Round($totalLogSize / 1MB, 2)
                IsEnabled = $logIsWritable
                IntegrityStatus = if ($logIsWritable) { "Intact" } else { "Issue Detected" }
            }
        } catch {
            @{ IntegrityStatus = "Cannot Verify" }
        }
        
        foreach ($event in $recentEvents) {
            $syslogMessage = @{
                Timestamp = $event.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                Hostname = $computerInfo.ComputerName
                EventType = "MAPS_Event"
                EventId = $event.Id
                Message = $event.Message
                SpynetReporting = $spynetReporting
                SubmitSamplesConsent = $submitSamplesConsent
                LogIntegrity = $logIntegrityCheck.IntegrityStatus
            } | ConvertTo-Json -Compress
            
            # Simple UDP syslog send (RFC 3164 format)
            $udpClient = New-Object System.Net.Sockets.UdpClient
            $facility = 16 # local0
            $severity = 6  # info
            $priority = $facility * 8 + $severity
            $bytes = [System.Text.Encoding]::UTF8.GetBytes("<$priority>$syslogMessage")
            $udpClient.Send($bytes, $bytes.Length, $SyslogServer, 514)
            $udpClient.Close()
        }
        
        Write-Host "  $($recentEvents.Count) MAPS events forwarded to SIEM: $SyslogServer" -ForegroundColor Green
        Write-Host "  Log integrity status: $($logIntegrityCheck.IntegrityStatus)" -ForegroundColor Gray
        
        # NIST AU-6 (Audit Review) compliance note
        if ($recentEvents.Count -gt 10) {
            Write-Host "  Note: High audit volume detected - ensure adequate SIEM retention per NIST AU-6" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "  SIEM forwarding failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Check if Defender is running
Write-Host ""
Write-Host "🛡️ Defender Status:" -ForegroundColor Yellow
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus) {
        Write-Host "  Real-time Protection: $($defenderStatus.RealTimeProtectionEnabled)"
        Write-Host "  On-Access Protection: $($defenderStatus.OnAccessProtectionEnabled)"
        Write-Host "  IOAV Protection: $($defenderStatus.IoavProtectionEnabled)"
        Write-Host "  AM Service: $($defenderStatus.AMServiceEnabled)"
        Write-Host "  Antivirus Signature Age: $($defenderStatus.AntivirusSignatureAge) days"
        Write-Host "  Last Quick Scan: $($defenderStatus.QuickScanEndTime)"
    } else {
        Write-Host "  ⚠️ Cannot retrieve Defender status" -ForegroundColor Red
    }
} catch {
    Write-Host "  ⚠️ Defender PowerShell module not available" -ForegroundColor Red
}Write-Host ""
Write-Host "🎯 CIS/NIST Compliance Recommendations:" -ForegroundColor Cyan
if ($spynetReporting -eq 0) {
    Write-Host "  • ❌ CRITICAL: Enable Cloud Protection immediately (CIS Level 1 requirement)" -ForegroundColor Red
    Write-Host "  • Set SpynetReporting=2 and SubmitSamplesConsent=1" -ForegroundColor Yellow
} elseif ($spynetReporting -in @(1,2) -and $submitSamplesConsent -eq 1) {
    Write-Host "  • ✅ Configuration meets CIS Windows benchmarks" -ForegroundColor Green
    Write-Host "  • ✅ Aligns with NIST SP 800-53 SI-3, SI-4, SI-8 controls" -ForegroundColor Green
} elseif ($submitSamplesConsent -eq 2) {
    Write-Host "  • ⚠️ '# MAPS/Cloud Protection Configuration Audit Script
# Run this on individual machines or via Intune/SCCM for quick local checks

param(
    [switch]$ExportCSV,
    [string]$OutputPath = "C:\Temp\MAPS_Audit.csv",
    [switch]$EnforceCIS,
    [switch]$CheckMpPreference,
    [switch]$ForwardToSIEM,
    [string]$SyslogServer
)

Write-Host "🔍 Microsoft Defender MAPS/Cloud Protection Audit" -ForegroundColor Cyan
Write-Host "=" * 60

# Function to get registry value safely
function Get-RegistryValue {
    param($Path, $Name)
    try {
        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    }
    catch {
        return $null
    }
}

# Function to decode configuration
function Get-ConfigDescription {
    param($SpynetReporting, $SubmitSamplesConsent)
    
    $cloudProtection = switch ($SpynetReporting) {
        0 { "❌ Disabled" }
        1 { "✅ Advanced (Legacy Value)" }
        2 { "✅ Advanced" }
        default { "🔍 Unknown ($SpynetReporting)" }
    }
    
    $sampleSubmission = switch ($SubmitSamplesConsent) {
        0 { "⚠️ Always Prompt" }
        1 { "🟢 Safe Samples Auto" }
        2 { "🔒 Never Send" }
        3 { "🚨 Send All Auto" }
        default { "🔍 Unknown ($SubmitSamplesConsent)" }
    }
    
    $recommendation = if ($SpynetReporting -eq 0) {
        "❌ NON-COMPLIANT: Enable Cloud Protection (Microsoft Baseline Requirement)"
    } elseif ($SpynetReporting -in @(1,2) -and $SubmitSamplesConsent -eq 1) {
        "✅ MICROSOFT RECOMMENDED (Safe Samples Auto)"
    } elseif ($SpynetReporting -in @(1,2) -and $SubmitSamplesConsent -eq 3) {
        "✅ MAXIMUM PROTECTION (Send All Auto - Microsoft Default)"
    } elseif ($SpynetReporting -in @(1,2) -and $SubmitSamplesConsent -eq 2) {
        "⚠️ REDUCED PROTECTION (Never Send - Block at First Sight disabled)"
    } elseif ($SpynetReporting -in @(1,2) -and $SubmitSamplesConsent -eq 0) {
        "⚠️ INCONSISTENT PROTECTION (User Prompted)"
    } else {
        "🔍 Review Configuration"
    }
    
    return @{
        CloudProtection = $cloudProtection
        SampleSubmission = $sampleSubmission
        Recommendation = $recommendation
    }
}

# Get computer information
$computerInfo = @{
    ComputerName = $env:COMPUTERNAME
    Domain = $env:USERDOMAIN
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
}

Write-Host "Computer: $($computerInfo.ComputerName)" -ForegroundColor Green
Write-Host "Domain: $($computerInfo.Domain)" -ForegroundColor Green
Write-Host "Scan Time: $($computerInfo.Timestamp)" -ForegroundColor Green
Write-Host ""

# Registry paths
$spynetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
$defenderPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender"

# Get MAPS configuration
Write-Host "📋 MAPS Configuration:" -ForegroundColor Yellow
$spynetReporting = Get-RegistryValue -Path $spynetPath -Name "SpynetReporting"
$submitSamplesConsent = Get-RegistryValue -Path $spynetPath -Name "SubmitSamplesConsent"

Write-Host "  SpynetReporting: $spynetReporting"
Write-Host "  SubmitSamplesConsent: $submitSamplesConsent"

$config = Get-ConfigDescription -SpynetReporting $spynetReporting -SubmitSamplesConsent $submitSamplesConsent

Write-Host ""
Write-Host "🎯 Current Configuration:" -ForegroundColor Yellow
Write-Host "  Cloud Protection: $($config.CloudProtection)"
Write-Host "  Sample Submission: $($config.SampleSubmission)"
Write-Host "  Assessment: $($config.Recommendation)"

# Check Defender Preferences (NIST recommendation for comprehensive monitoring)
if ($CheckMpPreference) {
    Write-Host ""
    Write-Host "🔍 Microsoft Defender Preferences (Get-MpPreference):" -ForegroundColor Yellow
    try {
        $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($mpPref) {
            Write-Host "  MAPSReporting: $($mpPref.MAPSReporting)"
            Write-Host "  SubmitSamplesConsent: $($mpPref.SubmitSamplesConsent)"
            Write-Host "  DisablePrivacyMode: $($mpPref.DisablePrivacyMode)"
            Write-Host "  SignatureDisableUpdateOnStartupWithoutEngine: $($mpPref.SignatureDisableUpdateOnStartupWithoutEngine)"
            
            # Cross-validate with registry
            if ($mpPref.MAPSReporting -ne $spynetReporting -or $mpPref.SubmitSamplesConsent -ne $submitSamplesConsent) {
                Write-Host "  ⚠️ WARNING: MpPreference values differ from registry!" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "  ⚠️ Get-MpPreference failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# CIS Enforcement (if requested)
if ($EnforceCIS) {
    Write-Host ""
    Write-Host "🔧 CIS Enforcement Mode:" -ForegroundColor Cyan
    if ($spynetReporting -ne 2 -or $submitSamplesConsent -ne 1) {
        Write-Host "  Applying CIS-compliant settings..." -ForegroundColor Yellow
        try {
            # Set registry values for CIS compliance
            Set-ItemProperty -Path $spynetPath -Name "SpynetReporting" -Value 2 -Force
            Set-ItemProperty -Path $spynetPath -Name "SubmitSamplesConsent" -Value 1 -Force
            Write-Host "  ✅ Registry updated to CIS-compliant values" -ForegroundColor Green
            
            # Also set via PowerShell if available
            try {
                Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
                Write-Host "  ✅ MpPreference updated to CIS-compliant values" -ForegroundColor Green
            } catch {
                Write-Host "  ⚠️ MpPreference update failed: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  ❌ Enforcement failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "  ✅ Already CIS-compliant, no changes needed" -ForegroundColor Green
    }
}

# Check recent events (if Event Log is accessible)
Write-Host ""
Write-Host "📊 Recent MAPS Activity (last 7 days):" -ForegroundColor Yellow
try {
    $events = @{
        "1116 (Suspicious Detected)" = 0
        "1117 (Sample Submitted)" = 0
        "1118 (Submission Failed)" = 0
        "1121 (ASR Block)" = 0
        "1122 (ASR Audit)" = 0
        "1125 (Network Protection Block)" = 0
        "1126 (Network Protection Audit)" = 0
        "5007 (Policy Change)" = 0
    }
    
    $startTime = (Get-Date).AddDays(-7)
    $logEntries = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$startTime; ID=1116,1117,1118,1121,1122,1125,1126,5007} -ErrorAction SilentlyContinue
    
    foreach ($event in $logEntries) {
        switch ($event.Id) {
            1116 { $events["1116 (Suspicious Detected)"]++ }
            1117 { $events["1117 (Sample Submitted)"]++ }
            1118 { $events["1118 (Submission Failed)"]++ }
            1121 { $events["1121 (ASR Block)"]++ }
            1122 { $events["1122 (ASR Audit)"]++ }
            1125 { $events["1125 (Network Protection Block)"]++ }
            1126 { $events["1126 (Network Protection Audit)"]++ }
            5007 { $events["5007 (Policy Change)"]++ }
        }
    }
    
    foreach ($eventType in $events.Keys) {
        $count = $events[$eventType]
        $icon = if ($count -eq 0) { "✅" } 
               elseif ($eventType -like "*Failed*") { "❌" } 
               elseif ($eventType -like "*Block*") { "🛡️" } 
               elseif ($eventType -like "*Policy Change*") { "🔧" }
               else { "📊" }
        Write-Host "  $icon $eventType : $count events"
    }
    
    # Validate MAPS functionality
    $mapsEvents = $events["1117 (Sample Submitted)"] + $events["1118 (Submission Failed)"]
    if ($mapsEvents -eq 0 -and $spynetReporting -in @(1,2) -and $submitSamplesConsent -in @(1,3)) {
        Write-Host "  ⚠️ No MAPS activity detected - verify configuration is working" -ForegroundColor Yellow
    }
    
    # Check for configuration drift
    if ($events["5007 (Policy Change)"] -gt 0) {
        Write-Host "  🔧 Recent policy changes detected - review for unauthorized modifications" -ForegroundColor Yellow
    }
    
    if (($events.Values | Measure-Object -Sum).Sum -eq 0) {
        Write-Host "  ℹ️ No security events found in the last 7 days"
    }
    
} catch {
    Write-Host "  ⚠️ Cannot access Event Log: $($_.Exception.Message)" -ForegroundColor Red
}
    
    foreach ($eventType in $events.Keys) {
        $count = $events[$eventType]
        $icon = if ($count -eq 0) { "✅" } elseif ($eventType -like "*Failed*" -or $eventType -like "*Disabled*") { "❌" } else { "📊" }
        Write-Host "  $icon $eventType : $count events"
    }
    
    if (($events.Values | Measure-Object -Sum).Sum -eq 0) {
        Write-Host "  ℹ️ No MAPS events found in the last 7 days"
    }
    
} catch {
    Write-Host "  ⚠️ Cannot access Event Log: $($_.Exception.Message)" -ForegroundColor Red
}

# Test MAPS connectivity using official Microsoft tool
Write-Host ""
Write-Host "🌐 MAPS Connectivity Validation:" -ForegroundColor Yellow
try {
    $mpcmdPath = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
    if (Test-Path $mpcmdPath) {
        Write-Host "  Running official MAPS validation..." -ForegroundColor Gray
        $result = & $mpcmdPath -ValidateMapsConnection 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✅ MAPS connection successful!" -ForegroundColor Green
            
            # Parse the output for details
            $connectionLine = $result | Where-Object { $_ -like "*Last Successful MAPS connection*" }
            if ($connectionLine) {
                Write-Host "  $connectionLine" -ForegroundColor Gray
            }
            
            $internetCheck = $result | Where-Object { $_ -like "*fIsConnectedToInternet*" }
            if ($internetCheck -and $internetCheck -like "*true*") {
                Write-Host "  ✅ Internet connectivity confirmed" -ForegroundColor Green
            }
        } else {
            Write-Host "  ❌ MAPS connection failed (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
            Write-Host "  Error details:" -ForegroundColor Red
            $result | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        }
    } else {
        Write-Host "  ⚠️ MpCmdRun.exe not found at expected location" -ForegroundColor Yellow
        
        # Fallback to basic connectivity test
        Write-Host "  Performing basic connectivity test..." -ForegroundColor Gray
        $mapsEndpoints = @("wdcp.microsoft.com", "wd.microsoft.com")
        foreach ($endpoint in $mapsEndpoints) {
            try {
                $testResult = Test-NetConnection -ComputerName $endpoint -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
                $status = if ($testResult) { "✅ Connected" } else { "❌ Failed" }
                Write-Host "    $endpoint : $status"
            } catch {
                Write-Host "    $endpoint : ❌ Error testing" -ForegroundColor Red
            }
        }
    }
} catch {
    Write-Host "  ❌ Connectivity test failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Prepare results for export
$results = [PSCustomObject]@{
    ComputerName = $computerInfo.ComputerName
    Domain = $computerInfo.Domain
    Timestamp = $computerInfo.Timestamp
    OSVersion = $computerInfo.OSVersion
    SpynetReporting = $spynetReporting
    SubmitSamplesConsent = $submitSamplesConsent
    CloudProtection = $config.CloudProtection
    SampleSubmission = $config.SampleSubmission
    Recommendation = $config.Recommendation
    MicrosoftCompliant = ($spynetReporting -in @(1,2) -and $submitSamplesConsent -in @(1,3))
    RealtimeProtection = $defenderStatus.RealTimeProtectionEnabled
    OnAccessProtection = $defenderStatus.OnAccessProtectionEnabled
    SuspiciousDetected_7days = $events["1116 (Suspicious Detected)"]
    SampleSubmitted_7days = $events["1117 (Sample Submitted)"]
    SubmissionFailed_7days = $events["1118 (Submission Failed)"]
    ASRBlocks_7days = $events["1121 (ASR Block)"]
    ASRAudits_7days = $events["1122 (ASR Audit)"]
    NetworkBlocks_7days = $events["1125 (Network Protection Block)"]
    NetworkAudits_7days = $events["1126 (Network Protection Audit)"]
    PolicyChanges_7days = $events["5007 (Policy Change)"]
    NIST_SI3_Compliance = ($spynetReporting -in @(1,2) -and $submitSamplesConsent -in @(1,3))
}

# Export to CSV if requested
if ($ExportCSV) {
    try {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Append
        Write-Host ""
        Write-Host "📁 Results exported to: $OutputPath" -ForegroundColor Green
    } catch {
        Write-Host ""
        Write-Host "❌ Failed to export: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Microsoft Security Baseline Recommendations:" -ForegroundColor Cyan
if ($spynetReporting -eq 0) {
    Write-Host "  • CRITICAL: Enable Cloud Protection immediately (Microsoft Baseline requirement)" -ForegroundColor Red
    Write-Host "  • Set SpynetReporting=2 and SubmitSamplesConsent=1 (Safe Samples)" -ForegroundColor Yellow
} elseif ($spynetReporting -in @(1,2) -and $submitSamplesConsent -eq 1) {
    Write-Host "  • Configuration aligns with Microsoft Security Baseline" -ForegroundColor Green
    Write-Host "  • Block at First Sight enabled for optimal protection" -ForegroundColor Green
    Write-Host "  • Meets NIST SP 800-53 SI-3 (Malicious Code Protection) requirements" -ForegroundColor Green
} elseif ($spynetReporting -in @(1,2) -and $submitSamplesConsent -eq 3) {
    Write-Host "  • Maximum protection enabled (Microsoft default baseline)" -ForegroundColor Green
    Write-Host "  • Consider privacy implications for sensitive environments" -ForegroundColor Yellow
    Write-Host "  • Exceeds NIST SP 800-53 SI-3 requirements" -ForegroundColor Green
} elseif ($submitSamplesConsent -eq 2) {
    Write-Host "  • 'Never Send' disables Block at First Sight (reduced protection)" -ForegroundColor Yellow
    Write-Host "  • Consider Safe Samples Auto (SubmitSamplesConsent=1) for better security" -ForegroundColor Yellow
    Write-Host "  • May not fully meet NIST SP 800-53 SI-3 collaborative defense requirements" -ForegroundColor Yellow
} elseif ($submitSamplesConsent -eq 0) {
    Write-Host "  • User prompts create inconsistent protection" -ForegroundColor Yellow
    Write-Host "  • Microsoft recommends automated sample submission" -ForegroundColor Yellow
} else {
    Write-Host "  • Review current configuration against Microsoft Security Baseline" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Reference Standards:" -ForegroundColor Cyan
Write-Host "  • Microsoft Security Baseline for Windows 11" -ForegroundColor Gray
Write-Host "  • NIST SP 800-53 Rev. 5: SI-3, SI-4, SI-8 controls" -ForegroundColor Gray
Write-Host "  • NIST SP 800-83: Guide to Malware Incident Prevention" -ForegroundColor Gray
Write-Host "  • NIST SP 800-92: Guide to Computer Security Log Management" -ForegroundColor GraydColor Yellow
} elseif ($submitSamplesConsent -eq 0) {
    Write-Host "  • ⚠️ User prompts create inconsistent protection" -ForegroundColor Yellow
    Write-Host "  • CIS recommends automated sample submission" -ForegroundColor Yellow
} elseif ($submitSamplesConsent -eq 3) {
    Write-Host "  • ✅ Maximum protection enabled (exceeds CIS requirements)" -ForegroundColor Green
    Write-Host "  • ⚠️ Consider privacy implications for sensitive environments" -ForegroundColor Yellow
} else {
    Write-Host "  • 🔍 Review current configuration against CIS benchmarks" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "📚 Compliance References:" -ForegroundColor Cyan
Write-Host "  • CIS Microsoft Windows 10/11 Benchmark Level 1 & 2" -ForegroundColor Gray
Write-Host "  • NIST SP 800-53 Rev. 5: SI-3, SI-4, SI-8 controls" -ForegroundColor Gray
Write-Host "  • NIST SP 800-83: Guide to Malware Incident Prevention" -ForegroundColor Gray

Write-Host ""
Write-Host "Audit Complete!" -ForegroundColor Green

# Return results object for further processing
return $results