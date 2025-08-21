### 18. Configuration Changes and Policy Drift Detection (Event 5007)
```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "AntivirusSettings"
| extend ParsedFields = parse_json(AdditionalFields)
| where tostring(ParsedFields.EventOriginalType) == "5007" or toint(ParsedFields.EventId) == 5007
| extend 
    SettingName = tostring(ParsedFields.SettingName),
    OldValue = tostring(ParsedFields.OldValue),
    NewValue = tostring(ParsedFields.NewValue),
    ConfigChange = case(
        SettingName has "SpynetReporting", 
            case(
                OldValue == "2" and NewValue == "0", "🔴 MAPS DISABLED",
                OldValue == "0" and NewValue == "2", "🟢 MAPS ENABLED",
                "MAPS Modified"
            ),
        SettingName has "SubmitSamplesConsent",
            case(
                OldValue == "2" and NewValue != "2", "⚠️ Sample submission enabled",
                OldValue != "2" and NewValue == "2", "🔒 Sample submission disabled",
                OldValue == "1" and NewValue == "3", "📈 Increased to Send All",
                OldValue == "3" and NewValue == "1", "📉 Reduced to Safe Samples",
                "Sample policy modified"
            ),
        "Other Defender Setting"
    )
| project Timestamp, DeviceName, DeviceId, SettingName, OldValue, NewValue, ConfigChange, InitiatingProcessAccountName
| where ConfigChange != "Other Defender Setting"
| sort by Timestamp desc
```# MAPS/Cloud Protection - KQL Hunting Queries for 7000 Endpoints

## 🔍 Overview
This collection provides comprehensive KQL queries to analyze Microsoft Defender MAPS/Cloud Protection activity across your 7000 endpoints. Use these queries in **Microsoft 365 Defender Advanced Hunting** (security.microsoft.com).

---

## 📊 Quick Assessment Queries

### 1. Current MAPS Configuration Status Across All Devices
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has "Windows Defender\\Spynet"
| where RegistryValueName in ("SpynetReporting", "SubmitSamplesConsent")
| summarize 
    arg_max(Timestamp, RegistryValueData) by DeviceId, DeviceName, RegistryValueName
| evaluate pivot(RegistryValueName, any(RegistryValueData))
| extend 
    CloudProtection = case(
        SpynetReporting == "0", "❌ Disabled",
        SpynetReporting in ("1", "2"), "✅ Advanced", 
        "🔍 Unknown"
    ),
    SampleSubmission = case(
        SubmitSamplesConsent == "0", "⚠️ Always Prompt",
        SubmitSamplesConsent == "1", "🟢 Safe Samples Auto",
        SubmitSamplesConsent == "2", "🔒 Never Send",
        SubmitSamplesConsent == "3", "🚨 Send All Auto",
        "🔍 Unknown"
    ),
    MicrosoftCompliance = case(
        SpynetReporting == "0", "❌ Non-compliant",
        SpynetReporting in ("1", "2") and SubmitSamplesConsent == "1", "✅ Microsoft Recommended",
        SpynetReporting in ("1", "2") and SubmitSamplesConsent == "3", "✅ Microsoft Baseline Default",
        SpynetReporting in ("1", "2") and SubmitSamplesConsent == "2", "⚠️ Reduced Protection",
        "🔍 Review Required"
    )
| project DeviceName, DeviceId, CloudProtection, SampleSubmission, SpynetReporting, SubmitSamplesConsent
| sort by DeviceName asc
```

### 2. Configuration Summary Dashboard
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has "Windows Defender\\Spynet"
| where RegistryValueName in ("SpynetReporting", "SubmitSamplesConsent")
| summarize arg_max(Timestamp, RegistryValueData) by DeviceId, RegistryValueName
| evaluate pivot(RegistryValueName, any(RegistryValueData))
| extend 
    ConfigProfile = case(
        SpynetReporting == "0", "🔴 MAPS Disabled (Non-compliant)",
        SpynetReporting in ("1", "2") and SubmitSamplesConsent == "1", "🟢 Safe Samples Auto (Microsoft Recommended)",
        SpynetReporting in ("1", "2") and SubmitSamplesConsent == "3", "🟡 Send All Auto (Maximum Protection)",
        SpynetReporting in ("1", "2") and SubmitSamplesConsent == "2", "🟠 Hash Check Only (Reduced Protection - Non-compliant)",
        SpynetReporting in ("1", "2") and SubmitSamplesConsent == "0", "⚠️ User Prompted (Inconsistent)",
        "🔍 Unknown/Mixed"
    )
| summarize DeviceCount = dcount(DeviceId) by ConfigProfile
| extend Percentage = round(DeviceCount * 100.0 / sum(DeviceCount), 1)
| sort by DeviceCount desc
```

---

## 🕵️ Sample Submission Activity Analysis

### 3. Devices with Recent Sample Submission Activity (Event ID 1117)
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "AntivirusDetection"
| extend ParsedFields = parse_json(AdditionalFields)
| where 
    tostring(ParsedFields.EventOriginalType) == "1117" or 
    toint(ParsedFields.EventId) == 1117 or
    AdditionalFields has "1117"
| summarize 
    SubmissionCount = count(),
    FirstSubmission = min(Timestamp),
    LastSubmission = max(Timestamp),
    SampleFiles = make_set(strcat(tostring(ParsedFields.FileName), " (", tostring(ParsedFields.ThreatName), ")"), 10)
| by DeviceName, DeviceId
| sort by SubmissionCount desc
```

### 4. Failed Sample Submissions (Network/Policy Blocked - Event ID 1118)
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "AntivirusDetection"
| extend ParsedFields = parse_json(AdditionalFields)
| where ParsedFields.EventOriginalType == "1118" or ParsedFields.EventId == 1118
| summarize 
    FailedSubmissions = count(),
    FirstFailure = min(Timestamp),
    LastFailure = max(Timestamp),
    ErrorDetails = make_set(tostring(ParsedFields.ErrorMessage))
| by DeviceName, DeviceId
| sort by FailedSubmissions desc
```

### 5. Cloud Protection Connectivity Issues
```kql
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType in ("AntivirusDetection", "AntivirusError")
| extend ParsedFields = parse_json(AdditionalFields)
| where ParsedFields has "MAPS" or ParsedFields has "cloud" or ParsedFields has "connectivity"
| project Timestamp, DeviceName, ActionType, ParsedFields
| sort by Timestamp desc
```

---

## 📈 Trend and Volume Analysis

### 6. Sample Submission Volume Over Time
```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "AntivirusDetection"
| extend ParsedFields = parse_json(AdditionalFields)
| where ParsedFields.EventOriginalType == "1117" or ParsedFields.EventId == 1117
| summarize SubmissionCount = count() by bin(Timestamp, 1d)
| render timechart 
    with (
        title="Daily Sample Submissions to Microsoft",
        xtitle="Date",
        ytitle="Number of Submissions"
    )
```

### 7. Top File Types Being Submitted
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "AntivirusDetection"
| extend ParsedFields = parse_json(AdditionalFields)
| where ParsedFields.EventOriginalType == "1117" or ParsedFields.EventId == 1117
| extend FileName = tostring(ParsedFields.FileName)
| extend FileExtension = tolower(extract(@"\.([^\.]+)$", 1, FileName))
| where isnotempty(FileExtension)
| summarize 
    SubmissionCount = count(),
    UniqueFiles = dcount(FileName),
    SampleFiles = make_set(FileName, 5)
| by FileExtension
| sort by SubmissionCount desc
| take 20
```

### 8. Devices with Highest MAPS Activity
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "AntivirusDetection"
| extend ParsedFields = parse_json(AdditionalFields)
| where ParsedFields.EventOriginalType in ("1116", "1117", "1118") or ParsedFields.EventId in (1116, 1117, 1118)
| extend EventType = case(
    ParsedFields.EventOriginalType == "1116" or ParsedFields.EventId == 1116, "🔍 Suspicious Detected",
    ParsedFields.EventOriginalType == "1117" or ParsedFields.EventId == 1117, "📤 Sample Submitted", 
    ParsedFields.EventOriginalType == "1118" or ParsedFields.EventId == 1118, "❌ Submission Failed",
    "Other"
)
| summarize 
    TotalEvents = count(),
    SuspiciousDetected = countif(EventType == "🔍 Suspicious Detected"),
    SamplesSubmitted = countif(EventType == "📤 Sample Submitted"),
    SubmissionsFailed = countif(EventType == "❌ Submission Failed")
| by DeviceName, DeviceId
| where TotalEvents > 5
| sort by TotalEvents desc
| take 50
```

---

## 🚨 Security and Compliance Monitoring

### 9. Detect Configuration Changes
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has "Windows Defender\\Spynet"
| where RegistryValueName in ("SpynetReporting", "SubmitSamplesConsent")
| extend 
    ConfigChange = case(
        RegistryValueName == "SpynetReporting", 
            case(
                PreviousRegistryValueData == "2" and RegistryValueData == "0", "🔴 MAPS DISABLED",
                PreviousRegistryValueData == "0" and RegistryValueData == "2", "🟢 MAPS ENABLED",
                "MAPS Modified"
            ),
        RegistryValueName == "SubmitSamplesConsent",
            case(
                PreviousRegistryValueData == "2" and RegistryValueData != "2", "⚠️ Sample submission enabled",
                PreviousRegistryValueData != "2" and RegistryValueData == "2", "🔒 Sample submission disabled",
                "Sample policy modified"
            ),
        "Other"
    )
| project Timestamp, DeviceName, InitiatingProcessAccountName, ConfigChange, RegistryValueName, PreviousRegistryValueData, RegistryValueData
| sort by Timestamp desc
```

### 10. Devices Not Compliant with Microsoft Security Baseline
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has "Windows Defender\\Spynet"
| where RegistryValueName in ("SpynetReporting", "SubmitSamplesConsent")
| summarize arg_max(Timestamp, RegistryValueData) by DeviceId, DeviceName, RegistryValueName
| evaluate pivot(RegistryValueName, any(RegistryValueData))
| where 
    SpynetReporting == "0" or  // Cloud Protection disabled
    (SpynetReporting in ("1", "2") and SubmitSamplesConsent !in ("1", "3"))  // Not following Microsoft recommendations
| extend 
    ComplianceIssue = case(
        SpynetReporting == "0", "🔴 MAPS Completely Disabled (Non-compliant)",
        SubmitSamplesConsent == "2", "🟠 Never Send Samples (Block at First Sight disabled)", 
        SubmitSamplesConsent == "0", "⚠️ User Prompted (Inconsistent Protection)",
        "🔍 Unknown Issue"
    ),
    MicrosoftRecommendation = "Enable Safe Samples Auto (SubmitSamplesConsent=1) per Microsoft Security Baseline"
| project DeviceName, DeviceId, ComplianceIssue, MicrosoftRecommendation, SpynetReporting, SubmitSamplesConsent
| sort by ComplianceIssue, DeviceName
```

---

## 🌐 Network and Bandwidth Analysis

### 11. Sample Submission Volume Analysis (Enhanced with FileSize)
```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "AntivirusDetection"
| extend ParsedFields = parse_json(AdditionalFields)
| where 
    tostring(ParsedFields.EventOriginalType) == "1117" or 
    toint(ParsedFields.EventId) == 1117
| extend 
    FileName = tostring(ParsedFields.FileName),
    FileExtension = tolower(extract(@"\.([^\.]+)$", 1, tostring(ParsedFields.FileName))),
    ActualFileSize = toint(ParsedFields.FileSize), // Use actual size if available
    // Estimate file size based on extension if actual size unavailable
    EstimatedSizeKB = case(
        isnotnull(ActualFileSize) and ActualFileSize > 0, ActualFileSize / 1024,
        FileExtension in ("exe", "dll", "msi"), 1024,  // ~1MB average
        FileExtension in ("scr", "bat", "ps1", "vbs"), 50,  // ~50KB average  
        FileExtension in ("zip", "rar", "7z"), 2048,  // ~2MB average
        FileExtension == "html", 100,  // ~100KB average
        512  // Default ~512KB
    )
| summarize 
    TotalSubmissions = count(),
    EstimatedDataKB = sum(EstimatedSizeKB),
    UniqueDevices = dcount(DeviceId),
    FileTypes = make_set(FileExtension, 10),
    ActualSizeCount = countif(isnotnull(ActualFileSize) and ActualFileSize > 0)
| by bin(Timestamp, 1d)
| extend 
    EstimatedDataMB = round(EstimatedDataKB / 1024.0, 2),
    DataAccuracy = round(ActualSizeCount * 100.0 / TotalSubmissions, 1)
| project Timestamp, TotalSubmissions, UniqueDevices, EstimatedDataMB, DataAccuracy, FileTypes
| sort by Timestamp desc
```

### 12. MAPS Connectivity Health Check
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any ("wdcp.microsoft.com", "wd.microsoft.com", "wdcpalt.microsoft.com")
| summarize 
    TotalConnections = count(),
    SuccessfulConnections = countif(ActionType == "ConnectionSuccess"),
    FailedConnections = countif(ActionType == "ConnectionFailed"),
    UniqueDevices = dcount(DeviceId)
| by bin(Timestamp, 1h), RemoteUrl
| extend SuccessRate = round(SuccessfulConnections * 100.0 / TotalConnections, 1)
| sort by Timestamp desc
```

### 15. MpCmdRun Validation Results Analysis
```kql
// Query to analyze MpCmdRun -ValidateMapsConnection results from process events
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "MpCmdRun.exe"
| where ProcessCommandLine has "ValidateMapsConnection"
| extend 
    ValidationResult = case(
        ProcessCommandLine has "successfully established", "✅ Success",
        ProcessCommandLine has "failed" or ProcessCommandLine has "error", "❌ Failed",
        "🔍 Unknown"
    )
| summarize 
    TotalValidations = count(),
    SuccessfulValidations = countif(ValidationResult == "✅ Success"),
    FailedValidations = countif(ValidationResult == "❌ Failed"),
    LastValidation = max(Timestamp)
| by DeviceName, DeviceId
| extend SuccessRate = round(SuccessfulValidations * 100.0 / TotalValidations, 1)
| where TotalValidations > 0
| sort by SuccessRate asc, TotalValidations desc
```

### 16. Complete MAPS and Defender Protection Events
```kql
// Comprehensive query including MAPS, ASR, and Network Protection events
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("AntivirusDetection", "AsrAuditModeHit", "AsrHit", "NetworkProtectionUserBypass", "SmartScreenBlockedUserOverride")
| extend ParsedFields = parse_json(AdditionalFields)
| extend EventCategory = case(
    tostring(ParsedFields.EventOriginalType) in ("1116", "1117", "1118") or toint(ParsedFields.EventId) in (1116, 1117, 1118), "MAPS",
    tostring(ParsedFields.EventOriginalType) in ("1121", "1122") or toint(ParsedFields.EventId) in (1121, 1122), "ASR",
    tostring(ParsedFields.EventOriginalType) in ("1125", "1126") or toint(ParsedFields.EventId) in (1125, 1126), "Network Protection",
    "Other"
)
| extend EventType = case(
    tostring(ParsedFields.EventOriginalType) == "1116" or toint(ParsedFields.EventId) == 1116, "🔍 Suspicious Detected",
    tostring(ParsedFields.EventOriginalType) == "1117" or toint(ParsedFields.EventId) == 1117, "📤 Sample Submitted",
    tostring(ParsedFields.EventOriginalType) == "1118" or toint(ParsedFields.EventId) == 1118, "❌ Submission Failed",
    tostring(ParsedFields.EventOriginalType) == "1121" or toint(ParsedFields.EventId) == 1121, "🛡️ ASR Block",
    tostring(ParsedFields.EventOriginalType) == "1122" or toint(ParsedFields.EventId) == 1122, "📋 ASR Audit",
    tostring(ParsedFields.EventOriginalType) == "1125" or toint(ParsedFields.EventId) == 1125, "🌐 Network Block",
    tostring(ParsedFields.EventOriginalType) == "1126" or toint(ParsedFields.EventId) == 1126, "📊 Network Audit",
    "Other Event"
)
| summarize 
    TotalEvents = count(),
    MAPSEvents = countif(EventCategory == "MAPS"),
    ASREvents = countif(EventCategory == "ASR"),
    NetworkEvents = countif(EventCategory == "Network Protection"),
    SampleSubmissions = countif(EventType == "📤 Sample Submitted"),
    SubmissionFailures = countif(EventType == "❌ Submission Failed")
| by DeviceName, DeviceId
| where TotalEvents > 0
| sort by TotalEvents desc
| take 100
```

---

## 📋 Executive Summary Query

### 17. Complete MAPS Health Dashboard (30-day overview)
```kql
let ConfigData = DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has "Windows Defender\\Spynet"
| where RegistryValueName in ("SpynetReporting", "SubmitSamplesConsent")
| summarize arg_max(Timestamp, RegistryValueData) by DeviceId, RegistryValueName
| evaluate pivot(RegistryValueName, any(RegistryValueData))
| extend ConfigProfile = case(
    SpynetReporting == "0", "Disabled (Non-compliant)",
    SpynetReporting in ("1", "2") and SubmitSamplesConsent == "1", "Microsoft Recommended",
    SpynetReporting in ("1", "2") and SubmitSamplesConsent == "3", "Maximum Protection",
    SpynetReporting in ("1", "2") and SubmitSamplesConsent == "2", "Reduced Protection (Non-compliant)",
    "Other"
);
let SubmissionData = DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "AntivirusDetection"
| extend ParsedFields = parse_json(AdditionalFields)
| where tostring(ParsedFields.EventOriginalType) == "1117" or toint(ParsedFields.EventId) == 1117
| summarize TotalSubmissions = count() by DeviceId;
let FailureData = DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "AntivirusDetection" 
| extend ParsedFields = parse_json(AdditionalFields)
| where tostring(ParsedFields.EventOriginalType) == "1118" or toint(ParsedFields.EventId) == 1118
| summarize TotalFailures = count() by DeviceId;
ConfigData
| join kind=leftouter (SubmissionData) on DeviceId
| join kind=leftouter (FailureData) on DeviceId
| summarize 
    DeviceCount = count(),
    DevicesWithSubmissions = countif(TotalSubmissions > 0),
    DevicesWithFailures = countif(TotalFailures > 0),
    TotalSubmissions = sum(TotalSubmissions),
    TotalFailures = sum(TotalFailures)
| by ConfigProfile
| extend 
    SubmissionRate = round(DevicesWithSubmissions * 100.0 / DeviceCount, 1),
    FailureRate = round(DevicesWithFailures * 100.0 / DeviceCount, 1)
| sort by DeviceCount desc
```
| summarize TotalSubmissions = count() by DeviceId;
let FailureData = DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "AntivirusDetection" 
| extend ParsedFields = parse_json(AdditionalFields)
| where tostring(ParsedFields.EventOriginalType) == "1118" or toint(ParsedFields.EventId) == 1118
| summarize TotalFailures = count() by DeviceId;
ConfigData
| join kind=leftouter (SubmissionData) on DeviceId
| join kind=leftouter (FailureData) on DeviceId
| summarize 
    DeviceCount = count(),
    DevicesWithSubmissions = countif(TotalSubmissions > 0),
    DevicesWithFailures = countif(TotalFailures > 0),
    TotalSubmissions = sum(TotalSubmissions),
    TotalFailures = sum(TotalFailures)
| by ConfigProfile
| extend 
    SubmissionRate = round(DevicesWithSubmissions * 100.0 / DeviceCount, 1),
    FailureRate = round(DevicesWithFailures * 100.0 / DeviceCount, 1)
| sort by DeviceCount desc
```

---

## 🔧 Usage Instructions

### Running These Queries:
1. Go to **security.microsoft.com**
2. Navigate to **Hunting > Advanced hunting**
3. Copy and paste any query into the query editor
4. Adjust the time range (`ago(7d)`, `ago(30d)`) as needed
5. Click **Run query**

### Time Range Recommendations:
- **Quick checks**: `ago(24h)` or `ago(7d)`
- **Trend analysis**: `ago(30d)`
- **Historical review**: `ago(90d)` (if data retention allows)

### Performance Tips for 7000+ Endpoints:
- Start with shorter time ranges and expand gradually
- Use `take 100` or `take 1000` for initial exploration
- Add specific device filters if analyzing subsets
- Run during off-peak hours for large queries

### Export Results:
- Use the **Export** button to save results as CSV
- Create scheduled queries for regular monitoring
- Set up custom detection rules for critical configuration changes

---

## 🎯 Key Metrics to Monitor:

1. **Configuration Compliance**: % of devices using "Safe Samples Auto" (Microsoft Recommended)
2. **Submission Volume**: Daily submissions per 1000 devices
3. **Failure Rate**: % of devices with connectivity issues (Event 1118)
4. **Configuration Drift**: Unauthorized changes to MAPS settings
5. **Bandwidth Impact**: Estimated data usage from submissions
6. **Block at First Sight Effectiveness**: Ratio of devices with full protection vs reduced protection

Use Query #17 (Executive Summary) for regular reporting to management!

## 💡 Pro Tips for MpCmdRun Integration:

### Automated Validation via Intune:
```powershell
# Deploy this via Intune Remediation Scripts
$validation = & "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -ValidateMapsConnection 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Output "MAPS connectivity verified"
    exit 0
} else {
    Write-Output "MAPS connectivity failed: $validation"
    exit 1
}
```

### SCCM Compliance Baseline:
Create a configuration item that runs MpCmdRun.exe -ValidateMapsConnection and reports non-compliant devices with connectivity issues.

### Group Policy Startup Script:
Deploy MpCmdRun validation as a computer startup script to catch network/firewall issues early.

### NIST SP 800-92 Log Management Integration:
```powershell
# Forward MAPS events to SIEM
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1116,1117,1118} | 
ForEach-Object {
    $SyslogMessage = @{
        Timestamp = $_.TimeCreated
        Computer = $_.MachineName
        EventId = $_.Id
        Message = $_.Message
    } | ConvertTo-Json
    # Send to SIEM endpoint
}
```