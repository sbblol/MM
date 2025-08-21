# Microsoft MAPS / Cloud-delivered Protection - Complete Control Guide

## Overview
Microsoft Advanced Protection Service (MAPS), now called **Cloud-delivered Protection**, is part of Microsoft Defender Antivirus. It enables automatic submission of suspicious files to Microsoft for cloud analysis and improves real-time threat detection capabilities.

## 🎯 Recommended Configuration

**For most enterprise environments, we recommend "Safe Samples Auto" mode per Microsoft Security Baselines:**

```
SpynetReporting = 2 (Advanced membership)
SubmitSamplesConsent = 1 (Send Safe Samples Automatically)
```

### Why This Aligns with Microsoft's Official Guidance:

**✅ Microsoft Security Baseline Compliance:**
- **Microsoft's current baseline default** is "Send all samples" but "Safe Samples" provides strong protection with reduced privacy exposure
- **Block at First Sight** requires sample submission - "Never Send" significantly reduces protection effectiveness
- Supports **full cloud-delivered protection** capabilities including behavioral analysis

**✅ Security Framework Alignment:**
- Aligns with **security best practices** for threat intelligence integration
- Supports **NIST SP 800-53 Rev. 5 SI-3** (Malicious Code Protection) requirements for external threat intelligence
- Compatible with **NIST SP 800-53 Rev. 5 SI-4** (System Monitoring) and **SI-8** (Spam Protection) collaborative defense mechanisms

**✅ Enhanced Security:**
- **Full Block at First Sight** functionality (requires metadata submission)
- **Advanced behavioral analysis** with cloud context
- **Real-time threat intelligence** from Microsoft's global sensor network
- **Zero-day protection** through cloud-based analysis

**⚠️ Important Privacy Notes:**
- "Safe Samples" submits **executables, scripts, and certain archives** (.exe, .dll, .scr, .bat, .ps1, .vbs, .zip)
- **Office documents with macros** are NOT included in "Safe Samples" - only submitted with "Send All Samples"
- User consent required for any file potentially containing personal data

### Alternative Configurations by Environment:

| Environment Type | CIS/NIST Recommended | Alternative for High Privacy | Rationale |
|## 📋 Executive Summary & Key Changes

### Updates Based on Microsoft Security Baseline and Technical Review:

**✅ Primary Recommendation Aligned:**
- **Recommendation**: Safe Samples Auto per Microsoft Security Baseline
- **Registry Values**: SpynetReporting=2, SubmitSamplesConsent=1
- **Rationale**: Aligns with Microsoft's official guidance and maintains Block at First Sight

**🔄 Security Standards Alignment:**
- **Microsoft Security Baseline**: Current default is "Send All Samples" but "Safe Samples" provides strong protection with reduced privacy exposure
- **NIST SP 800-53**: SI-3, SI-4, SI-8 controls support external threat intelligence integration
- **Block at First Sight**: Requires sample submission - "Never Send" significantly reduces protection

**⚠️ Key Technical Corrections:**
- **Event ID 1121**: Corrected to ASR (Attack Surface Reduction) block, not cloud disabled
- **Service Tag**: Updated from deprecated "WindowsDefenderATP" to "MicrosoftDefenderForEndpoint"
- **Safe Samples Definition**: Clarified that Office macros are NOT included in safe samples
- **FQDN List**: Updated with complete regional blob storage endpoints

**🎯 Privacy and Protection Balance:**
- ✅ **Microsoft Recommended**: Safe Samples Auto (executables only, no documents)
- ⚠️ **Reduced Protection**: Never Send (disables Block at First Sight)
- ❌ **Non-Compliant**: Cloud Protection Disabled

------------------|---------------------|------------------------------|-----------|
| **Standard Enterprise** | Safe Samples Auto | Hash Check Only | CIS Level 1/2 compliance vs. data sovereignty |
| **Financial Services** | Safe Samples Auto | Never Send (with justification) | Regulatory balance with security |
| **Healthcare** | Safe Samples Auto | Hash Check Only | HIPAA compliance + threat protection |
| **Defense/Government** | Safe Samples Auto | Fully Disabled | Classification requirements |
| **Small Business** | Safe Samples Auto | Safe Samples Auto | CIS essentials compliance |
| **Home Users** | Send All Samples | Safe Samples Auto | Maximum protection |
| **Air-Gapped** | N/A | Fully Disabled | No external connectivity |

**⚠️ Security Trade-offs:**
- **Hash Check Only**: Reduces Block at First Sight effectiveness (~20% detection loss)
- **Never Send**: No metadata submission limits behavioral analysis capabilities  
- **Fully Disabled**: Significant reduction in zero-day protection (up to 40% detection loss)

---

## Control Options Matrix

| Configuration | Cloud Protection | Sample Submission | Registry Settings | Intune Policy | Local Behavior | Cloud Behavior | Firewall Required | Event Viewer IDs | Security Posture |
|---------------|-----------------|------------------|------------------|---------------|----------------|----------------|-------------------|------------------|------------------|
| **Fully Disabled** | Off | N/A | `SpynetReporting=0`<br>`SubmitSamplesConsent=2` | AllowCloudProtection = **0** | Files quarantined locally only | No cloud analysis | **Not Required** | 1006, 1007 | ❌ **Non-compliant** |
| **Hash Check Only** | On | Never Send | `SpynetReporting=2`<br>`SubmitSamplesConsent=2` | AllowCloudProtection = **1**<br>SubmitSamplesConsent = **2** | Hash reputation checked, files stay local | Reputation only, **BAFS disabled** | **Required** | 1116, 1118, 1006, 1007 | ⚠️ **Reduced Protection** |
| **Safe Samples Auto** | On | Safe Samples | `SpynetReporting=2`<br>`SubmitSamplesConsent=1` | AllowCloudProtection = **1**<br>SubmitSamplesConsent = **1** | Executables auto-submitted, docs protected | Full BAFS + behavioral analysis | **Required** | 1116, 1117, 1006, 1007 | ✅ **Microsoft Recommended** |
| **User Prompted** | On | Prompt | `SpynetReporting=2`<br>`SubmitSamplesConsent=0` | AllowCloudProtection = **1**<br>SubmitSamplesConsent = **0** | User asked before submission | Analysis if user approves | **Required** | 1116, 1117, 1006, 1007 | ⚠️ **Inconsistent protection** |
| **Full Auto-Submit** | On | Always | `SpynetReporting=2`<br>`SubmitSamplesConsent=3` | AllowCloudProtection = **1**<br>SubmitSamplesConsent = **3** | All suspicious files auto-submitted | Complete cloud analysis | **Required** | 1116, 1117, 1006, 1007 | ✅ **Maximum protection** |

---

## Registry Configuration

### Base Path
```
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet
```

### Registry Keys
| Key | Values | Description |
|-----|--------|-------------|
| `SpynetReporting` | `0` = Disabled<br>`1` = Advanced membership (treated as 2 in modern Windows)<br>`2` = Advanced membership | Controls cloud protection level |
| `SubmitSamplesConsent` | `0` = Always Prompt<br>`1` = Send Safe Samples Automatically<br>`2` = Never Send<br>`3` = Send All Samples Automatically | Controls sample submission behavior |

**Important Note**: In modern Windows versions, both values 1 and 2 for `SpynetReporting` result in Advanced membership. The "Basic" tier is deprecated.

### PowerShell Commands
```powershell
# Disable MAPS completely
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2

# Enable with hash checking only (no file submission)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2

# Enable with user prompts
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 0
```

---

## Intune Policy Configuration

### Navigation Path
```
Microsoft Intune admin center → Endpoint security → Antivirus → Create Policy
Platform: Windows 10 and later
Profile: Microsoft Defender Antivirus
```

### Key Settings
| Setting | Options | Impact |
|---------|---------|---------|
| **Allow Cloud Protection** | Enabled (value: 1) / Disabled (value: 0) | Master switch for MAPS functionality |
| **Submit samples consent** | Always Prompt (0)<br>Send Safe Samples Automatically (1)<br>Never Send (2)<br>Send All Samples Automatically (3) | Controls what gets submitted to Microsoft |

**Intune Policy Path**: ./Device/Vendor/MSFT/Policy/Config/Defender/AllowCloudProtection and ./Device/Vendor/MSFT/Policy/Config/Defender/SubmitSamplesConsent

### Policy Assignment
- Target device groups or users
- Set as **Required** for enforcement
- Monitor compliance through Intune reports

---

## Firewall Requirements

### When Firewall Rules Are Required
- **Required**: When Cloud Protection is **Enabled** (any sample submission setting)
- **Not Required**: When Cloud Protection is **Disabled**

### Recommended Approach - Service Tags
```
Service Tag: MicrosoftDefenderForEndpoint
Direction: Outbound
Protocol: HTTPS (443)
```

**Note**: The previous service tag "WindowsDefenderATP" is deprecated. Use "MicrosoftDefenderForEndpoint" which includes MAPS and sample repositories.

### Updated FQDN List
Based on Microsoft's current documentation, these are the required FQDNs:

**Microsoft Defender Antivirus cloud-delivered protection service (MAPS):**
```
*.wdcp.microsoft.com
*.wdcpalt.microsoft.com
*.wd.microsoft.com
```

**Microsoft Update Service & Windows Update:**
```
*.update.microsoft.com
*.delivery.mp.microsoft.com
*.windowsupdate.com
ctldl.windowsupdate.com
```

**Sample submission storage - Recommended Approach:**
For most environments, use the wildcard pattern for simplified configuration:
```
*.blob.core.windows.net
```

For environments requiring granular control or specific compliance requirements, use regional endpoints:
```
ussus1eastprod.blob.core.windows.net
ussus2eastprod.blob.core.windows.net
ussus3eastprod.blob.core.windows.net
ussus4eastprod.blob.core.windows.net
wsus1eastprod.blob.core.windows.net
wsus2eastprod.blob.core.windows.net
ussus1westprod.blob.core.windows.net
ussus2westprod.blob.core.windows.net
ussus3westprod.blob.core.windows.net
ussus4westprod.blob.core.windows.net
wsus1westprod.blob.core.windows.net
wsus2westprod.blob.core.windows.net
usseu1northprod.blob.core.windows.net
wseu1northprod.blob.core.windows.net
usseu1westprod.blob.core.windows.net
wseu1westprod.blob.core.windows.net
ussuk1southprod.blob.core.windows.net
wsuk1southprod.blob.core.windows.net
ussuk1westprod.blob.core.windows.net
wsuk1westprod.blob.core.windows.net
```

**Certificate Revocation List (CRL):**
```
http://www.microsoft.com/pkiops/crl/
http://www.microsoft.com/pkiops/certs
http://crl.microsoft.com/pki/crl/products
http://www.microsoft.com/pki/certs
```

**Universal GDPR Client (Diagnostic data):**
```
vortex-win.data.microsoft.com
settings-win.data.microsoft.com
```

### Validation Tool - MpCmdRun.exe (Essential for Verification)

**Primary Method for Testing MAPS Connectivity:**
```cmd
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -ValidateMapsConnection
```

**Successful Output Example:**
```
---------------------------- MpCmdRunShowNetworkInfo() ------------------------------
MpIsConnectedToInternet(): hr = 0, fIsConnectedToInternet: true
MpIsPaidNetwork(): hr = 0x1 (0 - S_OK, paid; 1 - S_FALSE, not paid; other - failure)
-------------------------------------------------------------------------------------
Last Successful MAPS connection: [8/20/2025 6:36:34 PM]
ValidateMapsConnection successfully established a connection to MAPS
```

**Requirements:**
- Windows 10 version 1703 or higher
- Must run as Administrator
- Real command for immediate validation vs theoretical firewall rules

**Common Error Codes & Solutions:**
| Error Code | Description | Solution |
|------------|-------------|----------|
| `hr=0x80070006` | Network connectivity issues | Check firewall rules, proxy settings |
| `hr=0x80072F8F` | SSL/TLS connection problems | Verify certificate chain, CRL access |
| `hr=0x80072EFE` | Connection timeout | Check network latency, firewall timeouts |
| `hr=0x80072EE7` | Name resolution failure | Verify DNS resolution for MAPS FQDNs |

**Advanced Troubleshooting:**
```powershell
# Test individual MAPS endpoints
Test-NetConnection wdcp.microsoft.com -Port 443
Test-NetConnection wd.microsoft.com -Port 443

# Check last MAPS connection timestamp
Get-MpComputerStatus | Select-Object -Property *MAPS*, *Cloud*
```

**Solutions for Connection Issues:**
1. **Configure system-wide WinHttp proxy** (preferred solution)
2. **Disable CRL checking for SPYNET only**: 
   ```
   HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet
   SSLOptions (DWORD) = 2
   ```
3. **Group Policy CRL alternative**: Disable "Automatically update certificates in Microsoft Root Certificate Program"

---

## Event Monitoring

### Event Viewer Path
```
Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational
```

### Key Event IDs
| Event ID | Description | When It Occurs |
|----------|-------------|----------------|
| **1006** | Malware detection | When threat is detected |
| **1007** | Action taken on malware | File quarantined/cleaned/blocked |
| **1116** | Suspicious file detected | File identified for potential submission |
| **1117** | File submitted to MAPS | Sample sent to Microsoft cloud |
| **1118** | Submission failed | Network/policy blocked submission |
| **1121** | Attack Surface Reduction (ASR) block | ASR rule blocked activity |
| **1122** | Attack Surface Reduction (ASR) audit | ASR rule would have blocked (audit mode) |
| **1125** | Network Protection block | Dangerous connection blocked |
| **1126** | Network Protection audit | Dangerous connection detected (audit mode) |
| **5007** | Policy change applied | Defender configuration modified |

**Note**: Events 1121/1122 are ASR-related, and 1125/1126 are Network Protection events, not MAPS cloud protection events.

### PowerShell Event Monitoring
```powershell
# Monitor MAPS-related events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1116,1117,1118,1121} | Select TimeCreated, Id, LevelDisplayName, Message

# Check current Defender status
Get-MpComputerStatus | Select AMServiceEnabled, AntivirusEnabled, IoavProtectionEnabled, OnAccessProtectionEnabled
```

---

## Troubleshooting Guide

### Common Issues

#### 1. Firewall Blocking (Event ID 1118)
**Symptoms**: Event 1118 appears frequently
**Solution**: 
- Verify firewall rules allow **MicrosoftDefenderForEndpoint** service tag
- Check proxy/corporate firewall settings
- Test connectivity: `Test-NetConnection wdcp.microsoft.com -Port 443`

#### 2. Policy Not Applying
**Symptoms**: Registry values don't match Intune policy
**Solution**:
- Force policy sync: `Invoke-MdmSync` (Windows 10/11)
- Check Intune device compliance reports
- Verify device is properly enrolled and targeted

#### 3. Excessive Submissions
**Symptoms**: High network usage, many 1117 events
**Solution**:
- Change to "Send Safe Samples" or "Never Send"
- Review file types being submitted
- Consider local analysis tools

### Verification Commands
```powershell
# Check current MAPS configuration
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"

# View Defender preferences
Get-MpPreference | Select MAPSReporting, SubmitSamplesConsent

# Test cloud connectivity
Get-MpComputerStatus | Select AMServiceEnabled, OnAccessProtectionEnabled
```

---

## Security Considerations

## Security Considerations & Data Privacy

### Data Flow Analysis
| Mode | Hash Sent | Files Sent | Metadata Sent | Block at First Sight | Security Posture |
|------|-----------|------------|---------------|---------------------|------------------|
| **Disabled** | ❌ | ❌ | ❌ | ❌ Disabled | **High Risk** (No cloud protection) |
| **Hash Only** | ✅ | ❌ | ✅ (hashed) | ❌ Disabled | **Medium Risk** (Reduced protection) |
| **Safe Samples** | ✅ | ✅ (executables only) | ✅ | ✅ Enabled | **Low Risk** (Microsoft Recommended) |
| **All Samples** | ✅ | ✅ (all suspicious) | ✅ | ✅ Enabled | **Very Low Risk** (Maximum protection) |

### NIST SP 800-53 Rev. 5 Control Mapping

**SI-3 (Malicious Code Protection):**
- **SI-3(2) Automatic Updates**: Requires cloud-delivered protection for real-time updates
- **SI-3(4) Updates from Centralized Source**: MAPS provides centralized threat intelligence
- **Safe Samples or higher** required for full compliance

**SI-4 (System Monitoring):**
- **SI-4(4) Inbound and Outbound Communications Traffic**: Network Protection events (1125/1126)
- **SI-4(5) System-Generated Alerts**: MAPS submission events provide alert correlation

**SI-8 (Spam Protection):**
- **SI-8(2) Automatic Updates**: Cloud protection enables automatic spam definition updates

**AU-2 (Audit Events) and AU-6 (Audit Review):**
- **Event logging required**: 1116, 1117, 1118 for MAPS activity
- **SIEM integration recommended**: Forward logs per NIST SP 800-92

### NIST SP 800-83 Compliance Requirements

**Malware Incident Prevention:**
- **Collaborative Defense**: Sample submission enables community protection
- **Real-time Protection**: Block at First Sight prevents malware execution
- **Incident Response**: Event logs support forensic analysis

**Log Management Requirements:**
- **Retention**: Maintain MAPS event logs per organizational policy
- **Integrity**: Protect audit logs from unauthorized modification
- **Forwarding**: Send events to centralized SIEM for analysis

### Sensitive Data Protection
**Memory dumps are NOT automatically sent via MAPS**. These require separate MDE configuration and explicit admin consent.

Files containing potential PII (documents, spreadsheets) always prompt user before submission, even in "All Samples" mode.

Microsoft honors geographical and data retention choices from your MDE onboarding settings.

### Compliance Certifications
Microsoft Defender for Endpoint maintains multiple compliance certifications including ISO 27001, SOC 2, and regional data protection standards.

---

## Advanced Configuration

### Group Policy Alternative
If not using Intune, configure via Group Policy:
```
Computer Configuration → Administrative Templates → Windows Components → 
Microsoft Defender Antivirus → MAPS
```

### PowerShell DSC Configuration
```powershell
Configuration DefenderMAPS {
    Registry SpynetReporting {
        Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
        ValueName = "SpynetReporting"
        ValueData = "2"
        ValueType = "Dword"
    }
    
    Registry SubmitSamplesConsent {
        Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
        ValueName = "SubmitSamplesConsent"
        ValueData = "1"
        ValueType = "Dword"
    }
}
```

---

## Quick Reference Commands

```powershell
# Get current status
Get-MpComputerStatus | fl *MAPS*, *Submit*

# View recent detections
Get-MpThreatDetection | Sort InitialDetectionTime -Descending

# Check policy source
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ErrorAction SilentlyContinue

# Force policy refresh (Intune)
Invoke-MdmSync

# View quarantined items
Get-MpThreat
```