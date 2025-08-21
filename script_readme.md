# Azure Orphaned Role Assignment Cleanup

PowerShell script to detect and remove orphaned role assignments across Azure Management Groups, Subscriptions, and Resource Groups.

## What are Orphaned Role Assignments?

Orphaned role assignments occur when Azure AD principals (users, groups, service principals) are deleted but their role assignments remain in Azure RBAC. These assignments appear as "Identity not found" in the Azure portal and represent potential security risks.

## Prerequisites

- Azure PowerShell modules: `Az.Accounts` (v2.0.0+) and `Az.Resources` (v5.1.0+)
- Azure account with appropriate permissions:
  - **Reader** access on scopes to scan
  - **User Access Administrator** or **Owner** to delete assignments
  - **Management Group Reader** for Management Group scanning

## Installation

```powershell
Install-Module Az.Accounts, Az.Resources -Force -AllowClobber
```

## Usage

### 1. Connect to Azure
```powershell
Connect-AzAccount -TenantId "your-tenant-id"
```

### 2. Analysis (Dry Run)
```powershell
# Scan current subscription
.\Phase1-WithManagementGroups.ps1 -DetailedReport

# Scan all accessible subscriptions and Management Groups
.\Phase1-WithManagementGroups.ps1 -TenantWide -DetailedReport

# Scan specific subscription
.\Phase1-WithManagementGroups.ps1 -SubscriptionId "your-sub-id" -DetailedReport
```

### 3. Cleanup
```powershell
# Safe cleanup (excludes Managed Identities)
.\Phase1-WithManagementGroups.ps1 -TenantWide -Delete -ExcludeTypes @("MSI")

# Full cleanup (includes all types)
.\Phase1-WithManagementGroups.ps1 -TenantWide -Delete

# Skip confirmation prompts
.\Phase1-WithManagementGroups.ps1 -TenantWide -Delete -Force
```

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Delete` | Enable deletion mode | `$false` |
| `-TenantWide` | Scan all accessible subscriptions | `$false` |
| `-SubscriptionId` | Target specific subscription | Current context |
| `-ExcludeTypes` | Skip principal types | `@()` |
| `-DetailedReport` | Show detailed assignment list | `$false` |
| `-Force` | Skip confirmation prompts | `$false` |
| `-IncludeManagementGroups` | Include Management Group scanning | `$true` |

## Detection Methods

1. **ObjectType=Unknown**: Assignments marked as "Unknown" by Azure
2. **PrincipalVerification**: Cross-reference with Azure AD using `Get-AzADUser/Group/ServicePrincipal`

## Security Considerations

- **High-risk roles**: Owner, Contributor, User Access Administrator assignments are flagged as critical
- **Management Group inheritance**: Assignments at MG level affect all child subscriptions
- **Backup recommendation**: Document current assignments before cleanup
- **Staged approach**: Start with `-ExcludeTypes @("MSI")` to avoid Managed Identity issues

## Example Output

```
📊 COMPREHENSIVE SCAN RESULTS:
==============================
  📋 Scopes scanned: 219
  🔍 Total assignments: 1,247
  ❓ Unknown type: 15
  ✅ Verified existing: 1,220
  🗑️ Verified orphaned: 12
  🚨 TOTAL ORPHANED: 27

⚠️  CRITICAL: 22 ORPHANED PRIVILEGED ASSIGNMENTS!
📍 By Scope Type:
  🏢 Management Group: 1
  📊 Subscription: 2
  📁 Resource Group: 24
```

## Performance

- **Small environment**: 2-5 minutes
- **Large enterprise**: 20-45 minutes (16 subs, 198 RGs, 5 MGs)
- **Optimization**: Script includes progress indicators and scope filtering

## Troubleshooting

### Authentication Issues
```powershell
# Clear context and reconnect
Clear-AzContext -Force
Connect-AzAccount -TenantId "your-tenant-id"
```

### Permission Errors
- Ensure User Access Administrator role for deletion
- Management Group permissions required for MG scanning

### Module Version Issues
```powershell
Update-Module Az.Accounts, Az.Resources
```

## Alternative Approaches

For large environments, consider a hybrid approach:
1. Use Azure Resource Graph to identify candidate principals
2. Run focused PowerShell verification on suspicious assignments

## Safety Features

- **Dry run by default**: Requires explicit `-Delete` flag
- **Confirmation prompts**: Must type 'DELETE' to confirm
- **Exclusion lists**: Skip specific principal types
- **Detailed logging**: Shows exactly what will be deleted
- **Error handling**: Continues processing if individual assignments fail

## Limitations

- Cannot detect all orphaned assignments through Azure Resource Graph alone
- Requires elevated permissions for comprehensive scanning
- Management Group scanning requires additional permissions
- Large environments may require extended execution time