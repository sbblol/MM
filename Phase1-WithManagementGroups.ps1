# Phase 1: Enhanced Orphaned Role Assignment Cleanup - Including Management Groups
# This version properly scans Management Groups and shows full scope details

param(
    [switch]$Delete = $false,
    [string]$SubscriptionId,
    [switch]$TenantWide = $false,
    [string[]]$ExcludeTypes = @(),
    [switch]$DetailedReport = $false,
    [switch]$Force = $false,
    [switch]$IncludeManagementGroups = $true  # New parameter to include MG scanning
)

# Module check
Write-Host "🔧 Checking Azure PowerShell modules..." -ForegroundColor Yellow
$requiredModules = @('Az.Accounts', 'Az.Resources')

foreach ($module in $requiredModules) {
    $installed = Get-Module $module -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $installed) {
        Write-Error "❌ Module $module not installed. Run: Install-Module $module -Force"
        exit 1
    }
    Write-Host "✅ $module version $($installed.Version) OK" -ForegroundColor Green
}

function Verify-AzureConnection {
    Write-Host "🔍 Verifying Azure connection..." -ForegroundColor Yellow
    
    try {
        $context = Get-AzContext -ErrorAction Stop
        
        if (-not $context -or -not $context.Account) {
            Write-Host "❌ No Azure connection found!" -ForegroundColor Red
            Write-Host "`n🔧 Please connect manually first:" -ForegroundColor Yellow
            Write-Host "Connect-AzAccount -TenantId '3d627bf1-4bad-4158-ad29-0a5ec75268aa'" -ForegroundColor Cyan
            return $false
        }
        
        Write-Host "✅ Connected as: $($context.Account.Id)" -ForegroundColor Green
        Write-Host "📊 Subscription: $($context.Subscription.Name)" -ForegroundColor Cyan
        Write-Host "🏢 Tenant: $($context.Tenant.Id)" -ForegroundColor Cyan
        
        return $true
    }
    catch {
        Write-Host "❌ No valid Azure context: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-ManagementGroupScopes {
    Write-Host "🏢 Scanning Management Groups..." -ForegroundColor Yellow
    
    $mgScopes = @()
    
    try {
        # Get all management groups
        $managementGroups = Get-AzManagementGroup -ErrorAction Stop
        
        if ($managementGroups.Count -gt 0) {
            Write-Host "📊 Found $($managementGroups.Count) Management Groups" -ForegroundColor Cyan
            
            foreach ($mg in $managementGroups) {
                try {
                    $mgScope = "/providers/Microsoft.Management/managementGroups/$($mg.Name)"
                    $mgScopes += $mgScope
                    Write-Host "  🏢 Added MG: $($mg.DisplayName) ($($mg.Name))" -ForegroundColor Gray
                }
                catch {
                    Write-Warning "Cannot access Management Group $($mg.Name): $($_.Exception.Message)"
                }
            }
        } else {
            Write-Host "ℹ️ No Management Groups found or accessible" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Cannot access Management Groups: $($_.Exception.Message)"
        Write-Host "This is normal if you don't have MG permissions" -ForegroundColor Gray
    }
    
    return $mgScopes
}

function Get-AllScopes {
    param(
        [string]$SubscriptionId,
        [switch]$TenantWide,
        [switch]$IncludeManagementGroups
    )
    
    Write-Host "`n🔍 Building scope list..." -ForegroundColor Green
    $allScopes = @()
    
    # 1. Management Groups (if enabled and tenant-wide)
    if ($IncludeManagementGroups -and $TenantWide) {
        $mgScopes = Get-ManagementGroupScopes
        $allScopes += $mgScopes
    }
    
    # 2. Subscriptions and Resource Groups
    try {
        if ($TenantWide) {
            Write-Host "🌍 Adding all accessible subscriptions..." -ForegroundColor Yellow
            
            $subscriptions = Get-AzSubscription -ErrorAction Stop
            Write-Host "📊 Found $($subscriptions.Count) accessible subscriptions" -ForegroundColor Cyan
            
            foreach ($sub in $subscriptions) {
                try {
                    Write-Host "  📋 Processing: $($sub.Name)" -ForegroundColor Gray
                    Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
                    $allScopes += "/subscriptions/$($sub.Id)"
                    
                    # Add resource groups
                    $rgs = Get-AzResourceGroup -ErrorAction SilentlyContinue
                    if ($rgs) {
                        $allScopes += $rgs | ForEach-Object { $_.ResourceId }
                        Write-Host "    Added $($rgs.Count) resource groups" -ForegroundColor DarkGray
                    }
                }
                catch {
                    Write-Warning "Cannot process subscription $($sub.Name): $($_.Exception.Message)"
                }
            }
        }
        elseif ($SubscriptionId) {
            Write-Host "🎯 Single subscription mode: $SubscriptionId" -ForegroundColor Yellow
            Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
            $allScopes += "/subscriptions/$SubscriptionId"
            
            $resourceGroups = Get-AzResourceGroup -ErrorAction Stop
            $allScopes += $resourceGroups | ForEach-Object { $_.ResourceId }
        }
        else {
            # Current subscription
            $context = Get-AzContext -ErrorAction Stop
            Write-Host "📋 Current subscription: $($context.Subscription.Name)" -ForegroundColor Yellow
            $allScopes += "/subscriptions/$($context.Subscription.Id)"
            
            $resourceGroups = Get-AzResourceGroup -ErrorAction Stop
            $allScopes += $resourceGroups | ForEach-Object { $_.ResourceId }
        }
    }
    catch {
        Write-Error "Failed to build subscription scopes: $($_.Exception.Message)"
    }
    
    Write-Host "📊 Total scopes to scan: $($allScopes.Count)" -ForegroundColor Cyan
    
    # Group scopes by type for better visibility
    $scopesByType = @{
        ManagementGroups = ($allScopes | Where-Object { $_ -like "*/managementGroups/*" }).Count
        Subscriptions = ($allScopes | Where-Object { $_ -like "/subscriptions/*" -and $_ -notlike "*/resourceGroups/*" }).Count
        ResourceGroups = ($allScopes | Where-Object { $_ -like "*/resourceGroups/*" }).Count
    }
    
    Write-Host "  🏢 Management Groups: $($scopesByType.ManagementGroups)" -ForegroundColor White
    Write-Host "  📊 Subscriptions: $($scopesByType.Subscriptions)" -ForegroundColor White
    Write-Host "  📁 Resource Groups: $($scopesByType.ResourceGroups)" -ForegroundColor White
    
    return $allScopes
}

function Get-ScopeDisplayName {
    param([string]$Scope)
    
    if ($Scope -like "*/managementGroups/*") {
        $mgName = ($Scope -split '/')[-1]
        try {
            $mg = Get-AzManagementGroup -GroupName $mgName -ErrorAction SilentlyContinue
            if ($mg) {
                return "🏢 MG: $($mg.DisplayName) ($mgName)"
            }
        } catch {}
        return "🏢 MG: $mgName"
    }
    elseif ($Scope -like "/subscriptions/*" -and $Scope -notlike "*/resourceGroups/*") {
        $subId = ($Scope -split '/')[2]
        try {
            $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction SilentlyContinue
            if ($sub) {
                return "📊 Sub: $($sub.Name)"
            }
        } catch {}
        return "📊 Sub: $subId"
    }
    elseif ($Scope -like "*/resourceGroups/*") {
        $parts = $Scope -split '/'
        $subId = $parts[2]
        $rgName = $parts[4]
        try {
            $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction SilentlyContinue
            if ($sub) {
                return "📁 RG: $rgName (in $($sub.Name))"
            }
        } catch {}
        return "📁 RG: $rgName"
    }
    else {
        return "📋 Other: $Scope"
    }
}

function Get-SafeRoleAssignments {
    param([string]$Scope)
    
    try {
        $assignments = Get-AzRoleAssignment -Scope $Scope -IncludeClassicAdministrators:$false -ErrorAction Stop
        return $assignments
    }
    catch {
        Write-Warning "Cannot access scope $Scope`: $($_.Exception.Message)"
        return @()
    }
}

function Test-PrincipalExistsSafe {
    param(
        [string]$ObjectId,
        [string]$PrincipalType
    )
    
    $result = @{
        Exists = $null
        Error = $null
        SkipReason = $null
    }
    
    if ([string]::IsNullOrEmpty($ObjectId)) {
        $result.SkipReason = "Empty ObjectId"
        return $result
    }
    
    try {
        switch ($PrincipalType) {
            "User" {
                $principal = Get-AzADUser -ObjectId $ObjectId -ErrorAction SilentlyContinue
                $result.Exists = $null -ne $principal
            }
            "Group" {
                $principal = Get-AzADGroup -ObjectId $ObjectId -ErrorAction SilentlyContinue
                $result.Exists = $null -ne $principal
            }
            { $_ -in @("ServicePrincipal", "MSI") } {
                $principal = Get-AzADServicePrincipal -ObjectId $ObjectId -ErrorAction SilentlyContinue
                $result.Exists = $null -ne $principal
            }
            default {
                $result.SkipReason = "Unknown principal type: $PrincipalType"
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        if ($_.Exception.Message -like "*insufficient*" -or $_.Exception.Message -like "*forbidden*") {
            $result.Exists = $null
            $result.SkipReason = "Insufficient permissions"
        }
    }
    
    return $result
}

function Get-AllOrphanedAssignments {
    param(
        [string]$SubscriptionId,
        [switch]$TenantWide,
        [switch]$IncludeManagementGroups
    )
    
    Write-Host "`n🔍 Scanning for orphaned role assignments..." -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
    
    # Get all scopes
    $scopes = Get-AllScopes -SubscriptionId $SubscriptionId -TenantWide:$TenantWide -IncludeManagementGroups:$IncludeManagementGroups
    
    if ($scopes.Count -eq 0) {
        Write-Warning "No scopes found to scan"
        return @()
    }
    
    $allOrphaned = @()
    $totalScanned = 0
    $totalAssignments = 0
    $stats = @{
        Unknown = 0
        Verified = 0
        Skipped = 0
        Orphaned = 0
        Errors = 0
    }
    
    Write-Host "`n🔍 Starting comprehensive scan..." -ForegroundColor Yellow
    
    foreach ($scope in $scopes) {
        $totalScanned++
        Write-Progress -Activity "Scanning Scopes" -Status "[$totalScanned/$($scopes.Count)] $scope" -PercentComplete (($totalScanned / $scopes.Count) * 100)
        
        $assignments = Get-SafeRoleAssignments -Scope $scope
        if ($assignments.Count -eq 0) {
            continue
        }
        
        $totalAssignments += $assignments.Count
        $scopeDisplayName = Get-ScopeDisplayName -Scope $scope
        
        # Show progress for scopes with assignments
        Write-Host "  📍 $scopeDisplayName ($($assignments.Count) assignments)" -ForegroundColor Gray
        
        foreach ($assignment in $assignments) {
            # Check for Unknown type (most reliable)
            if ($assignment.ObjectType -eq 'Unknown') {
                $allOrphaned += [PSCustomObject]@{
                    Scope = $scope
                    ScopeDisplayName = $scopeDisplayName
                    ObjectId = $assignment.ObjectId
                    RoleDefinitionName = $assignment.RoleDefinitionName
                    DisplayName = $assignment.DisplayName
                    PrincipalType = "Unknown"
                    DetectionMethod = "ObjectType=Unknown"
                    VerificationResult = "N/A"
                    Assignment = $assignment
                }
                $stats.Unknown++
                Write-Host "    🗑️ Found Unknown: $($assignment.ObjectId) ($($assignment.RoleDefinitionName))" -ForegroundColor Red
                continue
            }
            
            # Verify principal existence
            if (-not [string]::IsNullOrEmpty($assignment.ObjectId)) {
                $verification = Test-PrincipalExistsSafe -ObjectId $assignment.ObjectId -PrincipalType $assignment.ObjectType
                
                if ($verification.Exists -eq $false) {
                    $allOrphaned += [PSCustomObject]@{
                        Scope = $scope
                        ScopeDisplayName = $scopeDisplayName
                        ObjectId = $assignment.ObjectId
                        RoleDefinitionName = $assignment.RoleDefinitionName
                        DisplayName = $assignment.DisplayName
                        PrincipalType = $assignment.ObjectType
                        DetectionMethod = "PrincipalVerification"
                        VerificationResult = if($verification.SkipReason) { $verification.SkipReason } else { "NotFound" }
                        Assignment = $assignment
                    }
                    $stats.Orphaned++
                    Write-Host "    🗑️ Found Orphaned: $($assignment.ObjectType) $($assignment.ObjectId) ($($assignment.RoleDefinitionName))" -ForegroundColor Red
                }
                elseif ($verification.Exists -eq $true) {
                    $stats.Verified++
                }
                else {
                    $stats.Skipped++
                    if ($verification.Error) {
                        $stats.Errors++
                    }
                }
            }
        }
    }
    
    Write-Progress -Completed -Activity "Scanning Scopes"
    
    Write-Host "`n📊 COMPREHENSIVE SCAN RESULTS:" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "  📋 Scopes scanned: $totalScanned" -ForegroundColor White
    Write-Host "  🔍 Total assignments: $totalAssignments" -ForegroundColor White
    Write-Host "  ❓ Unknown type: $($stats.Unknown)" -ForegroundColor Yellow
    Write-Host "  ✅ Verified existing: $($stats.Verified)" -ForegroundColor Green
    Write-Host "  ⏭️ Skipped verification: $($stats.Skipped)" -ForegroundColor Gray
    Write-Host "  🗑️ Verified orphaned: $($stats.Orphaned)" -ForegroundColor Red
    Write-Host "  ❌ Verification errors: $($stats.Errors)" -ForegroundColor DarkRed
    Write-Host "  🚨 TOTAL ORPHANED: $($allOrphaned.Count)" -ForegroundColor $(if($allOrphaned.Count -gt 0){"Red"}else{"Green"})
    
    return $allOrphaned
}

function Show-OrphanedSummary {
    param([array]$OrphanedAssignments)
    
    if ($OrphanedAssignments.Count -eq 0) {
        Write-Host "`n✅ No orphaned role assignments found!" -ForegroundColor Green
        Write-Host "Your Azure environment is clean! 🎉" -ForegroundColor Green
        return
    }
    
    Write-Host "`n🚨 ORPHANED ASSIGNMENTS FOUND: $($OrphanedAssignments.Count)" -ForegroundColor Red
    Write-Host "=" * 70 -ForegroundColor Red
    
    # By type
    $byType = $OrphanedAssignments | Group-Object PrincipalType
    Write-Host "`n📊 By Principal Type:" -ForegroundColor Cyan
    foreach ($group in $byType) {
        $icon = switch ($group.Name) {
            "Unknown" { "❓" }
            "User" { "👤" }
            "Group" { "👥" }
            "ServicePrincipal" { "🔧" }
            "MSI" { "🤖" }
            default { "📋" }
        }
        Write-Host "  $icon $($group.Name): $($group.Count)" -ForegroundColor White
    }
    
    # By role (high-risk first)
    $byRole = $OrphanedAssignments | Group-Object RoleDefinitionName | Sort-Object Count -Descending
    Write-Host "`n📊 By Role:" -ForegroundColor Cyan
    $byRole | ForEach-Object {
        $color = if ($_.Name -in @("Owner", "Contributor", "User Access Administrator", "Security Administrator")) { 
            "Red" 
        } else { 
            "White" 
        }
        Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor $color
    }
    
    # By scope type
    $byScopeType = $OrphanedAssignments | Group-Object { 
        if ($_.Scope -like "*/managementGroups/*") { "Management Group" }
        elseif ($_.Scope -like "/subscriptions/*" -and $_.Scope -notlike "*/resourceGroups/*") { "Subscription" }
        elseif ($_.Scope -like "*/resourceGroups/*") { "Resource Group" }
        else { "Other" }
    }
    Write-Host "`n📍 By Scope Type:" -ForegroundColor Cyan
    foreach ($group in $byScopeType) {
        $icon = switch ($group.Name) {
            "Management Group" { "🏢" }
            "Subscription" { "📊" }
            "Resource Group" { "📁" }
            default { "📋" }
        }
        Write-Host "  $icon $($group.Name): $($group.Count)" -ForegroundColor White
    }
    
    # High-risk summary
    $highRisk = $OrphanedAssignments | Where-Object { 
        $_.RoleDefinitionName -in @("Owner", "Contributor", "User Access Administrator", "Security Administrator") 
    }
    if ($highRisk.Count -gt 0) {
        Write-Host "`n⚠️  CRITICAL: $($highRisk.Count) ORPHANED PRIVILEGED ASSIGNMENTS!" -ForegroundColor Red
        Write-Host "These represent serious security risks!" -ForegroundColor Red
        $highRisk | Group-Object RoleDefinitionName | ForEach-Object {
            Write-Host "  🔥 $($_.Name): $($_.Count)" -ForegroundColor Red
        }
    }
    
    if ($DetailedReport) {
        Write-Host "`n📋 DETAILED ORPHANED ASSIGNMENTS:" -ForegroundColor Yellow
        Write-Host "=" * 70 -ForegroundColor Yellow
        
        # Sort by risk level, then by scope type
        $sortedOrphans = $OrphanedAssignments | Sort-Object @{
            E={
                if($_.RoleDefinitionName -in @("Owner","Contributor","User Access Administrator")) {0} 
                else {1}
            }
        }, @{
            E={
                if ($_.Scope -like "*/managementGroups/*") {0}
                elseif ($_.Scope -like "/subscriptions/*" -and $_.Scope -notlike "*/resourceGroups/*") {1}
                else {2}
            }
        }, PrincipalType, RoleDefinitionName
        
        foreach ($orphan in $sortedOrphans) {
            $riskColor = if ($orphan.RoleDefinitionName -in @("Owner", "Contributor", "User Access Administrator")) { 
                "Red" 
            } else { 
                "White" 
            }
            
            Write-Host "🔸 Type: $($orphan.PrincipalType) | ObjectId: $($orphan.ObjectId)" -ForegroundColor $riskColor
            Write-Host "   Role: $($orphan.RoleDefinitionName)" -ForegroundColor Gray
            Write-Host "   Scope: $($orphan.ScopeDisplayName)" -ForegroundColor Gray
            Write-Host "   Full Scope: $($orphan.Scope)" -ForegroundColor DarkGray
            Write-Host "   Detection: $($orphan.DetectionMethod)" -ForegroundColor DarkGray
            if ($orphan.DisplayName) {
                Write-Host "   Last Known Name: $($orphan.DisplayName)" -ForegroundColor DarkGray
            }
            Write-Host ""
        }
    }
}

function Remove-OrphanedAssignments {
    param(
        [array]$OrphanedAssignments,
        [string[]]$ExcludeTypes,
        [switch]$Force
    )
    
    $toDelete = $OrphanedAssignments | Where-Object { $_.PrincipalType -notin $ExcludeTypes }
    
    if ($ExcludeTypes.Count -gt 0) {
        $excluded = $OrphanedAssignments.Count - $toDelete.Count
        Write-Host "`n⏭️  Excluding $excluded assignments of types: $($ExcludeTypes -join ', ')" -ForegroundColor Yellow
    }
    
    if ($toDelete.Count -eq 0) {
        Write-Host "ℹ️ No assignments to delete after exclusions" -ForegroundColor Green
        return
    }
    
    # Show what will be deleted by scope type
    Write-Host "`n📋 ASSIGNMENTS TO DELETE:" -ForegroundColor Yellow
    Write-Host "=========================" -ForegroundColor Yellow
    
    $deleteByScope = $toDelete | Group-Object { 
        if ($_.Scope -like "*/managementGroups/*") { "🏢 Management Group" }
        elseif ($_.Scope -like "/subscriptions/*" -and $_.Scope -notlike "*/resourceGroups/*") { "📊 Subscription" }
        elseif ($_.Scope -like "*/resourceGroups/*") { "📁 Resource Group" }
        else { "📋 Other" }
    }
    
    foreach ($group in $deleteByScope) {
        Write-Host "  $($group.Name): $($group.Count)" -ForegroundColor White
    }
    
    # Safety confirmation
    if (-not $Force) {
        Write-Host "`n⚠️  DANGER: About to DELETE $($toDelete.Count) orphaned assignments!" -ForegroundColor Red
        Write-Host "This action CANNOT be undone!" -ForegroundColor Red
        Write-Host "Includes assignments at Management Group level!" -ForegroundColor Red
        $confirmation = Read-Host "`nType 'DELETE' to confirm (case sensitive, or anything else to cancel)"
        if ($confirmation -ne "DELETE") {
            Write-Host "❌ Operation cancelled by user" -ForegroundColor Yellow
            return
        }
    }
    
    Write-Host "`n🗑️  DELETING $($toDelete.Count) orphaned assignments..." -ForegroundColor Red
    
    $success = 0
    $failed = 0
    $failedList = @()
    
    foreach ($orphan in $toDelete) {
        try {
            Remove-AzRoleAssignment -InputObject $orphan.Assignment -ErrorAction Stop
            Write-Host "✅ Deleted: $($orphan.PrincipalType) $($orphan.ObjectId) ($($orphan.RoleDefinitionName)) from $($orphan.ScopeDisplayName)" -ForegroundColor Green
            $success++
        }
        catch {
            Write-Host "❌ Failed: $($orphan.ObjectId) at $($orphan.ScopeDisplayName) - $($_.Exception.Message)" -ForegroundColor Red
            $failed++
            $failedList += $orphan
        }
    }
    
    Write-Host "`n📊 DELETION RESULTS:" -ForegroundColor Cyan
    Write-Host "  ✅ Successfully deleted: $success" -ForegroundColor Green
    Write-Host "  ❌ Failed to delete: $failed" -ForegroundColor Red
    
    if ($success -gt 0) {
        Write-Host "`n🎉 Successfully cleaned up $success orphaned role assignments!" -ForegroundColor Green
        Write-Host "Security posture improved! 🔒" -ForegroundColor Green
    }
    
    if ($failed -gt 0) {
        Write-Host "`n❌ Failed Deletions:" -ForegroundColor Red
        $failedList | Select-Object -First 5 | ForEach-Object {
            Write-Host "  - $($_.ObjectId) at $($_.ScopeDisplayName)" -ForegroundColor Gray
        }
        if ($failedList.Count -gt 5) {
            Write-Host "  ... and $($failedList.Count - 5) more" -ForegroundColor Gray
        }
    }
}

# MAIN EXECUTION
try {
    Write-Host "🚀 Phase 1: Enhanced Orphaned Role Assignment Cleanup" -ForegroundColor Green
    Write-Host "====================================================" -ForegroundColor Green
    Write-Host "Includes Management Groups scanning! 🏢" -ForegroundColor Green
    
    # Verify connection first
    $connected = Verify-AzureConnection
    if (-not $connected) {
        exit 1
    }
    
    # Scan for orphaned assignments
    $orphaned = Get-AllOrphanedAssignments -SubscriptionId $SubscriptionId -TenantWide:$TenantWide -IncludeManagementGroups:$IncludeManagementGroups
    
    # Show results
    Show-OrphanedSummary -OrphanedAssignments $orphaned
    
    # Take action
    if ($Delete) {
        Remove-OrphanedAssignments -OrphanedAssignments $orphaned -ExcludeTypes $ExcludeTypes -Force:$Force
    } else {
        Write-Host "`n💡 DRY RUN COMPLETE - No changes made" -ForegroundColor Cyan
        
        if ($orphaned.Count -gt 0) {
            Write-Host "`n🎯 To clean up these orphaned assignments:" -ForegroundColor Yellow
            $cmd = ".\Phase1-WithManagementGroups.ps1 -Delete -ExcludeTypes @('MSI')"
            if ($SubscriptionId) { $cmd += " -SubscriptionId '$SubscriptionId'" }
            if ($TenantWide) { $cmd += " -TenantWide" }
            Write-Host $cmd -ForegroundColor Cyan
            Write-Host "`nNote: This includes Management Group assignments!" -ForegroundColor Red
            Write-Host "Make sure you have proper permissions!" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n✅ Enhanced Phase 1 completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Error "❌ Phase 1 failed: $($_.Exception.Message)"
    exit 1
}

<#
ENHANCED USAGE:

1. Connect manually first:
   Connect-AzAccount -TenantId "3d627bf1-4bad-4158-ad29-0a5ec75268aa"

2. Full scan including Management Groups:
   .\Phase1-WithManagementGroups.ps1 -TenantWide -DetailedReport

3. Safe cleanup:
   .\Phase1-WithManagementGroups.ps1 -TenantWide -Delete -ExcludeTypes @("MSI")

This version will show Management Group assignments with full scope details!
#>