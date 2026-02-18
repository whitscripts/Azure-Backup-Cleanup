<#
.SYNOPSIS
End-to-end deployment of an automated Azure backup cleanup solution.

.DESCRIPTION
This script deploys and configures an Azure-based solution to evaluate and clean up
Azure VM backup recovery points stored in a Recovery Services Vault when backups
are stopped, disabled, or suspended.

The script performs the following high-level actions:
- Ensures required Azure resource providers and PowerShell modules are available
- Creates or reuses an Azure Automation Account with a system-assigned managed identity
- Assigns required RBAC permissions for backup management
- Configures Automation variables for cross-subscription Log Analytics logging
- Generates, imports, and publishes an Automation Runbook that:
  - Enumerates Azure VM backup items in a Recovery Services Vault
  - Evaluates recovery points against configurable retention thresholds
  - Logs detailed results to Log Analytics
  - Supports a DryRun mode to simulate deletions without making changes
- Deploys a Logic App (Consumption) that triggers the runbook on a scheduled basis
- Optionally configures email notifications for runbook execution events

The solution is designed for safe operation in regulated or production environments,
with DryRun enabled by default and all destructive actions explicitly controlled.

.NOTES
- This script supports Recovery Services Vaults only.
- Data Protection Backup Vaults are detected and intentionally not modified.
- All environment-specific values must be provided in the VARIABLES section.
- Review and test in a non-production environment before enabling deletions.
#>




# =========================
# 0) VARIABLES (EDIT HERE)
# =========================
# ---------------- CORE SUBSCRIPTIONS ----------------
$PrimarySubscriptionId = "<Primary Subscription ID>" # Vault + Automation + Logic App + VNet
$LogAnalyticsSubscriptionId = "<Log Analytics Subscription ID>" # Log Analytics workspace subscription

# ---------------- BACKUP / AUTOMATION ----------------
# Vault inputs (we detect whether this is RSV or Data Protection)
$VaultName = "<Recovery Services Vault Name>"
$VaultResourceGroup = "<Vault Resource Group Name>"

# Automation Account
$AutomationAccountName = "<Automation Account Name>"
$AutomationRG = "<Automation Account Resource Group Name>"
$RunbookName = "<Runbook Name>" #"RB-Cleanup-Detached-VM-Backups"

# ---------------- LOG ANALYTICS ----------------
$LogAnalyticsResourceGroup = "<Log Analytics Resource Group Name>"
$LogAnalyticsWorkspaceName = "<Log Analytics Workspace Name>"

# ---------------- LOGIC APP ----------------
# Logic App
$LogicAppResourceGroup = "<Logic App Resource Group Name>"
$LogicAppName = "<Logic App Name>"

# Logic App schedule (UTC)
$ScheduleHours = @("<UTC Hour 0-23>","<UTC Hour 0-23>")  #Example:  @("0","12") 
$ScheduleMinutes = @("<UTC Minute 0-59>")    #Example:  @("0")

# ---------------- GLOBAL ----------------
# Safety / behavior (Logic App parameter values must be STRING)
$DryRun = "true" # "true" means NO deletions
$NotifyEnabled = "true" # "true" to enable email notifications
$NotifyTo = @("<notification-recipient@domain>")
$NotifySubject = "<Notification Email Subject>"

# Location
$Location = "<Azure Region (e.g., eastus)>"

# ---------------- API CONNECTION CONFIG ----------------
# Office 365 API Connection (for Logic App email)
$CreateOffice365Connection = $true
$Office365ConnectionName = "<API Connection Name (office365)>"

<# ---------------- PRIVATE ENDPOINT (AUTOMATION) ----------------
# Automation Private Endpoint
$EnableAutomationPrivateEndpoint = $true
$AutomationPrivateEndpointName = "<Private Endpoint Name>"
$PeVnetResourceGroup = "<VNet Resource Group Name>"
$PeVnetName = "<VNet Name>"
$PeSubnetName = "<Subnet Name>"
$AutomationPrivateDnsZoneName = "privatelink.azure-automation.net"
$AutomationPrivateEndpointGroupIds = @("DSCAndHybridWorker") # recommended group for Automation private endpoint 4
#>

# Output paths (generated artifacts)
$OutDir = (Get-Location).Path
$RunbookFile = Join-Path $OutDir "$RunbookName.ps1"
$LogicAppTemplateFile = Join-Path $OutDir "backupCleanupLogicApp.json"
Set-AzContext -Subscription $PrimarySubscriptionId

# =========================
# 1) HELPER FUNCTIONS***
# =========================
function Ensure-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Installing PowerShell module: $Name" -ForegroundColor Cyan
        Install-Module $Name -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $Name -ErrorAction Stop
}

function Ensure-ProviderRegistered {
    param([string]$Namespace)
    $prov = Get-AzResourceProvider -ProviderNamespace $Namespace -ErrorAction SilentlyContinue
    if ($prov -and $prov.RegistrationState -ne "Registered") {
        Write-Host "Registering resource provider: $Namespace" -ForegroundColor Cyan
        Register-AzResourceProvider -ProviderNamespace $Namespace | Out-Null
    }
}

function Ensure-ResourceGroup {
    param([string]$SubscriptionId, [string]$Name, [string]$Location)
    Set-AzContext -Subscription $SubscriptionId | Out-Null
    if (-not (Get-AzResourceGroup -Name $Name -ErrorAction SilentlyContinue)) {
        Write-Host "Creating Resource Group: $Name ($Location) in sub $SubscriptionId" -ForegroundColor Cyan
        New-AzResourceGroup -Name $Name -Location $Location | Out-Null
    } else {
        Write-Host "Resource Group exists: $Name (sub $SubscriptionId)" -ForegroundColor Yellow
    }
}

function Upsert-AutomationVariable {
    param(
        [string]$AutomationAccountName,
        [string]$AutomationRG,
        [string]$Name,
        [string]$Value,
        [bool]$Encrypted
    )
    $existing = Get-AzAutomationVariable -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationRG -Name $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Set-AzAutomationVariable -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationRG -Name $Name -Value $Value -Encrypted:$Encrypted | Out-Null
        Write-Host "Updated Automation variable: $Name" -ForegroundColor Green
    } else {
        New-AzAutomationVariable -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationRG -Name $Name -Value $Value -Encrypted:$Encrypted | Out-Null
        Write-Host "Created Automation variable: $Name" -ForegroundColor Green
    }
}

# =========================
# 2) MODULES + LOGIN***
# =========================
Ensure-Module Az.Accounts
Ensure-Module Az.Resources
Ensure-Module Az.Automation
Ensure-Module Az.Network
Ensure-Module Az.PrivateDns
Ensure-Module Az.OperationalInsights

Write-Host "Connecting to Azure..." -ForegroundColor Cyan
#Connect-AzAccount | Out-Null

# Providers (register in primary subscription)
Set-AzContext -Subscription $PrimarySubscriptionId | Out-Null
Ensure-ProviderRegistered "Microsoft.Automation"
Ensure-ProviderRegistered "Microsoft.Logic"
Ensure-ProviderRegistered "Microsoft.Network"
Ensure-ProviderRegistered "Microsoft.OperationalInsights"
Ensure-ProviderRegistered "Microsoft.RecoveryServices"
Ensure-ProviderRegistered "Microsoft.DataProtection"

# =========================
# 3) ENSURE RESOURCE GROUPS (ALL)***
# =========================
# Primary subscription RGs
Ensure-ResourceGroup -SubscriptionId $PrimarySubscriptionId -Name $VaultResourceGroup       -Location $Location
Ensure-ResourceGroup -SubscriptionId $PrimarySubscriptionId -Name $AutomationRG  -Location $Location
Ensure-ResourceGroup -SubscriptionId $PrimarySubscriptionId -Name $LogicAppResourceGroup    -Location $Location
Ensure-ResourceGroup -SubscriptionId $PrimarySubscriptionId -Name $PeVnetResourceGroup      -Location $Location

# Log Analytics subscription RG
Ensure-ResourceGroup -SubscriptionId $LogAnalyticsSubscriptionId -Name $LogAnalyticsResourceGroup -Location $Location

# =========================
# 4) DETECT VAULT TYPE (RSV vs Data Protection)***
# =========================
Set-AzContext -Subscription $PrimarySubscriptionId | Out-Null

$vaultRSV = Get-AzResource -ResourceGroupName $VaultResourceGroup -Name $VaultName -ResourceType "Microsoft.RecoveryServices/vaults" -ErrorAction SilentlyContinue
$vaultDP  = Get-AzResource -ResourceGroupName $VaultResourceGroup -Name $VaultName -ResourceType "Microsoft.DataProtection/backupVaults" -ErrorAction SilentlyContinue

if ($vaultDP -and -not $vaultRSV) {
    Write-Host "ERROR Detected '$VaultName' is a Data Protection Backup Vault (Microsoft.DataProtection/backupVaults)." -ForegroundColor Red
    Write-Host "This runbook deletes individual VM recovery points using Recovery Services vault cmdlets." -ForegroundColor Red
    Write-Host "For Backup Vaults, recovery points can be listed using Get-AzDataProtectionRecoveryPoint." -ForegroundColor Yellow  # 67
    throw "Stop: provide a Recovery Services vault name OR request the Data Protection variant."
}
if (-not $vaultRSV) {
    throw "Could not find vault '$VaultName' in RG '$VaultResourceGroup' as a Recovery Services vault."
}
Write-Host "OK Detected Recovery Services vault: $VaultName" -ForegroundColor Green

# =========================
# 5) CREATE/ENSURE AUTOMATION ACCOUNT + MI + PUBLIC ACCESS ENABLED
# =========================
Set-AzContext -Subscription $PrimarySubscriptionId | Out-Null

$aa = Get-AzAutomationAccount -ResourceGroupName $AutomationRG -Name $AutomationAccountName -ErrorAction SilentlyContinue
if (-not $aa) {
    Write-Host "Creating Automation Account: $AutomationAccountName" -ForegroundColor Cyan
    $aa = New-AzAutomationAccount -ResourceGroupName $AutomationRG -Name $AutomationAccountName -Location $Location -Plan "Basic"
} else {
    Write-Host "Automation Account exists: $AutomationAccountName" -ForegroundColor Yellow
}

# Ensure system assigned identity is enabled (cmdlet supports -AssignSystemIdentity) 2
$aa = Get-AzAutomationAccount -ResourceGroupName $AutomationRG -Name $AutomationAccountName
if (-not $aa.Identity -or -not $aa.Identity.PrincipalId) {
    Write-Host "Enabling Automation Account System Assigned Managed Identity..." -ForegroundColor Cyan
    Set-AzAutomationAccount -ResourceGroupName $AutomationRG -Name $AutomationAccountName -AssignSystemIdentity | Out-Null
    $aa = Get-AzAutomationAccount -ResourceGroupName $AutomationRG -Name $AutomationAccountName
}
Write-Host "Automation MI PrincipalId: $($aa.Identity.PrincipalId)" -ForegroundColor Green

# Force publicNetworkAccess = true on Automation account (ARM/Bicep schema includes publicNetworkAccess) 13
$aaRes = Get-AzResource -ResourceGroupName $AutomationRG -Name $AutomationAccountName -ResourceType "Microsoft.Automation/automationAccounts" -ErrorAction Stop
$props = @{}
foreach ($p in $aaRes.Properties.PSObject.Properties) { $props[$p.Name] = $p.Value }
$props["publicNetworkAccess"] = $true
Set-AzResource -ResourceId $aaRes.ResourceId -Properties $props -Force | Out-Null
Write-Host "OK Automation Account publicNetworkAccess set to TRUE (public access enabled)." -ForegroundColor Green



# =========================
# 6) PRIVATE ENDPOINT FOR AUTOMATION + PRIVATE DNS ZONE (ASYNC-SAFE + DNS VERIFY)
# Failing deployment - Will develop Code for this later
# =========================


# =========================
# 7) RBAC: Automation MI -> Vault (Backup Contributor)
# =========================
$vaultId = $vaultRSV.Id
New-AzRoleAssignment -ObjectId $aa.Identity.PrincipalId -RoleDefinitionName "Backup Contributor" -Scope $vaultId -ErrorAction SilentlyContinue | Out-Null
Write-Host "OK RBAC set: Automation MI has Backup Contributor on vault scope." -ForegroundColor Green

# =========================
# 8) LOG ANALYTICS: GET WORKSPACE ID + KEY FROM OTHER SUB & STORE IN AUTOMATION VARIABLES
# =========================
Set-AzContext -Subscription $LogAnalyticsSubscriptionId | Out-Null
$ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspaceName -ErrorAction Stop
$wsKey = (Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $LogAnalyticsResourceGroup -Name $LogAnalyticsWorkspaceName).PrimarySharedKey

Set-AzContext -Subscription $PrimarySubscriptionId | Out-Null
Upsert-AutomationVariable -AutomationAccountName $AutomationAccountName -AutomationRG $AutomationRG -Name "LA-WorkspaceId" -Value $ws.CustomerId.Guid -Encrypted:$false
Upsert-AutomationVariable -AutomationAccountName $AutomationAccountName -AutomationRG $AutomationRG -Name "LA-PrimaryKey"  -Value $wsKey         -Encrypted:$true
Write-Host "OK Log Analytics workspace ID/key stored in Automation variables." -ForegroundColor Green

# =========================
# 9) GENERATE RUNBOOK FILE (RECOVERY SERVICES VAULT)
# =========================
$RunbookContent = @'
<#
.SYNOPSIS
 Scans an Azure Recovery Services Vault for Azure VM backup items in a stopped/disabled state,
 evaluates recovery points against custom retention thresholds, and deletes (or simulates delete)
 of out-of-retention recovery points. Logs detailed results to Log Analytics custom table:
 DeleteStoppedBackupKeptsJobs_CL (via Log-Type header "DeleteStoppedBackupKeptsJobs").
.NOTES
 - Log Analytics HTTP Data Collector API creates table <Log-Type>_CL. Log-Type must be alpha-only.
 Use Log-Type: "DeleteStoppedBackupKeptsJobs" -> table "DeleteStoppedBackupKeptsJobs_CL".
 - In Azure Automation, WorkspaceId/Key are typically stored as Automation Variables.
 - On a laptop, pass -WorkspaceId and -WorkspaceKey explicitly.
#>

param(
 # -----------------------------
 # Logic App / Automation Parameters (match EXACT names passed by Logic App)
 # -----------------------------
 [Parameter(Mandatory = $true)]
 [string] $VaultName,
 [Parameter(Mandatory = $true)]
 [string] $VaultResourceGroup,
 [Parameter(Mandatory = $false)]
 [string] $DryRun = "true",
 [Parameter(Mandatory = $true)]
 [string] $SubscriptionId_Vault,
 # -----------------------------
 # Log Analytics (Data Collector API)
 # -----------------------------
 [string] $WorkspaceId = "",
 [string] $WorkspaceKey = "",
 # NEW DEFAULT: user requested keep (NOT deleted) details in output + logs
 [bool] $LogKeepDecisions = $true
)

# -----------------------------
# Normalize DryRun input from Logic App ("true"/"false") -> [bool]
# -----------------------------
$DryRun_b = $true
try {
 switch -Regex ($DryRun.Trim().ToLowerInvariant()) {
 '^(true|1|yes|y)$' { $DryRun_b = $true; break }
 '^(false|0|no|n)$' { $DryRun_b = $false; break }
 default { $DryRun_b = [bool]::Parse($DryRun) }
 }
} catch {
 throw "Invalid DryRun value '$DryRun'. Expected 'true' or 'false'."
}

# -----------------------------
# Retention thresholds
# -----------------------------
# Future Production Retention thresholds
# $InstantDays = 2
# $DailyDays = 21
# $WeeklyDays = 35
# $MonthlyDays = 547
# $YearlyDays = 3650
# Current Testing Retention thresholds (as provided)
$InstantDays = 3
$DailyDays = 3
$WeeklyDays = 7
$MonthlyDays = 20
$YearlyDays = 5

# -----------------------------
# Run context
# -----------------------------
$RunTimeUtc = (Get-Date).ToUniversalTime()
$RunId = if ($PSPrivateMetadata -and $PSPrivateMetadata.JobId) { [string]$PSPrivateMetadata.JobId } else { [guid]::NewGuid().ToString() }

# -----------------------------
# Helpers: Automation Variable read (safe on laptop)
# -----------------------------
function Try-GetAutomationVariable {
 param([Parameter(Mandatory=$true)][string]$Name)
 try {
 if (Get-Command -Name Get-AutomationVariable -ErrorAction SilentlyContinue) {
 return (Get-AutomationVariable -Name $Name)
 }
 } catch {}
 return $null
}

# If not provided, attempt Automation Variables
if ([string]::IsNullOrWhiteSpace($WorkspaceId)) { $WorkspaceId = Try-GetAutomationVariable -Name "LA-WorkspaceId" }
if ([string]::IsNullOrWhiteSpace($WorkspaceKey)) { $WorkspaceKey = Try-GetAutomationVariable -Name "LA-PrimaryKey" }
if ([string]::IsNullOrWhiteSpace($WorkspaceId) -or [string]::IsNullOrWhiteSpace($WorkspaceKey)) {
 throw "Missing Log Analytics WorkspaceId/Key. Provide -WorkspaceId and -WorkspaceKey (laptop), or set Automation Variables 'LA-WorkspaceId' and 'LA-PrimaryKey' (Azure Automation)."
}

# Ensure TLS 1.2+
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# -----------------------------
# Log Analytics Data Collector API (DeleteStoppedBackupKeptsJobs_CL)
# -----------------------------
$LogType = "DeleteStoppedBackupKeptsJobs" # Creates DeleteStoppedBackupKeptsJobs_CL

function New-LADataCollectorSignature {
 param(
 [Parameter(Mandatory=$true)][string]$BodyJson,
 [Parameter(Mandatory=$true)][string]$DateRfc1123
 )
 $method = "POST"
 $contentType = "application/json"
 $resource = "/api/logs"
 $contentLength = ([Text.Encoding]::UTF8.GetBytes($BodyJson)).Length
 $xHeaders = "x-ms-date:$DateRfc1123"
 $stringToHash = "$method`n$contentLength`n$contentType`n$xHeaders`n$resource"
 $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
 $keyBytes = [Convert]::FromBase64String($WorkspaceKey)
 $hmac = New-Object System.Security.Cryptography.HMACSHA256
 $hmac.Key = $keyBytes
 $hashBytes = $hmac.ComputeHash($bytesToHash)
 $encodedHash = [Convert]::ToBase64String($hashBytes)
 return "SharedKey ${WorkspaceId}:$encodedHash"
}

function Send-LALog {
 param(
 [Parameter(Mandatory=$true)][hashtable]$Record,
 [string]$TimeGeneratedField = "EventTimeUtc"
 )

 # Standard fields (NO manual suffixing - let Log Analytics apply suffix once)
 if (-not $Record.ContainsKey("RunId")) { $Record["RunId"] = $RunId }
 if (-not $Record.ContainsKey("RunTimeUtc")) { $Record["RunTimeUtc"] = $RunTimeUtc }
 if (-not $Record.ContainsKey("DryRun")) { $Record["DryRun"] = [bool]$DryRun_b }
 if (-not $Record.ContainsKey("VaultName")) { $Record["VaultName"] = $VaultName }
 if (-not $Record.ContainsKey("VaultRG")) { $Record["VaultRG"] = $VaultResourceGroup }
 if (-not $Record.ContainsKey("EventTimeUtc")) { $Record["EventTimeUtc"] = (Get-Date).ToUniversalTime() }

 $json = ($Record | ConvertTo-Json -Depth 20)
 $date = [DateTime]::UtcNow.ToString("r")
 $sig = New-LADataCollectorSignature -BodyJson $json -DateRfc1123 $date
 $uri = "https://$WorkspaceId.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

 Invoke-RestMethod -Method POST -Uri $uri -Headers @{
 "Authorization" = $sig
 "Log-Type" = $LogType
 "x-ms-date" = $date
 "Content-Type" = "application/json"
 "time-generated-field" = $TimeGeneratedField
 } -Body $json | Out-Null
}

function Write-CleanupLog {
 param(
 [Parameter(Mandatory=$true)][string]$Event,
 [hashtable]$Extra = @{}
 )

 # Event is a base name; LA will make Event_s automatically
 $rec = @{ Event = $Event }
 foreach ($k in $Extra.Keys) { $rec[$k] = $Extra[$k] }
 Send-LALog -Record $rec
}

# -----------------------------
# Azure Auth
# -----------------------------
function Connect-AzureContext {
 param([string]$SubId)
 try {
 if ($env:AUTOMATION_ASSET_ACCOUNTID -or (Get-Command -Name Get-AutomationConnection -ErrorAction SilentlyContinue)) {
 Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
 } else {
 Connect-AzAccount -ErrorAction Stop | Out-Null
 }
 } catch {
 Connect-AzAccount -ErrorAction Stop | Out-Null
 }
 Set-AzContext -SubscriptionId $SubId -ErrorAction Stop | Out-Null
}

Write-Output "=== Stopped Backup Cleanup Run ==="
Write-Output ("RunId: {0}" -f $RunId)
Write-Output ("RunTimeUtc: {0}" -f $RunTimeUtc.ToString("o"))
Write-Output ("DryRun: {0}" -f $DryRun_b)
Write-Output ("SubscriptionId_Vault: {0}" -f $SubscriptionId_Vault)
Write-Output ("Vault: {0} (RG: {1})" -f $VaultName, $VaultResourceGroup)
Write-Output ""

Write-CleanupLog -Event "RunStarted" -Extra @{
 Message = "Stopped-backup cleanup evaluation started"
 SubscriptionId_Vault = $SubscriptionId_Vault
}

# Set context to Vault subscription and get vault
Connect-AzureContext -SubId $SubscriptionId_Vault
$vault = Get-AzRecoveryServicesVault -Name $VaultName -ResourceGroupName $VaultResourceGroup -ErrorAction Stop
Set-AzRecoveryServicesVaultContext -Vault $vault

Write-CleanupLog -Event "VaultContextSet" -Extra @{
 VaultId = [string]$vault.ID
 Message = "Recovery Services vault context set"
}

# Determine "stopped/disabled" states robustly
$StoppedStateRegex = '(?i)stop|suspend|disable'

# Recovery point classification
function Get-RetentionTypeAndLimit {
 param([Parameter(Mandatory=$true)]$rp)
 $type = "Daily"
 if ($rp.PSObject.Properties.Name -contains "IsInstantRP" -and $rp.IsInstantRP) {
 $type = "Instant"
 }
 elseif ($rp.PSObject.Properties.Name -contains "RecoveryPointTier" -and $rp.RecoveryPointTier) {
 switch ([string]$rp.RecoveryPointTier) {
 "Weekly" { $type = "Weekly" }
 "Monthly" { $type = "Monthly" }
 "Yearly" { $type = "Yearly" }
 default { $type = "Daily" }
 }
 }
 $limit = @{
 Instant = $InstantDays
 Daily = $DailyDays
 Weekly = $WeeklyDays
 Monthly = $MonthlyDays
 Yearly = $YearlyDays
 }[$type]
 return @{ Type = $type; Limit = [int]$limit }
}

# Enumerate items at vault level
$allVmItems = @()
try {
 $allVmItems = Get-AzRecoveryServicesBackupItem -BackupManagementType AzureVM -WorkloadType AzureVM -VaultId $vault.ID -ErrorAction Stop
} catch {
 Write-CleanupLog -Event "ItemEnumerationFailed" -Extra @{
 Error = $_.Exception.Message
 Message = "Failed to enumerate AzureVM backup items at vault level"
 }
 throw
}

Write-Output ("Total VM backup items returned by vault query: {0}" -f ($allVmItems.Count))

Write-CleanupLog -Event "ItemsEnumerated" -Extra @{
 TotalItems = [int]$allVmItems.Count
 Message = "Enumerated AzureVM backup items at vault level"
}

# Tracking
$StoppedVMs  = New-Object System.Collections.Generic.List[string]
$Candidates  = New-Object System.Collections.Generic.List[object]
$Deletions   = New-Object System.Collections.Generic.List[object]
# NEW: Keep list (NOT deleted)
$Keeps       = New-Object System.Collections.Generic.List[object]

$EvaluatedVMs = 0
$EligibleRPs  = 0
$KeptRPs      = 0
$Errors       = New-Object System.Collections.Generic.List[string]

foreach ($item in $allVmItems) {
 $ps = [string]$item.ProtectionState
 $vmName = [string]$item.FriendlyName
 if ([string]::IsNullOrWhiteSpace($vmName)) { $vmName = [string]$item.Name }
 if ($ps -notmatch $StoppedStateRegex) { continue }

 $EvaluatedVMs++
 if (-not $StoppedVMs.Contains($vmName)) { $StoppedVMs.Add($vmName) }

 Write-Output ("Stopped/Disabled VM detected: {0} / ProtectionState={1}" -f $vmName, $ps)

 Write-CleanupLog -Event "StoppedBackupVMDetected" -Extra @{
 VMName = $vmName
 ProtectionState = $ps
 ItemName = [string]$item.Name
 Message = "VM backup item is in stopped/disabled/suspended state and will be evaluated"
 }

 $rps = @()
 try {
 $rps = Get-AzRecoveryServicesBackupRecoveryPoint -Item $item -VaultId $vault.ID -ErrorAction Stop
 } catch {
 $msg = "Failed RP enumeration for VM '$vmName': $($_.Exception.Message)"
 $Errors.Add($msg) | Out-Null
 Write-Output $msg
 Write-CleanupLog -Event "RecoveryPointEnumerationFailed" -Extra @{
 VMName = $vmName
 Error  = $_.Exception.Message
 }
 continue
 }

 $vmEvaluatedRPs = 0
 $vmCandidates   = 0
 $vmDeleted      = 0
 $vmKept         = 0

 foreach ($rp in $rps) {
 $vmEvaluatedRPs++
 $rpTime = $rp.RecoveryPointTime
 $ageDays = (New-TimeSpan -Start $rpTime -End (Get-Date)).TotalDays
 $rt = Get-RetentionTypeAndLimit -rp $rp
 $type  = $rt.Type
 $limit = [int]$rt.Limit

 # -----------------------------
 # KEEP (NOT deleted)
 # -----------------------------
 if ($ageDays -le $limit) {
 $vmKept++
 $KeptRPs++

 $keepObj = [PSCustomObject]@{
 VMName = $vmName
 ProtectionState = $ps
 RecoveryPointTimeUtc = ([datetime]$rpTime).ToUniversalTime().ToString("o")
 RecoveryPointType = $type
 AgeDays = [int]$ageDays
 ThresholdDays = $limit
 Action = "Keep"
 Reason = "WithinRetention"
 }

 $Keeps.Add($keepObj) | Out-Null

 if ($LogKeepDecisions) {
 Write-CleanupLog -Event "RecoveryPointKept" -Extra @{
 VMName = $vmName
 Decision = "Keep"
 RecoveryPointType = $type
 RetentionLimit = $limit
 AgeDays = [int]$ageDays
 RecoveryPointTime = $rpTime
 Reason = "WithinRetention"
 }
 }
 continue
 }

 # -----------------------------
 # OUTSIDE retention => candidate/delete
 # -----------------------------
 $EligibleRPs++
 $vmCandidates++

 if ($DryRun_b) {
 $cand = [PSCustomObject]@{
 VMName = $vmName
 ProtectionState = $ps
 RecoveryPointTimeUtc = ([datetime]$rpTime).ToUniversalTime().ToString("o")
 RecoveryPointType = $type
 AgeDays = [int]$ageDays
 ThresholdDays = $limit
 Action = "WouldDelete"
 Reason = "$type retention threshold exceeded"
 }

 $Candidates.Add($cand) | Out-Null

 Write-CleanupLog -Event "DryRunCandidate" -Extra @{
 VMName = $vmName
 Decision = "WouldDelete"
 RecoveryPointType = $type
 RetentionLimit = $limit
 AgeDays = [int]$ageDays
 RecoveryPointTime = $rpTime
 Reason = "ExceedsRetention_DryRun"
 }
 }
 else {
 try {
 Remove-AzRecoveryServicesBackupRecoveryPoint -Item $item -RecoveryPoint $rp -Force -Confirm:$false -ErrorAction Stop
 $vmDeleted++

 $del = [PSCustomObject]@{
 VMName = $vmName
 ProtectionState = $ps
 RecoveryPointTimeUtc = ([datetime]$rpTime).ToUniversalTime().ToString("o")
 DeletedTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
 RecoveryPointType = $type
 AgeDays = [int]$ageDays
 ThresholdDays = $limit
 Action = "Deleted"
 Reason = "$type retention threshold exceeded"
 }

 $Deletions.Add($del) | Out-Null

 Write-CleanupLog -Event "RecoveryPointDeleted" -Extra @{
 VMName = $vmName
 Decision = "Deleted"
 RecoveryPointType = $type
 RetentionLimit = $limit
 AgeDays = [int]$ageDays
 RecoveryPointTime = $rpTime
 DeletedTimeUtc = (Get-Date).ToUniversalTime()
 Reason = "ExceedsRetention_Deleted"
 }
 }
 catch {
 $msg = "Deletion failed for VM '$vmName' RP '$rpTime': $($_.Exception.Message)"
 $Errors.Add($msg) | Out-Null
 Write-Output $msg

 Write-CleanupLog -Event "DeletionFailed" -Extra @{
 VMName = $vmName
 Decision = "Failed"
 RecoveryPointType = $type
 RetentionLimit = $limit
 AgeDays = [int]$ageDays
 RecoveryPointTime = $rpTime
 Error = $_.Exception.Message
 Reason = "DeleteException"
 }
 }
 }
 }

 # UPDATED: include kept count
 Write-CleanupLog -Event "VMEvaluated" -Extra @{
 VMName = $vmName
 ProtectionState = $ps
 EvaluatedRPs = [int]$vmEvaluatedRPs
 Kept = [int]$vmKept
 Candidates = [int]$vmCandidates
 Deleted = [int]$vmDeleted
 VMStatus = if ($vmCandidates -eq 0) { "NoAction" } elseif ($DryRun_b) { "DryRunCandidates" } else { "DeletionsPerformed" }
 }

 Write-Output ("VM Evaluated: {0} / RPs={1} / Kept={2} / Candidates={3} / Deleted={4}" -f $vmName, $vmEvaluatedRPs, $vmKept, $vmCandidates, $vmDeleted)
}

if ($EvaluatedVMs -eq 0) {
 Write-Output ""
 Write-Output "No stopped/disabled VM backup items were detected."
 Write-CleanupLog -Event "NoStoppedVMsFound" -Extra @{
 Message = "No VM items matched stopped/disabled/suspended state filter"
 }
}

if ($EligibleRPs -eq 0) {
 Write-Output ""
 Write-Output "No eligible recovery points found for cleanup."
 Write-CleanupLog -Event "NoOp" -Extra @{
 Message = "No recovery points exceeded retention thresholds"
 EvaluatedVMs = [int]$EvaluatedVMs
 }
}

# UPDATED: include kept counts in completion
Write-CleanupLog -Event "RunCompleted" -Extra @{
 EvaluatedVMs = [int]$EvaluatedVMs
 EligibleRPs  = [int]$EligibleRPs
 KeptRPs      = [int]$KeptRPs
 KeepCount    = [int]$Keeps.Count
 Candidates   = [int]$Candidates.Count
 Deletions    = [int]$Deletions.Count
 Errors       = [int]$Errors.Count
 Message      = "Stopped-backup cleanup evaluation completed"
}

Write-Output ""
Write-Output "=== Summary ==="
Write-Output ("Stopped/disabled VMs detected: {0}" -f $StoppedVMs.Count)
if ($StoppedVMs.Count -gt 0) {
 $StoppedVMs | Sort-Object | ForEach-Object { Write-Output (" - {0}" -f $_) }
}

Write-Output ""
Write-Output ("Recovery points kept (NOT deleted): {0}" -f $Keeps.Count)

# NEW: print kept details
if ($Keeps.Count -gt 0) {
 Write-Output ""
 Write-Output "Kept Recovery Points (Within Retention):"
 $Keeps | Sort-Object VMName, RecoveryPointTimeUtc | ForEach-Object {
 Write-Output (" - VM={0} / RP={1} / Type={2} / AgeDays={3} / ThresholdDays={4} / Reason={5}" -f `
 $_.VMName, $_.RecoveryPointTimeUtc, $_.RecoveryPointType, $_.AgeDays, $_.ThresholdDays, $_.Reason)
 }
}

Write-Output ""
if ($DryRun_b) {
 Write-Output ("DryRun candidates (would delete): {0}" -f $Candidates.Count)
 if ($Candidates.Count -gt 0) {
 $Candidates | Sort-Object VMName, RecoveryPointTimeUtc | ForEach-Object {
 Write-Output (" - VM={0} / RP={1} / Type={2} / AgeDays={3} / ThresholdDays={4} / Reason={5}" -f `
 $_.VMName, $_.RecoveryPointTimeUtc, $_.RecoveryPointType, $_.AgeDays, $_.ThresholdDays, $_.Reason)
 }
 }
} else {
 Write-Output ("Deletions performed: {0}" -f $Deletions.Count)
 if ($Deletions.Count -gt 0) {
 $Deletions | Sort-Object VMName, DeletedTimeUtc | ForEach-Object {
 Write-Output (" - VM={0} / RP={1} / Deleted={2} / Type={3} / AgeDays={4} / ThresholdDays={5} / Reason={6}" -f `
 $_.VMName, $_.RecoveryPointTimeUtc, $_.DeletedTimeUtc, $_.RecoveryPointType, $_.AgeDays, $_.ThresholdDays, $_.Reason)
 }
 }
}

if ($Errors.Count -gt 0) {
 Write-Output ""
 Write-Output ("Errors: {0}" -f $Errors.Count)
 $Errors | ForEach-Object { Write-Output (" - {0}" -f $_) }
}

$Summary = [PSCustomObject]@{
 RunId = $RunId
 RunTimeUtc = $RunTimeUtc.ToString("o")
 DryRun = $DryRun_b
 SubscriptionId = $SubscriptionId_Vault
 VaultName = $VaultName
 VaultResourceGroup = $VaultResourceGroup
 InstantDays = $InstantDays
 DailyDays = $DailyDays
 WeeklyDays = $WeeklyDays
 MonthlyDays = $MonthlyDays
 YearlyDays = $YearlyDays
 StoppedVMs = $StoppedVMs
 KeepCount = $Keeps.Count
 CandidateCount = $Candidates.Count
 DeletionCount = $Deletions.Count
 EligibleRPCount = $EligibleRPs
 KeptRPCount = $KeptRPs
 Errors = $Errors
 Keeps = $Keeps
 Candidates = $Candidates
 Deletions = $Deletions
}

Write-Output ""
Write-Output "=== JSON Summary (for Logic App) ==="
Write-Output ($Summary | ConvertTo-Json -Depth 20)
Write-Output "=== End Run ==="
'@

# Write file exactly as UTF-8 (no BOM) to avoid token corruption / extra escapes
[System.IO.File]::WriteAllText($RunbookFile, $RunbookContent, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "a ... Runbook file generated: $RunbookFile" -ForegroundColor Green


# =========================
# 10) IMPORT + PUBLISH RUNBOOK
# =========================
Set-AzContext -Subscription $PrimarySubscriptionId | Out-Null

$rb = Get-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationRG -Name $RunbookName -ErrorAction SilentlyContinue
if ($rb) {
    Remove-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationRG -Name $RunbookName -Force | Out-Null
}
Import-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationRG -Name $RunbookName -Type PowerShell -Path $RunbookFile | Out-Null
Publish-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationRG -Name $RunbookName | Out-Null
Write-Host "OK Runbook imported and published: $RunbookName" -ForegroundColor Green



# =========================
# 11) CREATE OFFICE365 API CONNECTION RESOURCE (optional email)
# =========================
if ($CreateOffice365Connection) {
    $conn = Get-AzResource -ResourceGroupName $LogicAppResourceGroup -ResourceType "Microsoft.Web/connections" -Name $Office365ConnectionName -ErrorAction SilentlyContinue
    if (-not $conn) {
        Write-Host "Creating Office365 API connection resource '$Office365ConnectionName' (authorization required after deploy)..." -ForegroundColor Cyan
        $managedApiId = "/subscriptions/$PrimarySubscriptionId/providers/Microsoft.Web/locations/$Location/managedApis/office365"
        New-AzResource -ResourceGroupName $LogicAppResourceGroup -Location $Location -ResourceType "Microsoft.Web/connections" -Name $Office365ConnectionName -ApiVersion "2016-06-01" -Force `
            -Properties @{ displayName=$Office365ConnectionName; api=@{ id=$managedApiId } } | Out-Null
    }
    Write-Host "INFO  Office365 connection exists/created. After deployment, open it in Portal and click 'Authorize' once." -ForegroundColor Yellow
}



# =========================
# 12) GENERATE LOGIC APP ARM TEMPLATE (FINAL / STABLE) - UPDATED (MINIMAL FIXES)
# - Fix 1: subscriptionIdVault() -> parameters('subscriptionIdVault') in Start_Runbook_Job URI
# - Fix 3: notifyEnabled variable becomes boolean to match If comparison
# - Fix 4: ADD required workflow definition parameters so runtime parameters('subscriptionIdVault') exists
# - Fix 5 (THIS FIX): ensure '$connections' is not PowerShell-expanded to empty string
# =========================
$logicAppTemplate = @{
 '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
 contentVersion = '1.0.0.0'
 parameters = @{
  logicAppName = @{ type = 'string' }
  location = @{ type = 'string' }
  automationAccountName = @{ type = 'string' }
  AutomationRG = @{ type = 'string' }
  runbookName = @{ type = 'string' }
  vaultName = @{ type = 'string' }
  vaultResourceGroup = @{ type = 'string' }
  dryRun = @{ type = 'string' }
  notifyEnabled = @{ type = 'string' }
  notifyTo = @{ type = 'array' }
  notifySubject = @{ type = 'string' }
  office365ConnectionName = @{ type = 'string' }
  subscriptionIdVault = @{ type = 'string' }
 }
 resources = @(
  @{
   type = 'Microsoft.Logic/workflows'
   apiVersion = '2019-05-01'
   name = "[parameters('logicAppName')]"
   location = "[parameters('location')]"
   identity = @{ type = 'SystemAssigned' }
   properties = @{
    state = 'Enabled'
    definition = @{
     '$schema' = 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
     contentVersion = '1.0.0.0'
     parameters = @{
      '$connections' = @{ type = 'Object' }
      subscriptionIdVault = @{ type = 'String'; defaultValue = "[parameters('subscriptionIdVault')]" }
      AutomationRG = @{ type = 'String'; defaultValue = "[parameters('AutomationRG')]" }
      automationAccountName = @{ type = 'String'; defaultValue = "[parameters('automationAccountName')]" }
      runbookName = @{ type = 'String'; defaultValue = "[parameters('runbookName')]" }
      dryRun = @{ type = 'String'; defaultValue = "[parameters('dryRun')]" }
      notifyTo = @{ type = 'Array' ; defaultValue = "[parameters('notifyTo')]" }
      notifySubject = @{ type = 'String'; defaultValue = "[parameters('notifySubject')]" }
      notifyEnabled = @{ type = 'String'; defaultValue = "[parameters('notifyEnabled')]" }
     }
     triggers = @{
      Recurrence = @{
       type = 'Recurrence'
       recurrence = @{
        frequency = 'Day'
        interval = 1
        schedule = @{
         hours = $ScheduleHours
         minutes = $ScheduleMinutes
        }
       }
      }
     }
     actions = @{
      Initialize_variables = @{
       type = 'InitializeVariable'
       inputs = @{
        variables = @(
         @{
          name = 'notifyEnabled'
          type = 'boolean'
          value = "[equals(toLower(parameters('notifyEnabled')), 'true')]"
         }
        )
       }
       runAfter = @{}
      }
      Generate_Job_Id = @{
       type = 'Compose'
       inputs = '@guid()'
       runAfter = @{ Initialize_variables = @('Succeeded') }
      }
      Start_Runbook_Job = @{
       type = 'Http'
       runAfter = @{ Generate_Job_Id = @('Succeeded') }
       inputs = @{
        method = 'PUT'
        uri = "@concat('https://management.azure.com/subscriptions/', parameters('subscriptionIdVault'), '/resourceGroups/', parameters('AutomationRG'), '/providers/Microsoft.Automation/automationAccounts/', parameters('automationAccountName'), '/jobs/', outputs('Generate_Job_Id'), '?api-version=2024-10-23')"
        authentication = @{ type = 'ManagedServiceIdentity'; audience = 'https://management.azure.com/' }
        headers = @{ 'Content-Type' = 'application/json' }
        body = @{
         properties = @{
          runbook = @{ name = "[parameters('runbookName')]" }
          parameters = @{
           VaultName = "[parameters('vaultName')]"
           VaultResourceGroup = "[parameters('vaultResourceGroup')]"
           DryRun = "[parameters('dryRun')]"
           SubscriptionId_Vault = "[parameters('subscriptionIdVault')]"
          }
         }
        }
       }
      }
      Notify_if_enabled = @{
       type = 'If'
       runAfter = @{ Start_Runbook_Job = @('Succeeded') }
       expression = @{
        and = @(
         @{ equals = @( "@variables('notifyEnabled')", $true ) }
        )
       }
       actions = @{
        Send_Email = @{
         type = 'ApiConnection'
         inputs = @{
          host = @{
           connection = @{
            # OK MINIMAL FIX: escape $ so PowerShell doesn't turn it into @parameters('') in the generated JSON
            name = "@parameters('`$connections')['office365']['connectionId']"
           }
          }
          method = 'post'
          path = '/v2/Mail'
          body = @{
           To = "@{join(parameters('notifyTo'), ';')}"
           Subject = "@parameters('notifySubject')"
           Body = "@{concat('Backup cleanup runbook job queued at ', utcNow(), '<br/>Automation Account: ', parameters('automationAccountName'), '<br/>Runbook: ', parameters('runbookName'), '<br/>DryRun: ', parameters('dryRun'))}"
           BodyContentType = 'Html'
           Importance = 'Normal'
          }
         }
        }
       }
       else = @{ actions = @{} }
      }
     }
    }
    parameters = @{
     '$connections' = @{
      value = @{
       office365 = @{
        connectionId = "[concat('/subscriptions/', subscription().subscriptionId, '/resourceGroups/', resourceGroup().name, '/providers/Microsoft.Web/connections/', parameters('office365ConnectionName'))]"
        connectionName = "[parameters('office365ConnectionName')]"
        id = "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', parameters('location'), '/managedApis/office365')]"
       }
      }
     }
    }
   }
  }
 )
}

# Write ARM template JSON to disk
$logicAppTemplate `
 | ConvertTo-Json -Depth 50 `
 | Set-Content -Path $LogicAppTemplateFile -Encoding UTF8

# Validate JSON immediately
Get-Content $LogicAppTemplateFile -Raw `
 | ConvertFrom-Json `
 | Out-Null

Write-Host "OK Logic App ARM template generated and validated." -ForegroundColor Green



# =========================
# 13) DEPLOY LOGIC APP
# =========================

$params = @{
 ResourceGroupName = $LogicAppResourceGroup
 TemplateFile = $LogicAppTemplateFile
 logicAppName = $LogicAppName
 location = $Location
 automationAccountName = $AutomationAccountName
 AutomationRG = $AutomationRG
 runbookName = $RunbookName
 vaultName = $VaultName
 vaultResourceGroup = $VaultResourceGroup
 dryRun = $DryRun
 notifyEnabled = $NotifyEnabled
 notifyTo = $NotifyTo
 notifySubject = $NotifySubject
 office365ConnectionName = $Office365ConnectionName
 subscriptionIdVault = $PrimarySubscriptionId
}

New-AzResourceGroupDeployment @params
Write-Host "OK Logic App deployed: $LogicAppName" -ForegroundColor Green



# =========================
# 14) RBAC: LOGIC APP MI -> AUTOMATION ACCOUNT (Automation Operator)
# =========================
$laRes = Get-AzResource -ResourceGroupName $LogicAppResourceGroup -ResourceType "Microsoft.Logic/workflows" -Name $LogicAppName -ExpandProperties -ErrorAction Stop
$laFull = Get-AzResource -ResourceId $laRes.ResourceId -ExpandProperties
$laPrincipalId = $laFull.Identity.PrincipalId

if (-not $laPrincipalId) {
    Write-Host "WARN  Could not read Logic App principalId immediately. Wait ~60 seconds and rerun this block:" -ForegroundColor Yellow
    Write-Host "    \$laFull = Get-AzResource -ResourceId '$($laRes.ResourceId)' -ExpandProperties" -ForegroundColor Yellow
    Write-Host "    \$laPrincipalId = \$laFull.Identity.PrincipalId" -ForegroundColor Yellow
} else {
    New-AzRoleAssignment -ObjectId $laPrincipalId -RoleDefinitionName "Automation Contributor" -Scope $aaRes.Id -ErrorAction SilentlyContinue | Out-Null
    Write-Host "OK RBAC set: Logic App MI has Automation Contributor on Automation Account." -ForegroundColor Green
}



# =========================
# 15) NEXT STEPS / VALIDATION
# =========================
Write-Host ""
Write-Host "================== NEXT STEPS ==================" -ForegroundColor Cyan
Write-Host "1) One-time Office365 authorization (for email notifications):" -ForegroundColor Cyan
Write-Host "   Portal -> RG '$LogicAppResourceGroup' -> API Connections -> '$Office365ConnectionName' -> Authorize" -ForegroundColor Yellow
Write-Host ""
Write-Host "2) Test (NO deletes):" -ForegroundColor Cyan
Write-Host "   - Logic App deployed with DryRun=$DryRun. Run Trigger manually in Portal to queue a job." -ForegroundColor Yellow
Write-Host "   - Verify Automation Account -> Jobs -> runbook output." -ForegroundColor Yellow
Write-Host ""
Write-Host "3) Validate Log Analytics '$LogAnalyticsWorkspaceName':" -ForegroundColor Cyan
Write-Host "   Query:" -ForegroundColor Yellow
Write-Host "   BackupDeletion_CL | order by TimeGenerated desc" -ForegroundColor Yellow
Write-Host ""
Write-Host "4) Go live (enable deletes):" -ForegroundColor Cyan
