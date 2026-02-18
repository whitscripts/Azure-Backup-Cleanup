[README.md](https://github.com/user-attachments/files/25401444/README.md)
# Deploy Azure Backup Cleanup

Notice: The DryRun parameter is currently set to true. When enabled, no backups will be deleted. Backup deletion will occur only if the DryRun parameter is explicitly set to false.
This code must be tested and its accuracy verified in a non‑production environment prior to any use in a production environment.
This software is provided “as is”, without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non‑infringement. Use of this software is at your own risk, and no guarantee is made regarding functionality, accuracy, or results.


End-to-end deployment of an automated Azure backup cleanup solution.

## DESCRIPTION

This script deploys and configures an Azure-based solution to evaluate and clean up Azure VM backup recovery points stored in a Recovery Services Vault when backups are stopped, disabled, or suspended.
This repo contains a **sanitized** PowerShell deployment script that provisions a backup-cleanup solution in Azure:

- Ensures required Azure resource providers and PowerShell modules are available
- Creates or reuses an Azure Automation Account with a system-assigned managed identity
- Assigns required RBAC permissions for backup management
- Configures Automation variables for cross-subscription Log Analytics logging
- Generates, imports, and publishes an Automation Runbook that:
  - Enumerates Azure VM backup items in a Recovery Services Vault(s)
  - Evaluates recovery points against configurable retention thresholds
  - Logs detailed results to Log Analytics
  - Supports a DryRun mode to simulate deletions without making changes
- Deploys a Logic App (Consumption) that triggers the runbook on a scheduled basis
- Optionally configures email notifications for runbook execution events

The solution is designed for safe operation in regulated or production environments,
with DryRun enabled by default and all destructive actions explicitly controlled.

## NOTES

- This script supports Recovery Services Vaults only.
- Data Protection Backup Vaults are detected and intentionally not modified.
- All environment-specific values must be provided in the VARIABLES section.
- Review and test in a non-production environment before enabling deletions.




> **Important**: This script targets **Recovery Services Vaults** (`Microsoft.RecoveryServices/vaults`). If you point it at a **Data Protection Backup Vault** (`Microsoft.DataProtection/backupVaults`), it will stop with guidance.

## Prerequisites

- PowerShell 7+ recommended
- Az PowerShell modules (the script will attempt to install required modules if missing)
- Permissions to log into Azure via PowerShell
- Permissions to create/update resources in the target subscription(s)
- Permissions to assign Backup Contributor to the Recovery Vault
- Permissions to assign Automation Contributor to the Automation Acocunt
- Permissions to Read and Create Resourcesa Groups
- Permissions to create Managed Identities

## How to use

1. Open `Deploy-BackupCleanup_public_final.ps1`
2. In the **0) VARIABLES (EDIT HERE)** section, replace each placeholder value like `<...>` with values from your environment.
3. Run:

```powershell
./Deploy-BackupCleanup_public_final.ps1
```

## Variable placeholders

In the script, placeholders appear like `<Primary Subscription ID>` or `<Vault Resource Group Name>`. Replace them with real values.

- `PrimarySubscriptionId`: Subscription where the vault/automation/logic app/vnet live.
- `LogAnalyticsSubscriptionId`: Subscription that contains the Log Analytics workspace (can be different).
- `VaultName`: Name of the Recovery Services Vault.
- `VaultResourceGroup`: Resource group of the vault.
- `AutomationAccountName`: Azure Automation account name.
- `AutomationRG`: Resource group for the Automation account.
- `RunbookName`: Runbook name to import/publish.
- `LogAnalyticsResourceGroup`: Resource group for Log Analytics workspace.
- `LogAnalyticsWorkspaceName`: Log Analytics workspace name.
- `LogicAppResourceGroup`: Resource group for the Logic App.
- `LogicAppName`: Logic App name.
- `ScheduleHours` / `ScheduleMinutes`: UTC schedule arrays for Logic App recurrence.
- `NotifyTo`: Array of recipient email addresses for notifications.
- `Location`: Azure region for resource creation (e.g., `eastus`).
- `Office365ConnectionName`: Name of the API connection resource (commonly `office365`).

## Notes

- Email notifications require a one-time **Authorize** action on the Office365 connection in the Azure Portal after deployment.
- The runbook logs to a Log Analytics custom table created by the Data Collector API.

## Disclaimer

This code must be tested and its accuracy verified in a non‑production environment prior to any use in a production environment.
This software is provided “as is”, without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non‑infringement. Use of this software is at your own risk, and no guarantee is made regarding functionality, accuracy, or results.
