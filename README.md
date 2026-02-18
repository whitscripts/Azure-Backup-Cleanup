[README.md](https://github.com/user-attachments/files/25401444/README.md)
# Deploy-BackupCleanup (Public Template)


Notice: The DryRun parameter is currently set to true. When enabled, no backups will be deleted. Backup deletion will occur only if the DryRun parameter is explicitly set to false.
This code must be tested and its accuracy verified in a non‑production environment prior to any use in a production environment.
This software is provided “as is”, without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non‑infringement. Use of this software is at your own risk, and no guarantee is made regarding functionality, accuracy, or results.



This repo contains a **sanitized** PowerShell deployment script that provisions a backup-cleanup solution in Azure:

- Azure Automation Account (creates if missing)
- Imports and publishes a Runbook that evaluates Recovery Services Vault VM backup recovery points and (optionally) deletes out-of-retention points
- Logic App (Consumption) that triggers the runbook on a schedule
- Optional Office 365 connection for email notifications

> **Important**: This script targets **Recovery Services Vaults** (`Microsoft.RecoveryServices/vaults`). If you point it at a **Data Protection Backup Vault** (`Microsoft.DataProtection/backupVaults`), it will stop with guidance.

- NOTE:  Dryrun is set to true. This will not delete backups unless the flag is set to false. Please test and verify working accuracy in a Non-Production Environment before publishing to a Production Environments.
- This is published and free to use without warranty or guarantee of results. 


## Prerequisites

- PowerShell 7+ recommended
- Az PowerShell modules (the script will attempt to install required modules if missing)
- Permissions to create/update resources in the target subscription(s)

## How to use

1. Open `Deploy-BackupCleanup_PUBLIC_NO_INTERNAL_URLS.ps1`
2. In the **0) VARIABLES (EDIT HERE)** section, replace each placeholder value like `<...>` with values from your environment.
3. Run:

```powershell
./Deploy-BackupCleanup_PUBLIC_NO_INTERNAL_URLS.ps1
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

This script is provided as-is. Review it and test in a non-production environment before using it in production.
