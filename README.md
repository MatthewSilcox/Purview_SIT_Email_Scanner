# SSN_Email_Scanner

## Overview
This PowerShell script scans Exchange Online user mailboxes for U.S. Social Security Numbers (SSNs) using the Microsoft Graph API. It applies confidence scoring based on contextual keyword proximity and regex patterns, exports results to a CSV for review, and provides optional deletion capabilities.

## Features
- Uses Microsoft Graph API with app-only (client credential) authentication
- Detects SSNs using regex and confidence scoring
- Extracts and displays matching context from email bodies
- Cleans HTML tags for better readability
- Exports findings to CSV
- Optional reviewed deletion logic with confirmation prompts

## Requirements
- PowerShell 7+
- Microsoft.Graph PowerShell module

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

## App Registration Setup (Microsoft Entra ID)
1. Sign into Azure Portal: https://portal.azure.com
2. Go to **Microsoft Entra ID > App registrations** > **New registration**
   - Name: `SSN Mailbox Scanner`
   - Supported account types: Single tenant (default)
3. After creation, go to **Certificates & secrets**
   - Select **Client secrets** > **New client secret**
   - Copy the value. This will be used as `$clientSecret`
4. Go to **API permissions** > **Add a permission** > **Microsoft Graph** > **Application permissions**
   - Add:
     - `Mail.ReadWrite`
     - `User.Read.All`
   - Click **Grant admin consent**

## Configuration
Set the following variables in your script:
```powershell
$tenantId     = "<YOUR TENANT ID>"
$clientId     = "<YOUR APP (CLIENT) ID>"
$clientSecret = "<YOUR CLIENT SECRET>"
```

## Execution
### 1. Scan Mailboxes for SSNs
- The script connects to Microsoft Graph and scans all users with valid mailboxes
- Matches are scored as `High`, `Medium`, or `Low` confidence
- Each match includes a snippet of matching context from the email body

```powershell
.\Invoke-EmailSITSearch.ps1
```

### 2. Review CSV Results
- Open the generated CSV file (e.g., `SSN_Email_Report_20250418-113000.csv`)
- Remove any false positives manually
- Save as `Reviewed_SSN_Results.csv`

### 3. Run Deletion Script (Optional)
- Use the deletion script to selectively or automatically delete matched emails

```powershell
Invoke-EmailSSNDeletion -ReviewedCsvPath '.\SSN_Email_Report_20250418-113000.csv'
```

---
Use responsibly, WITH EXTREME CAUTION, and only within environments where you are authorized to perform mailbox searches and deletions. Align with legal and compliance requirements at all times.
