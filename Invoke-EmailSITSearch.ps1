<#

.SYNOPSIS
- Scans Exchange Online user mailboxes for U.S. Social Security Numbers (SSNs), Credit Card Numbers (CCNs), and U.S. Bank Account Numbers using Microsoft Graph API.
- Applies confidence scoring (High, Medium, Low) based on keyword proximity and regex patterns.
- Exports matches to CSV for review.

.DESCRIPTION
- This script is intended as a forensic and compliance gap solution where Microsoft Purview fails to detect or act on messages AT REST in Exchange Online mailboxes.

Key Features:
- Full mailbox scan for multiple sensitive data types using Microsoft Graph (Mail.ReadWrite scope)
- Regex + contextual keyword scoring to avoid false positives
- CSV export of matches with subject, sender, timestamp, data type, and confidence level

.NOTES
- Use in accordance with your organization's legal and compliance policies. 
- Production-use should incorporate access control, logging, and optional automation hardening.

.AUTHOR
Matthew Silcox
Data Security Architect

#>

#Set function max to account for outdated powershell versions...graph module can easily reach the default limit
$MaximumFunctionCount = 9999

# Check if Microsoft.Graph is installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Output "Microsoft.Graph module not found. Installing..."
    try {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -ErrorAction Stop
        Write-Output "Microsoft.Graph module installed successfully."
    } catch {
        Write-Error "Failed to install Microsoft.Graph module: $_"
        exit
    }
} else {
    Write-Output "Microsoft.Graph module already installed."
}

# Import the module if not already imported
if (-not (Get-Module -Name Microsoft.Graph)) {
    try {
        Write-Output "Importing Microsoft.Graph module, this may take a few minutes..."
        Import-Module Microsoft.Graph -ErrorAction Stop
        Write-Output "Microsoft.Graph module imported successfully."
    } catch {
        Write-Error "Failed to import Microsoft.Graph module: $_"
        exit
    }
} else {
    Write-Output "Microsoft.Graph module already imported."
}

# Tenant and App Registration Details
$tenantId     = ""
$clientId     = ""
$clientSecret = ""

$secureClientSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$clientCredential = New-Object System.Management.Automation.PSCredential($clientId, $secureClientSecret)

Write-Output "Connecting to Graph API..."
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $clientCredential


# DATA TYPE DEFINITIONS

# 1. SSN Patterns
$ssnPatterns = @{
    High   = '\b\d{3}-\d{2}-\d{4}\b'
    Medium = '\b\d{9}\b'
    Low    = '\b\d{3}[\s-.]?\d{2}[\s-.]?\d{4}\b' # Generic pattern for context matching
}
$ssnKeywords = @(
    "SSA Number", "social security number", "social security #", "social security#",
    "social security no", "Social Security#", "Soc Sec", "SSN", "SSNS", "SSN#", "SS#", "SSID"
)

# 2. Credit Card Number (CCN) Patterns
$ccnPatterns = @{
    High   = '\b(?:\d[ -]*?){16}\b'         # Formatted 16-digit cards
    Medium = '\b\d{13,19}\b'               # Any valid length card number, unformatted
    Low    = '\b\d{13,19}\b'               # Low confidence is an unformatted number WITHOUT a keyword
}
$ccnKeywords = @(
    "credit card", "ccn", "card number", "visa", "mastercard", "amex", "discover",
    "expiration", "cvv", "cvc", "card verification"
)

# 3. US Bank Account Patterns
$bankAccountPatterns = @{
    High   = '\b\d{9}\b'       # Routing number is a strong indicator
    Medium = '\b\d{8,17}\b'    # Common account number length
    Low    = '\b\d{8,17}\b'    # Generic pattern for context matching
}
$bankAccountKeywords = @(
    "bank account", "account number", "routing number", "aba", "checking", "savings", "acct #"
)

# DATA TYPE DEFINITIONS


# HELPER FUNCTIONS
function Remove-HtmlTags {
    param ([string]$html)
    return ([regex]::Replace($html, '<[^>]*>', ' '))
}

function Get-MatchContext {
    param (
        [string]$text,
        [string]$pattern,
        [int]$contextLength = 150
    )
    $matches = [regex]::Matches($text, $pattern)
    $contexts = @()
    foreach ($match in $matches) {
        $start = [Math]::Max(0, $match.Index - $contextLength)
        $length = [Math]::Min($contextLength * 2 + $match.Length, $text.Length - $start)
        $contexts += $text.Substring($start, $length).Replace("`r", "").Replace("`n", " ")
    }
    return $contexts -join "`n---`n"
}

# CLASSIFICATION FUNCTION
function Find-SensitiveDataMatches {
    param (
        [string]$text,
        [string]$dataType,
        [array]$keywords,
        [hashtable]$patterns
    )
    
    $foundMatch = $null
    
    # Check for High/Medium confidence (requires keywords)
    $keywordFound = $false
    foreach ($keyword in $keywords) {
        if ($text -match "(?i)\b$keyword\b") {
            $keywordFound = $true
            break
        }
    }

    if ($keywordFound) {
        # Special, more precise logic for Bank Accounts
        if ($dataType -eq "Bank Account") {
            $hasRoutingPattern = $text -match $patterns.High
            $hasAccountPattern = $text -match $patterns.Medium

            if ($hasRoutingPattern -and $hasAccountPattern) {
                # If BOTH are found with a keyword, it's High Confidence.
                $foundMatch = @{ Confidence = "High"; MatchedPattern = $patterns.High }
            } elseif ($hasRoutingPattern -or $hasAccountPattern) {
                # If EITHER is found with a keyword, it's Medium Confidence.
                $matchedPattern = if ($hasRoutingPattern) { $patterns.High } else { $patterns.Medium }
                $foundMatch = @{ Confidence = "Medium"; MatchedPattern = $matchedPattern }
            }
        }
        # Original logic for SSN
        else {
            if ($text -match $patterns.High) {
                $foundMatch = @{ Confidence = "High"; MatchedPattern = $patterns.High }
            } elseif ($text -match $patterns.Medium) {
                $foundMatch = @{ Confidence = "Medium"; MatchedPattern = $patterns.Medium }
            }
        }
    }
    
    # Check for Low confidence (pattern only, no keyword)
    if (-not $foundMatch) {
        if ($dataType -eq "Bank Account") {
            # Low confidence for banks is finding either pattern without a keyword
            if ($text -match $patterns.High -or $text -match $patterns.Medium) {
                $foundMatch = @{ Confidence = "Low"; MatchedPattern = $patterns.Low }
            }
        } else {
            # Original Low confidence for SSN/CCN
            if ($text -match $patterns.Low) {
                $foundMatch = @{ Confidence = "Low"; MatchedPattern = $patterns.Low }
            }
        }
    }
    
    # If any match was found, prepare and return the result object
    if ($foundMatch) {
        $foundMatch.DataType = $dataType
        $foundMatch.ContextPattern = $foundMatch.MatchedPattern 
        return [PSCustomObject]$foundMatch
    }
    
    return $null
}


# MAIN PROCESSING LOGIC

# Collect results
Write-Output "Gathering user mailboxes..."
$users = Get-MgUser -All | Where-Object { $_.Mail -ne $null }
$results = @()

# Define all the sensitive data types to search for
$sensitiveDataTypes = @(
    @{ DataType = "SSN"; Keywords = $ssnKeywords; Patterns = $ssnPatterns }
    @{ DataType = "Credit Card"; Keywords = $ccnKeywords; Patterns = $ccnPatterns }
    @{ DataType = "Bank Account"; Keywords = $bankAccountKeywords; Patterns = $bankAccountPatterns }
)

foreach ($user in $users) {
    Write-Host "Scanning mailbox:" $user.Mail -ForegroundColor Cyan
    try {
        $messages = Get-MgUserMessage -UserId $user.Id -Top 1000 -Select "id,subject,sentDateTime,from"
    } catch {
        Write-Warning "Failed to retrieve messages for $($user.Mail): $_"
        continue
    }

    foreach ($msg in $messages) {
        try {
            $fullMessage = Get-MgUserMessage -UserId $user.Id -MessageId $msg.Id
            $bodyContent = Remove-HtmlTags $fullMessage.Body.Content
        } catch {
            Write-Warning "Failed to retrieve full content for message ID $($msg.Id) in $($user.Mail): $_"
            continue
        }

        # Loop through each data type for each message
        foreach ($type in $sensitiveDataTypes) {
            $matchInfo = Find-SensitiveDataMatches -text $bodyContent -dataType $type.DataType -keywords $type.Keywords -patterns $type.Patterns
            
            if ($matchInfo) {
                $matchContext = Get-MatchContext -text $bodyContent -pattern $matchInfo.ContextPattern
                Write-Host "Match found:" $msg.Subject "- Type:" $matchInfo.DataType "- Confidence:" $matchInfo.Confidence -ForegroundColor Green

                $results += [PSCustomObject]@{
                    Mailbox      = $user.Mail
                    UserId       = $user.Id
                    Subject      = $msg.Subject
                    DataType     = $matchInfo.DataType
                    Confidence   = $matchInfo.Confidence
                    From         = $msg.From.EmailAddress.Address
                    SentDateTime = $msg.SentDateTime
                    MessageId    = $msg.Id
                    MatchPreview = $matchContext
                }
                # Stop checking this message if a match is found to avoid duplicate entries for the same message
                break 
            }
        }
        Start-Sleep -Milliseconds 300
    }
}

# Export to CSV
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$csvPath = ".\\Sensitive_Data_Email_Report_$timestamp.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Report exported to $csvPath" -ForegroundColor Yellow