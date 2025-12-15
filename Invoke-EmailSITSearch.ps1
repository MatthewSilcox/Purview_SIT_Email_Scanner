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

Personal fork by author speckles0 notes:
The core functionality of this script is the same concept, but is now using pre-compiled regex instead of calculating each time in a loop.
I have also removed the unused and undefined credential data types from this script.

#>


# ============================================================================
# SETUP
# ============================================================================

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Output "Microsoft.Graph module not found. Installing..."
    try {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -ErrorAction Stop
        Write-Output "Microsoft.Graph module installed successfully."
    } catch {
        Write-Error "Failed to install Microsoft.Graph module: $_"
        exit
    }
}

if (-not (Get-Module -Name Microsoft.Graph)) {
    try {
        Write-Output "Importing Microsoft.Graph module..."
        Import-Module Microsoft.Graph -ErrorAction Stop
        Write-Output "Microsoft.Graph module imported successfully."
    } catch {
        Write-Error "Failed to import Microsoft.Graph module: $_"
        exit
    }
}

# ============================================================================
# AUTHENTICATION
# ============================================================================

$tenantId     = ""
$clientId     = ""
$clientSecret = ""

$secureClientSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$clientCredential   = New-Object System.Management.Automation.PSCredential($clientId, $secureClientSecret)
Write-Output "Establishing connection to MS Graph..."
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $clientCredential

# ============================================================================
# DATA TYPE DEFINITIONS
# ============================================================================

# Pre-compiled regex patterns for better performance

$ssnPatterns = @{
    High   = [regex]'\b\d{3}-\d{2}-\d{4}\b'
    Medium = [regex]'\b\d{9}\b'
    Low    = [regex]'\b\d{3}[\s-.]?\d{2}[\s-.]?\d{4}\b'
}
$ssnKeywords = @(
    "SSA Number", "social security number", "social security #", "social security#",
    "social security no", "Social Security#", "Soc Sec", "SSN", "SSNS", "SSN#", "SS#", "SSID"
)

$ccnPatterns = @{
    High   = [regex]'\b(?:\d[ -]*?){16}\b'
    Medium = [regex]'\b\d{13,19}\b'
    Low    = [regex]'\b\d{13,19}\b'
}
$ccnKeywords = @(
    "credit card", "ccn", "card number", "visa", "mastercard", "amex", "discover",
    "expiration", "cvv", "cvc", "card verification"
)

$bankAccountPatterns = @{
    High   = [regex]'\b\d{9}\b'
    Medium = [regex]'\b\d{8,17}\b'
    Low    = [regex]'\b\d{8,17}\b'
}
$bankAccountKeywords = @(
    "bank account", "account number", "routing number", "aba", "checking", "savings", "acct #"
)

# Define sensitive data types with pre-compiled keyword patterns

$sensitiveDataTypes = @(
    @{ 
        DataType = "SSN"
        Keywords = $ssnKeywords
        Patterns = $ssnPatterns
        KeywordPattern = [regex]('(?i)\b(' + (($ssnKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')
    }
    @{ 
        DataType = "Credit Card"
        Keywords = $ccnKeywords
        Patterns = $ccnPatterns
        KeywordPattern = [regex]('(?i)\b(' + (($ccnKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')
    }
    @{ 
        DataType = "Bank Account"
        Keywords = $bankAccountKeywords
        Patterns = $bankAccountPatterns
        KeywordPattern = [regex]('(?i)\b(' + (($bankAccountKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')
    }
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Remove-HtmlTags {
    param ([string]$html)
    if ([string]::IsNullOrWhiteSpace($html)) { return '' }
    
    # Static regex for better performance
    return ([regex]::Replace($html, '<[^>]*>', ' '))
}

function Get-MatchContext {
    param (
        [string]$text,
        [regex]$pattern,
        [int]$contextLength = 150
    )
    
    if ([string]::IsNullOrWhiteSpace($text)) { return '' }
    
    $matches = $pattern.Matches($text)
    if ($matches.Count -eq 0) { return '' }
    
    $contexts = [System.Collections.Generic.List[string]]::new($matches.Count)
    
    foreach ($match in $matches) {
        $start = [Math]::Max(0, $match.Index - $contextLength)
        $end = [Math]::Min($text.Length, $match.Index + $match.Length + $contextLength)
        $length = $end - $start
        $context = $text.Substring($start, $length) -replace '[\r\n]+', ' '
        $contexts.Add($context)
    }
    
    return $contexts -join "`n---`n"
}

# ============================================================================
# CLASSIFICATION FUNCTION
# ============================================================================

function Find-SensitiveDataMatches {
    param (
        [string]$text,
        [hashtable]$dataTypeInfo
    )
    
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    
    $dataType = $dataTypeInfo.DataType
    $keywordPattern = $dataTypeInfo.KeywordPattern
    $patterns = $dataTypeInfo.Patterns
    
    # Single keyword check using pre-compiled regex (for performance)

    $keywordFound = $keywordPattern.IsMatch($text)
    
    # Cache all pattern matches upfront (for performance)

    $highMatch = $patterns.High.IsMatch($text)
    $mediumMatch = $patterns.Medium.IsMatch($text)
    
    $foundMatch = $null
    
    if ($keywordFound) {
        if ($dataType -eq "Bank Account") {
            if ($highMatch -and $mediumMatch) {
                $foundMatch = @{ 
                    Confidence = "High"
                    MatchedPattern = $patterns.High
                }
            }
            elseif ($highMatch -or $mediumMatch) {
                $foundMatch = @{ 
                    Confidence = "Medium"
                    MatchedPattern = if ($highMatch) { $patterns.High } else { $patterns.Medium }
                }
            }
        }
        else {
            if ($highMatch) {
                $foundMatch = @{ 
                    Confidence = "High"
                    MatchedPattern = $patterns.High
                }
            }
            elseif ($mediumMatch) {
                $foundMatch = @{ 
                    Confidence = "Medium"
                    MatchedPattern = $patterns.Medium
                }
            }
        }
    }
    
    # Low confidence check (pattern without keyword)
    if (-not $foundMatch) {
        if ($dataType -eq "Bank Account") {
            if ($highMatch -or $mediumMatch) {
                $foundMatch = @{ 
                    Confidence = "Low"
                    MatchedPattern = $patterns.Low
                }
            }
        }
        else {
            # Only check Low pattern if we haven't already checked it
            $lowMatch = if ($patterns.Low -eq $patterns.Medium) { $mediumMatch } else { $patterns.Low.IsMatch($text) }
            if ($lowMatch) {
                $foundMatch = @{ 
                    Confidence = "Low"
                    MatchedPattern = $patterns.Low
                }
            }
        }
    }
    
    if ($foundMatch) {
        return [PSCustomObject]@{
            DataType = $dataType
            Confidence = $foundMatch.Confidence
            MatchedPattern = $foundMatch.MatchedPattern
        }
    }
    
    return $null
}

# ============================================================================
# MAIN PROCESSING LOGIC
# ============================================================================

# Filter usertype as Members to exclude guests/B2B by default

Write-Output "Gathering user mailboxes..."
$users = Get-MgUser -All -Property Mail,Id -Filter "UserType eq 'Member'"| Where-Object { $_.Mail -ne $null }
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

$totalUsers = $users.Count
$currentUser = 0

foreach ($user in $users) {
    $currentUser++
    Write-Host "[$currentUser/$totalUsers] Scanning mailbox: $($user.Mail)" -ForegroundColor Cyan
    
    try {
        $messages = Get-MgUserMessage -UserId $user.Id -Top 1000 -Select "id,subject,sentDateTime,from" -ErrorAction Stop

    } catch {
        Write-Warning "Failed to retrieve messages for $($user.Mail): $_"
        continue
    }

    $messageCount = $messages.Count
    Write-Host "  Processing $messageCount messages..." -ForegroundColor Gray

    foreach ($msg in $messages) {
        try {
            $fullMessage = Get-MgUserMessage -UserId $user.Id -MessageId $msg.Id -ErrorAction Stop
            $bodyContent = Remove-HtmlTags $fullMessage.Body.Content
            $bodyContent.Trim()
            
            # Skip empty messages
            if ([string]::IsNullOrWhiteSpace($bodyContent)) { continue }
            
        } catch {
            Write-Warning "Failed to retrieve content for message ID $($msg.Id): $_"
            continue
        }

        # Check each data type
        foreach ($type in $sensitiveDataTypes) {
            $matchInfo = Find-SensitiveDataMatches -text $bodyContent -dataTypeInfo $type
            
            if ($matchInfo) {
                $matchContext = Get-MatchContext -text $bodyContent -pattern $matchInfo.MatchedPattern
                Write-Host "  Match found: $($matchInfo.DataType) ($($matchInfo.Confidence)) - $($msg.Subject)" -ForegroundColor Green

                $results.Add([PSCustomObject]@{
                    Mailbox      = $user.Mail
                    UserId       = $user.Id
                    Subject      = $msg.Subject
                    DataType     = $matchInfo.DataType
                    Confidence   = $matchInfo.Confidence
                    From         = $msg.From.EmailAddress.Address
                    SentDateTime = $msg.SentDateTime
                    MessageId    = $msg.Id
                    MatchPreview = $matchContext
                })
                
                # Stop checking this message to avoid duplicates
                break 
            }
        }
        
        # Throttle to respect API limits
        Start-Sleep -Milliseconds 300
    }
}

# ============================================================================
# EXPORT RESULTS
# ============================================================================

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$csvPath = ".\Sensitive_Data_Email_Report_$timestamp.csv"

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "`nReport exported to $csvPath" -ForegroundColor Yellow
    Write-Host "Total matches found: $($results.Count)" -ForegroundColor Green
} else {
    Write-Host "`nNo sensitive data matches found." -ForegroundColor Yellow
}

Write-Host "`nScan complete!" -ForegroundColor Cyan
