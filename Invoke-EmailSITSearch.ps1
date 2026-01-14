<#

.SYNOPSIS
- Scans Exchange Online user mailboxes for sensitive information including PII and credentials using Microsoft Graph API.
- Detects: SSN, Credit Cards, Bank Accounts, GitHub PAT, Google API Keys, Slack Tokens, Azure Secrets, JWT Tokens, SQL Connection Strings, Passwords, and more.
- Applies confidence scoring (High, Medium, Low) based on keyword proximity and regex patterns.
- Exports matches to CSV for review.

.DESCRIPTION
- This script is intended as a forensic and compliance gap solution where Microsoft Purview fails to detect or act on messages AT REST in Exchange Online mailboxes.

Key Features:
- Full mailbox scan for multiple sensitive data types using Microsoft Graph (Mail.ReadWrite scope)
- Regex + contextual keyword scoring to avoid false positives
- CSV export of matches with subject, sender, timestamp, data type, and confidence level
- Parallel processing for faster scanning of large environments
- Pagination support for mailboxes with >1000 messages

.PARAMETER ThrottleLimit
Maximum number of parallel threads. Default: 5 (recommended for Graph API throttling)

.PARAMETER SleepMilliseconds
Delay between message processing (in milliseconds). Default: 300

.PARAMETER MaxMessages
Maximum messages per mailbox. Use 0 for unlimited (with pagination). Default: 0

.NOTES
- Use in accordance with your organization's legal and compliance policies.
- Production-use should incorporate access control, logging, and optional automation hardening.
- Requires PowerShell 7+ for parallel processing features

.AUTHOR
Matthew Silcox
Data Security Architect

Personal fork by author speckles0 notes:
The core functionality of this script is the same concept, but is now using pre-compiled regex instead of calculating each time in a loop.
I have also removed the unused and undefined credential data types from this script.

Additional optimizations by Claude Code:
- Parallel processing for multiple mailboxes simultaneously
- Fixed double API call (now fetches body in first request)
- Added pagination support for mailboxes with >1000 messages
- Configurable throttling and parallel execution limits

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int]$ThrottleLimit = 5,

    [Parameter(Mandatory=$false)]
    [int]$SleepMilliseconds = 300,

    [Parameter(Mandatory=$false)]
    [int]$MaxMessages = 0
)


# ============================================================================
# SETUP
# ============================================================================

# Increase function capacity to handle Microsoft Graph SDK (has 6000+ functions)
$MaximumFunctionCount = 8192

# Check if Microsoft Graph SDK is installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Output "Microsoft Graph SDK not found. Installing..."
    try {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Output "Microsoft Graph SDK installed successfully."
    } catch {
        Write-Error "Failed to install Microsoft Graph SDK: $_"
        Write-Error "Please run manually: Install-Module Microsoft.Graph -Scope CurrentUser"
        exit 1
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

# Credential & Secret Definitions (restored from original implementation)
$genericSecretKeywords = @(
    'secret','token','key','credential','password','pw','passwd','authorization','bearer','sas',
    'subscription','client id','clientid','client secret','connectionstring','userpass'
)

$githubPatPatterns = @{
    High   = [regex]'gh[pousr]_[A-Za-z0-9]{36}'
    Medium = [regex]'gh\w*_[A-Za-z0-9]{20,}'
    Low    = [regex]'gh\w+_[A-Za-z0-9]+'
}
$githubPatKeywords = @('github','pat') + $genericSecretKeywords

$googleApiPatterns = @{
    High   = [regex]'AIza[0-9A-Za-z\-_]{35}'
    Medium = [regex]'AIza[0-9A-Za-z\-_]{20,}'
    Low    = [regex]'AIza[0-9A-Za-z\-_]+'
}
$googleApiKeywords = @('google','api') + $genericSecretKeywords

$slackTokenPatterns = @{
    High   = [regex]'xox[baprs]-[0-9A-Za-z-]{10,48}'
    Medium = [regex]'xox\w-[0-9A-Za-z-]{8,}'
    Low    = [regex]'xox\w-'
}
$slackTokenKeywords = @('slack') + $genericSecretKeywords

$azureSasPatterns = @{
    High   = [regex]'sv=\d{4}-\d{2}-\d{2}.*?&sr=[bfqtco].*?&sig=[A-Za-z0-9%+/=]{20,}'
    Medium = [regex]'sig=[A-Za-z0-9%+/=]{20,}'
    Low    = [regex]'sv=\d{4}-\d{2}-\d{2}.*sig='
}
$azureSasKeywords = @('sas','storage','azure','blob','file','queue','table') + $genericSecretKeywords

$azureStorageKeyPatterns = @{
    High   = [regex]'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{86}==(?![A-Za-z0-9+/=])'
    Medium = [regex]'[A-Za-z0-9+/]{40,}={0,2}'
    Low    = [regex]'[A-Za-z0-9+/]{20,}'
}
$azureStorageKeyKeywords = @('azure','storage','account key') + $genericSecretKeywords

$jwtAuthPatterns = @{
    High   = [regex]'Authorization:\s*Bearer\s+eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'
    Medium = [regex]'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'
    Low    = [regex]'Authorization:\s*Bearer\s+'
}
$jwtAuthKeywords = @('authorization','bearer','jwt','token') + $genericSecretKeywords

$azureSqlConnPatterns = @{
    High   = [regex]'Server=.*\.database\.windows\.net;.*User\s*ID=.*;.*Password=.*;'
    Medium = [regex]'Server=.*\.database\.windows\.net;.*Password='
    Low    = [regex]'database\.windows\.net;'
}
$azureSqlConnKeywords = @('connection','sql','azure','connstr','connection string','db') + $genericSecretKeywords

$genericSecretPatterns = @{
    High   = [regex]'(client[_\- ]?secret|api[_\- ]?key|subscription[_\- ]?key)\s*[:=]\s*["'']?[A-Za-z0-9_\-\.]{16,}["'']?'
    Medium = [regex]'(secret|token|key)\s*[:=]\s*["'']?[A-Za-z0-9_\-\.]{12,}["'']?'
    Low    = [regex]'(secret|token|key)\s*[:=]\s*["'']'
}

$generalPasswordKeywords = @(
    'certutil','curl','powershell','ps1','-u','--env','signtool','winexe','net','rclone',
    'autologon','ldifde','password','passwd','pw','userpass','connectionstring','key',
    'credential','token','sas','securestring','sharedaccesskey','accountkey','dapi'
)
$generalPasswordPatterns = @{
    High   = [regex]'(?i)\b(password|passwd|pwd|pw|userpass)\b\s*[:=]\s*["'']?[^\s"'']{8,}["'']?'
    Medium = [regex]'(?i)\b(PASSWORD|PASS|PWD|SECRET|TOKEN|KEY)[A-Z0-9_\-]*\s*=\s*["'']?[^\s"'']{8,}["'']?'
    Low    = [regex]'(?i)\b(password|passwd|pwd|pw)\b\s*[:=]\s*[^\s]+'
}

# Define sensitive data types with pre-compiled keyword patterns

$sensitiveDataTypes = @(
    # PII Types
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
    # Credential Types (restored)
    @{
        DataType = "GitHub PAT"
        Keywords = $githubPatKeywords
        Patterns = $githubPatPatterns
        KeywordPattern = [regex]('(?i)\b(' + (($githubPatKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')
    }
    @{
        DataType = "Google API Key"
        Keywords = $googleApiKeywords
        Patterns = $googleApiPatterns
        KeywordPattern = [regex]('(?i)\b(' + (($googleApiKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')
    }
    @{
        DataType = "Slack Token"
        Keywords = $slackTokenKeywords
        Patterns = $slackTokenPatterns
        KeywordPattern = [regex]('(?i)\b(' + (($slackTokenKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')
    }
    @{
        DataType = "Azure Storage SAS"
        Keywords = $azureSasKeywords
        Patterns = $azureSasPatterns
        KeywordPattern = [regex]('(?i)\b(' + (($azureSasKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')
    }
    @{
        DataType = "Azure Storage Account Key"
        Keywords = $azureStorageKeyKeywords
        Patterns = $azureStorageKeyPatterns
        KeywordPattern = [regex]('(?i)\b(' + (($azureStorageKeyKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')
    }
    @{
        DataType = "JWT Bearer Token"
        Keywords = $jwtAuthKeywords
        Patterns = $jwtAuthPatterns
        KeywordPattern = [regex]('(?i)\b(' + (($jwtAuthKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')
    }
    @{
        DataType = "Azure SQL Connection String"
        Keywords = $azureSqlConnKeywords
        Patterns = $azureSqlConnPatterns
        KeywordPattern = [regex]('(?i)\b(' + (($azureSqlConnKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')
    }
    @{
        DataType = "Generic Client Secret / API Key"
        Keywords = $genericSecretKeywords
        Patterns = $genericSecretPatterns
        KeywordPattern = [regex]('(?i)\b(' + (($genericSecretKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')
    }
    @{
        DataType = "General Password"
        Keywords = $generalPasswordKeywords
        Patterns = $generalPasswordPatterns
        KeywordPattern = [regex]('(?i)\b(' + (($generalPasswordKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b')
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
# MAILBOX PROCESSING FUNCTION
# ============================================================================

function Process-Mailbox {
    param(
        [Parameter(Mandatory=$true)]
        $User,

        [Parameter(Mandatory=$true)]
        $SensitiveDataTypes,

        [Parameter(Mandatory=$true)]
        [int]$SleepMs,

        [Parameter(Mandatory=$true)]
        [int]$MaxMsgs,

        [Parameter(Mandatory=$true)]
        [int]$UserNumber,

        [Parameter(Mandatory=$true)]
        [int]$TotalUsers
    )

    $userResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Host "[$UserNumber/$TotalUsers] Scanning mailbox: $($User.Mail)" -ForegroundColor Cyan

    try {
        # OPTIMIZATION: Fetch body in first request to avoid double API call
        $allMessages = [System.Collections.Generic.List[object]]::new()
        $pageSize = if ($MaxMsgs -gt 0 -and $MaxMsgs -lt 1000) { $MaxMsgs } else { 1000 }

        # Initial fetch with body content included
        $messages = Get-MgUserMessage -UserId $User.Id -Top $pageSize -Select "id,subject,sentDateTime,from,body" -ErrorAction Stop

        if ($messages) {
            $allMessages.AddRange($messages)

            # PAGINATION: Handle mailboxes with >1000 messages
            if ($MaxMsgs -eq 0 -or $allMessages.Count -lt $MaxMsgs) {
                while ($messages -and $messages.'@odata.nextLink') {
                    Write-Host "  Fetching next page of messages..." -ForegroundColor Gray
                    $messages = Get-MgUserMessage -UserId $User.Id -Top $pageSize -Select "id,subject,sentDateTime,from,body" -PageLink $messages.'@odata.nextLink' -ErrorAction Stop

                    if ($messages) {
                        $allMessages.AddRange($messages)

                        # Check if we've hit the max message limit
                        if ($MaxMsgs -gt 0 -and $allMessages.Count -ge $MaxMsgs) {
                            break
                        }
                    }
                }
            }
        }

        $messageCount = $allMessages.Count
        Write-Host "  Processing $messageCount messages..." -ForegroundColor Gray

    } catch {
        Write-Warning "Failed to retrieve messages for $($User.Mail): $_"
        return $userResults
    }

    foreach ($msg in $allMessages) {
        try {
            # Body is already fetched - no second API call needed!
            $bodyContent = Remove-HtmlTags $msg.Body.Content

            # Skip empty messages
            if ([string]::IsNullOrWhiteSpace($bodyContent)) { continue }

        } catch {
            Write-Warning "Failed to process message ID $($msg.Id): $_"
            continue
        }

        # Check each data type
        foreach ($type in $SensitiveDataTypes) {
            $matchInfo = Find-SensitiveDataMatches -text $bodyContent -dataTypeInfo $type

            if ($matchInfo) {
                $matchContext = Get-MatchContext -text $bodyContent -pattern $matchInfo.MatchedPattern
                Write-Host "  Match found: $($matchInfo.DataType) ($($matchInfo.Confidence)) - $($msg.Subject)" -ForegroundColor Green

                $userResults.Add([PSCustomObject]@{
                    Mailbox      = $User.Mail
                    UserId       = $User.Id
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
        if ($SleepMs -gt 0) {
            Start-Sleep -Milliseconds $SleepMs
        }
    }

    return $userResults
}

# ============================================================================
# MAIN PROCESSING LOGIC
# ============================================================================

# Check PowerShell version for parallel support
$psVersion = $PSVersionTable.PSVersion.Major
if ($psVersion -lt 7) {
    Write-Warning "PowerShell 7+ is recommended for parallel processing. Detected version: $psVersion"
    Write-Warning "Script will run in sequential mode. Consider upgrading to PowerShell 7+ for significant performance improvements."
    $useParallel = $false
} else {
    $useParallel = ($ThrottleLimit -gt 1)
}

# Filter usertype as Members to exclude guests/B2B by default
Write-Output "Gathering user mailboxes..."
$users = Get-MgUser -All -Property Mail,Id -Filter "UserType eq 'Member'" | Where-Object { $_.Mail -ne $null }
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

$totalUsers = $users.Count
Write-Output "Found $totalUsers mailboxes to scan"
Write-Output "Throttle limit: $ThrottleLimit parallel threads"
Write-Output "Message delay: $SleepMilliseconds ms"
Write-Output "Max messages per mailbox: $(if ($MaxMessages -eq 0) { 'Unlimited (with pagination)' } else { $MaxMessages })"

if ($useParallel) {
    Write-Host "`nStarting PARALLEL processing with $ThrottleLimit threads..." -ForegroundColor Green

    # Capture functions as scriptblocks before parallel execution
    $removeHtmlTagsFunc = ${function:Remove-HtmlTags}
    $getMatchContextFunc = ${function:Get-MatchContext}
    $findSensitiveDataMatchesFunc = ${function:Find-SensitiveDataMatches}
    $processMailboxFunc = ${function:Process-Mailbox}

    # Parallel processing for PowerShell 7+
    $i = 0
    $userResults = $users | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $user = $_
        $currentIndex = $using:i
        $null = [System.Threading.Interlocked]::Increment([ref]$using:i)

        # Import the function and variables into parallel scope
        $sensitiveDataTypes = $using:sensitiveDataTypes
        $sleepMs = $using:SleepMilliseconds
        $maxMsgs = $using:MaxMessages
        $totalUsers = $using:totalUsers

        # Create function definitions from captured scriptblocks
        New-Item -Path Function: -Name Remove-HtmlTags -Value $using:removeHtmlTagsFunc -Force | Out-Null
        New-Item -Path Function: -Name Get-MatchContext -Value $using:getMatchContextFunc -Force | Out-Null
        New-Item -Path Function: -Name Find-SensitiveDataMatches -Value $using:findSensitiveDataMatchesFunc -Force | Out-Null
        New-Item -Path Function: -Name Process-Mailbox -Value $using:processMailboxFunc -Force | Out-Null

        # Process the mailbox
        $mailboxResults = Process-Mailbox -User $user -SensitiveDataTypes $sensitiveDataTypes `
            -SleepMs $sleepMs -MaxMsgs $maxMsgs -UserNumber $currentIndex -TotalUsers $totalUsers

        # Return results
        return $mailboxResults
    }

    # Collect results from parallel execution
    foreach ($mailboxResults in $userResults) {
        if ($mailboxResults) {
            # Handle both single objects and collections
            if ($mailboxResults -is [System.Collections.IEnumerable] -and $mailboxResults -isnot [string]) {
                foreach ($result in $mailboxResults) {
                    $results.Add($result)
                }
            } else {
                $results.Add($mailboxResults)
            }
        }
    }

} else {
    Write-Host "`nStarting SEQUENTIAL processing..." -ForegroundColor Yellow

    # Sequential processing (fallback for PS 5.1 or ThrottleLimit=1)
    $currentUser = 0
    foreach ($user in $users) {
        $currentUser++

        $mailboxResults = Process-Mailbox -User $user -SensitiveDataTypes $sensitiveDataTypes `
            -SleepMs $SleepMilliseconds -MaxMsgs $MaxMessages -UserNumber $currentUser -TotalUsers $totalUsers

        if ($mailboxResults) {
            foreach ($result in $mailboxResults) {
                $results.Add($result)
            }
        }
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
