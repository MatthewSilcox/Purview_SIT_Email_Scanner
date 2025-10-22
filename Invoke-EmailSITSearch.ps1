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

$MaximumFunctionCount = 9999

$tenantId     = ""
$clientId     = ""
$clientSecret = ""
$secureClientSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$clientCredential   = New-Object System.Management.Automation.PSCredential($clientId, $secureClientSecret)
Write-Output "Establishing connection to MS Graph..."
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $clientCredential

# PII & Fin Defs
$ssnPatterns = @{ High='\b\d{3}-\d{2}-\d{4}\b'; Medium='\b\d{9}\b'; Low='\b\d{3}[\s-.]?\d{2}[\s-.]?\d{4}\b' }
$ssnKeywords = @('SSA Number','social security number','social security #','social security#','social security no','Social Security#','Soc Sec','SSN','SSNS','SSN#','SS#','SSID')

$ccnPatterns = @{ High='\b(?:\d[ -]*?){16}\b'; Medium='\b\d{13,19}\b'; Low='\b\d{13,19}\b' }
$ccnKeywords = @('credit card','ccn','card number','visa','mastercard','amex','discover','expiration','cvv','cvc','card verification')

$bankAccountPatterns = @{ High='\b\d{9}\b'; Medium='\b\d{8,17}\b'; Low='\b\d{8,17}\b' }
$bankAccountKeywords = @('bank account','account number','routing number','aba','checking','savings','acct #')

#Credential & Secret defs
$genericSecretKeywords = @('secret','token','key','credential','password','pw','passwd','authorization','bearer','sas','subscription','client id','clientid','client secret','connectionstring','userpass')
$githubPatPatterns = @{ High='gh[pousr]_[A-Za-z0-9]{36}'; Medium='gh\w*_[A-Za-z0-9]{20,}'; Low='gh\w+_[A-Za-z0-9]+' }
$githubPatKeywords  = @('github','pat') + $genericSecretKeywords
$googleApiPatterns  = @{ High='AIza[0-9A-Za-z\-_]{35}'; Medium='AIza[0-9A-Za-z\-_]{20,}'; Low='AIza[0-9A-Za-z\-_]+' }
$googleApiKeywords  = @('google','api') + $genericSecretKeywords
$slackTokenPatterns = @{ High='xox[baprs]-[0-9A-Za-z-]{10,48}'; Medium='xox\w-[0-9A-Za-z-]{8,}'; Low='xox\w-' }
$slackTokenKeywords = @('slack') + $genericSecretKeywords
$azureSasPatterns   = @{ High='sv=\d{4}-\d{2}-\d{2}.*?&sr=[bfqtco].*?&sig=[A-Za-z0-9%+/=]{20,}'; Medium='sig=[A-Za-z0-9%+/=]{20,}'; Low='sv=\d{4}-\d{2}-\d{2}.*sig=' }
$azureSasKeywords   = @('sas','storage','azure','blob','file','queue','table') + $genericSecretKeywords
$azureStorageKeyPatterns = @{ High='(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{86}==(?![A-Za-z0-9+/=])'; Medium='[A-Za-z0-9+/]{40,}={0,2}'; Low='[A-Za-z0-9+/]{20,}' }
$azureStorageKeyKeywords = @('azure','storage','account key') + $genericSecretKeywords
$jwtAuthPatterns = @{ High='Authorization:\s*Bearer\s+eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'; Medium='eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'; Low='Authorization:\s*Bearer\s+' }
$jwtAuthKeywords = @('authorization','bearer','jwt','token') + $genericSecretKeywords
$azureSqlConnPatterns = @{ High='Server=.*\\.database\\.windows\\.net;.*User\s*ID=.*;.*Password=.*;'; Medium='Server=.*\\.database\\.windows\\.net;.*Password='; Low='database\\.windows\\.net;' }
$azureSqlConnKeywords = @('connection','sql','azure','connstr','connection string','db') + $genericSecretKeywords
$genericSecretPatterns = @{ High='(client[_\- ]?secret|api[_\- ]?key|subscription[_\- ]?key)\s*[:=]\s*["'']?[A-Za-z0-9_\-\.]{16,}["'']?'; Medium='(secret|token|key)\s*[:=]\s*["'']?[A-Za-z0-9_\-\.]{12,}["'']?'; Low='(secret|token|key)\s*[:=]\s*["'']' }
$generalPasswordKeywords = @('certutil','curl','powershell','ps1','-u','--env','signtool','winexe','net','rclone','autologon','ldifde','password','passwd','pw','userpass','connectionstring','key','credential','token','sas','securestring','sharedaccesskey','accountkey','dapi')
$generalPasswordPatterns = @{ High=@('(?i)\b(password|passwd|pwd|pw|userpass)\b\s*[:=]\s*["'']?[^\s"'']{8,}["'']?','(?i)\b(-p|--password)\b\s*[:=]?\s*["'']?[^\s"'']{6,}["'']?','(?i)<\s*password\s*>[^<]{6,}<\s*/\s*password\s*>','(?i)\bPassword\s*=\s*[^;"'']{6,};'); Medium=@('(?i)\b(PASSWORD|PASS|PWD|SECRET|TOKEN|KEY)[A-Z0-9_\-]*\s*=\s*["'']?[^\s"'']{8,}["'']?','(?i)<add\s+key=\s*"[^"]*(password|pwd|userpass)[^"]*"\s+value=\s*"[^"]{6,}"\s*/?>','(?i)[A-Za-z0-9+/]{43}={1}','(?i)[A-Za-z0-9+/]{86}==','(?i)[A-Fa-f0-9]{32}'); Low=@('(?i)\b(password|passwd|pwd|pw)\b\s*[:=]\s*[^\s]+') }

# Helpers
function Remove-HtmlTags { param([string]$html) ([regex]::Replace($html,'<[^>]*>',' ')) }
function Normalize-EmailText { param([string]$s) if([string]::IsNullOrWhiteSpace($s)){ return $s }; $s = $s -replace '\u00A0',' '; $s = $s -replace '[\u2010-\u2015]','-'; $s = $s -replace '\u2212','-'; return $s }

function Get-MatchContext { param([string]$text,[object]$pattern,[int]$contextLength=150) $contexts=@(); $patternList=@(); if($pattern -is [array]){ $patternList=$pattern } else { $patternList=@($pattern) } foreach($rx in $patternList){ $ms=[regex]::Matches($text,$rx); foreach($m in $ms){ $s=[Math]::Max(0,$m.Index-$contextLength); $l=[Math]::Min($contextLength*2+$m.Length,$text.Length-$s); $contexts+= $text.Substring($s,$l).Replace("`r",'').Replace("`n",' ') } } return $contexts -join "`n---`n" }

function Test-KeywordProximity { param([string]$text,[System.Text.RegularExpressions.Match]$match,[string[]]$keywords,[int]$window=150) $s=[Math]::Max(0,$match.Index-$window); $l=[Math]::Min($window*2+$match.Length,$text.Length-$s); $slice = $text.Substring($s,$l); foreach($k in $keywords){ if([string]::IsNullOrWhiteSpace($k)){ continue } $rx = "(?i)(?<!\\w)"+[regex]::Escape($k.Trim())+"(?!\\w)"; if($slice -match $rx){ return $true } } return $false }

# PII matcher with proximity
function Find-PIIMatches { param([string]$text,[string]$dataType,[array]$keywords,[hashtable]$patterns)
  $text = Normalize-EmailText $text
  if($patterns.High){ $m=[regex]::Match($text,$patterns.High); if($m.Success -and (Test-KeywordProximity -text $text -match $m -keywords $keywords)){ return [pscustomobject]@{ DataType=$dataType; Confidence='High'; MatchedPattern=$patterns.High; ContextPattern=$patterns.High } } }
  if($patterns.Medium){ $m2=[regex]::Match($text,$patterns.Medium); if($m2.Success -and (Test-KeywordProximity -text $text -match $m2 -keywords $keywords)){ return [pscustomobject]@{ DataType=$dataType; Confidence='Medium'; MatchedPattern=$patterns.Medium; ContextPattern=$patterns.Medium } } }
  if($patterns.Low -and ($text -match $patterns.Low)){ return [pscustomobject]@{ DataType=$dataType; Confidence='Low'; MatchedPattern=$patterns.Low; ContextPattern=$patterns.Low } }
  return $null }

# Credential & secret matcher
function Find-CredentialMatches { param([string]$text,[string]$dataType,[array]$keywords,[hashtable]$patterns) $kw=$false; foreach($k in $keywords){ if([string]::IsNullOrWhiteSpace($k)){continue}; $rx = "(?i)(?<!\\w)"+[regex]::Escape($k.Trim())+"(?!\\w)"; if($text -match $rx){ $kw=$true; break } } $level=$null; $used=$null; if($patterns.ContainsKey('High') -and ($text -match $patterns.High)){ $level='High'; $used=$patterns.High } elseif($patterns.ContainsKey('Medium') -and ($text -match $patterns.Medium)){ $level='Medium'; $used=$patterns.Medium } elseif($patterns.ContainsKey('Low') -and ($text -match $patterns.Low)){ $level='Low'; $used=$patterns.Low } else { return $null } if($level -eq 'High' -and -not $kw){ $level='Medium' } elseif($level -eq 'Medium' -and $kw){ $level='High' } return [pscustomobject]@{ DataType=$dataType; Confidence=$level; MatchedPattern=$used; ContextPattern=$used } }


# Main loop
Write-Output 'Gathering user mailboxes...'
$users = Get-MgUser -All | Where-Object { $_.Mail -ne $null }
$results=@()

$sensitiveDataTypes = @(
  @{ DataType='SSN';            Keywords=$ssnKeywords;             Patterns=$ssnPatterns;             Fn='PII' },
  @{ DataType='Credit Card';    Keywords=$ccnKeywords;             Patterns=$ccnPatterns;             Fn='PII' },
  @{ DataType='Bank Account';   Keywords=$bankAccountKeywords;     Patterns=$bankAccountPatterns;     Fn='PII' },
  @{ DataType='GitHub PAT';                 Keywords=$githubPatKeywords;         Patterns=$githubPatPatterns;         Fn='Cred' },
  @{ DataType='Google API Key';             Keywords=$googleApiKeywords;         Patterns=$googleApiPatterns;         Fn='Cred' },
  @{ DataType='Slack Token';                Keywords=$slackTokenKeywords;        Patterns=$slackTokenPatterns;        Fn='Cred' },
  @{ DataType='Azure Storage SAS';          Keywords=$azureSasKeywords;          Patterns=$azureSasPatterns;          Fn='Cred' },
  @{ DataType='Azure Storage Account Key';  Keywords=$azureStorageKeyKeywords;    Patterns=$azureStorageKeyPatterns;    Fn='Cred' },
  @{ DataType='JWT Bearer Token';           Keywords=$jwtAuthKeywords;           Patterns=$jwtAuthPatterns;           Fn='Cred' },
  @{ DataType='Azure SQL Connection String';Keywords=$azureSqlConnKeywords;       Patterns=$azureSqlConnPatterns;       Fn='Cred' },
  @{ DataType='Generic Client Secret / API Key'; Keywords=$genericSecretKeywords; Patterns=$genericSecretPatterns;      Fn='Cred' },
  @{ DataType='General Password';           Keywords=$generalPasswordKeywords;   Patterns=$generalPasswordPatterns;    Fn='Cred' }
)

foreach($user in $users){
  Write-Host "Scanning mailbox:" $user.Mail -ForegroundColor Cyan
  try { $messages = Get-MgUserMessage -UserId $user.Id -Top 1000 -Select 'id,subject,sentDateTime,from' } catch { Write-Warning "Failed to retrieve messages for $($user.Mail): $_"; continue }

  foreach($msg in $messages){
    try { $fullMessage = Get-MgUserMessage -UserId $user.Id -MessageId $msg.Id; $bodyContent = Remove-HtmlTags $fullMessage.Body.Content; $bodyContent = Normalize-EmailText $bodyContent } catch { Write-Warning "Failed to retrieve full content for message ID $($msg.Id) in $($user.Mail): $_"; continue }

    foreach($type in $sensitiveDataTypes){
      $match = if($type.Fn -eq 'PII'){ Find-PIIMatches -text $bodyContent -dataType $type.DataType -keywords $type.Keywords -patterns $type.Patterns } else { Find-CredentialMatches -text $bodyContent -dataType $type.DataType -keywords $type.Keywords -patterns $type.Patterns }
      if($match){
        $ctx = Get-MatchContext -text $bodyContent -pattern $match.ContextPattern
        Write-Host "Match found:" $msg.Subject "- Type:" $match.DataType "- Confidence:" $match.Confidence -ForegroundColor Green
        $results += [pscustomobject]@{ Mailbox=$user.Mail; UserId=$user.Id; Subject=$msg.Subject; DataType=$match.DataType; Confidence=$match.Confidence; From=$msg.From.EmailAddress.Address; SentDateTime=$msg.SentDateTime; MessageId=$msg.Id; MatchPreview=$ctx }
        break
      }
    }

    Start-Sleep -Milliseconds 300
  }
}

Write-Output "Generating report..."
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$csvPath = ".\\Sensitive_Data_Email_Report_$timestamp.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Report exported to $csvPath" -ForegroundColor Yellow