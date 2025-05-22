# -------------------- Tenant Configuration --------------------
$tenantId         = "<your-tenant-id>"  # e.g. "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# -------------------- Sentinel Configuration --------------------
$subscriptionId   = "<your-subscription-id>"  # e.g. "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$resourceGroup    = "<your-resource-group-name>"  # e.g. "rg-sentinel-logs"
$workspaceName    = "<your-log-analytics-workspace-name>"  # e.g. "la-sentinel"

# -------------------- OpenAI Configuration --------------------
$openaiApiKey     = "<your-azure-openai-api-key>"  # Create from Azure OpenAI resource
$openaiDeployment = "<your-deployment-name>"       # e.g. "gpt-4o-mini"
$openaiEndpoint   = "<your-endpoint-url>"          # e.g. "https://your-resource-name.openai.azure.com"
$openaiApiVersion = "2024-03-01-preview"           # Use appropriate version
$openaiUri        = "$openaiEndpoint/openai/deployments/$openaiDeployment/chat/completions?api-version=$openaiApiVersion"

# -------------------- Detection Configuration --------------------
$increaseFactor   = 1.2    # Thresholds factor for anomaly, e.g. 1.2 means 20% increase

# -------------------- Initialize --------------------
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"

# -------------------- Email Notification Configuration --------------------
$smtpServer       = "<your-smtp-server>"           # e.g. "smtp.yourdomain.com"
$smtpPort         = 587                            # Common ports: 587 (TLS), 25, 465 (SSL)
$smtpUseSsl       = $true                          # $true or $false depending on server requirements

$smtpUsername     = "<your-smtp-username>"         # Leave blank for anonymous (e.g. "noreply@yourdomain.com")
$smtpPassword     = "<your-smtp-password>"         # Leave blank for anonymous

$emailFrom        = "<your-from-address>"          # e.g. "sentinel-alerts@yourdomain.com"
$emailTo          = "<recipient-address>"          # e.g. "security-team@yourdomain.com"
$emailSubject     = "ALERT: Sentinel Log Events Anomaly Detected - $timestamp"


# -------------------- File Output --------------------
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$deepDiveFile = "SentinelAnomalyDeepDive-$timestamp.txt"

Write-Host ""
Write-Host "🛡️  Sentinel Log Events Anomaly Detector (AI)" -ForegroundColor Cyan
Write-Host "🛠️  Created by Morten Knudsen, Microsoft MVP (Azure/Security)" -ForegroundColor Cyan
Write-Host ""


# -------------------- Azure Connection --------------------
    # Check existing context
    $currentContext = Get-AzContext

    if (-not $currentContext -or
        $currentContext.Tenant.Id -ne $tenantId -or
        $currentContext.Subscription.Id -ne $subscriptionId) {

        Write-Host "🔐 Connecting to Azure..." -ForegroundColor Cyan
        Connect-AzAccount -TenantId $tenantId -SubscriptionId $subscriptionId
    } else {
        Write-Host "✅ Azure session already active for correct tenant and subscription." -ForegroundColor Green
    }

    $workspaceId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroup -Name $workspaceName).CustomerId

# -------------------- HELPER: LOG ANALYTICS QUERY --------------------
function Query-LogAnalytics {
    param($query)

    $secureToken = (Get-AzAccessToken -ResourceUrl "https://api.loganalytics.io/").Token
    $token = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    )
    $headers = @{ Authorization = "Bearer $token" }
    $uri = "https://api.loganalytics.io/v1/workspaces/$workspaceId/query"
    $body = @{ query = $query } | ConvertTo-Json -Depth 5

    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $body -ContentType "application/json"
    return $response.tables[0].rows
}

# -------------------- 1. Anomaly Detection --------------------
Write-Host "🔍 Running anomaly detection query..." -ForegroundColor Cyan

$queryAnomalies = @"
let increaseFactor = $increaseFactor;
SecurityEvent
| where TimeGenerated > ago(60m)
| summarize TotalEvents = count() by Computer, EventID
| join kind=inner (
    SecurityEvent
    | where TimeGenerated between (ago(7d)..ago(1h))
    | summarize HourlyCount = count() by bin(TimeGenerated, 1h), Computer, EventID
    | summarize AvgPerHourLastWeek = avg(HourlyCount) by Computer, EventID
) on Computer, EventID
| extend AvgPerHour = toint(AvgPerHourLastWeek), Threshold = toint(AvgPerHourLastWeek * increaseFactor)
| where TotalEvents > Threshold
| project Timestamp=now(), Computer, EventID, TotalEvents, AvgPerHour, Threshold
"@

$anomalies = Query-LogAnalytics -query $queryAnomalies

# Sort and select top anomalies
$topAnomalies = $anomalies | Sort-Object { [int]($_[3]) } -Descending | Select-Object -First 5
if ($topAnomalies.Count -gt 0 -and $topAnomalies[0] -isnot [object[]]) {
    $topAnomalies = ,$topAnomalies
}
$anomalyCount = @($topAnomalies).Count

if ($anomalyCount -eq 0) {
    Write-Host "❗ No anomalies detected in the last 24 hours." -ForegroundColor Yellow
    exit
} else {
    Write-Host "✅ Detected $anomalyCount anomaly event(s)." -ForegroundColor Green
}

# -------------------- 2. Build Filter --------------------
Write-Host "🔧 Building filter for raw event query..." -ForegroundColor Cyan

$eventFilters = $topAnomalies | ForEach-Object {
    $computer = $_[1]
    $eventId = $_[2]
    $computerEscaped = $computer -replace "'", "''"
    "(EventID == $eventId and Computer == '$computerEscaped')"
}
$filterClause = $eventFilters -join " or "

# -------------------- 3. Query Raw Events --------------------
Write-Host "📥 Querying sample events from SecurityEvent..." -ForegroundColor Cyan

$sampleQuery = @"
SecurityEvent
| where TimeGenerated > ago(24h)
| where $filterClause
| project TimeGenerated, EventID, Computer, Account, EventSourceName, EventData, Activity, Process, TargetUser, EventLevelName, SourceComputerId, SystemUserId, TargetAccount, LogonProcessName, LogonGuid, IpAddress
| take 1000
"@

$sampleEvents = Query-LogAnalytics -query $sampleQuery

# -------------------- 4. Build AI Prompt --------------------
Write-Host "🤖 Preparing prompt for OpenAI..." -ForegroundColor Cyan

$sb = [System.Text.StringBuilder]::new()
$null = $sb.AppendLine(@"
You work in IT and are responsible for cost optimization and security event anomaly detection.

Below are 1000 recent logs related to anomalies from Sentinel.

Please:
- Explain what’s happening
- Identify possible misconfigurations, compromise, or abuse
- Recommend per-server actions (no generic advice)
- Detect patterns like known usernames or processes causing issues
- summarize each of the top events in the response
"@)

foreach ($row in $sampleEvents) {
    $null = $sb.AppendLine("[$($row[0])] EventID: $($row[1]), Computer: $($row[2]), Account: $($row[3]), LogonType: $($row[4]), Command: $($row[6])")
}
$samplePrompt = $sb.ToString()

# -------------------- 5. Analyze with GPT (with Spinner) --------------------
function Analyze-WithGPT {
    param([string]$prompt)

    Write-Host "🚀 Sending prompt to OpenAI..." -ForegroundColor Cyan

    $body = @{
        messages = @(
            @{ role = "system"; content = "You are a cybersecurity analyst." },
            @{ role = "user"; content = $prompt }
        )
        temperature = 0.3
        max_tokens = 1000
    } | ConvertTo-Json -Depth 3

    $headers = @{ "api-key" = $openaiApiKey; "Content-Type" = "application/json" }

    $job = Start-Job -ScriptBlock {
        param($uri, $headers, $body)
        Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $body
    } -ArgumentList $openaiUri, $headers, $body

    $spinner = @("|", "/", "-", "\\")
    $i = 0
    while ($job.State -eq 'Running') {
        Write-Host -NoNewline "`r🧠 Analyzing with AI $($spinner[$i % $spinner.Length])"
        Start-Sleep -Milliseconds 100
        $i++
    }

    Write-Host "`r🧠 Analyzing with AI done.     "
    $result = Receive-Job $job
    Remove-Job $job

    return $result.choices[0].message.content
}

$response = Analyze-WithGPT -prompt $samplePrompt

# -------------------- 6. Output + Email --------------------
$response | Out-File -FilePath $deepDiveFile -Encoding utf8
Write-Host "`n--- AI Response ---`n" -ForegroundColor Cyan
$response -split "`n" | ForEach-Object { Write-Host $_ }

# Email (if configured)
if ($emailTo -and $smtpServer) {
    Write-Host "📧 Sending report to $emailTo..." -ForegroundColor Cyan

    $smtpParams = @{
        SmtpServer  = $smtpServer
        Port        = $smtpPort
        UseSsl      = $smtpUseSsl
        From        = $emailFrom
        To          = $emailTo
        Subject     = $emailSubject
        Body        = $response
    }

    if ($smtpUsername -and $smtpPassword) {
        $smtpParams.Credential = New-Object System.Management.Automation.PSCredential($smtpUsername, (ConvertTo-SecureString $smtpPassword -AsPlainText -Force))
    }

    Send-MailMessage @smtpParams 3>$null
    Write-Host "✅ Email sent." -ForegroundColor Green
}
