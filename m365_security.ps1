<#
.SYNOPSIS
    M365 Security Check - Skript zur Überprüfung von Postfächern auf Sicherheitsrisiken
.DESCRIPTION
    Verbindet sich per App-Only mit Microsoft Graph (per Client Secret) und Exchange Online (per Zertifikat).
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $env:TENANT_ID,

    [Parameter(Mandatory=$false)]
    [string]$ClientId = $env:CLIENT_ID,

    [Parameter(Mandatory=$false)]
    [string]$ClientSecret = $env:CLIENT_SECRET,

    [Parameter(Mandatory=$false)]
    [string]$CertBase64 = $env:AZURE_CERT_BASE64,

    [Parameter(Mandatory=$false)]
    [string]$CertPassword = $env:AZURE_CERT_PASSWORD,

    [Parameter(Mandatory=$false)]
    [string]$M365Domain = $env:M365_DOMAIN
)

# Überprüfung, ob alle notwendigen Variablen vorhanden sind
if (-not $TenantId -or -not $ClientId -or -not $ClientSecret -or -not $CertBase64 -or -not $CertPassword -or -not $M365Domain) {
    Write-Error "Fehler: Mindestens eine der erforderlichen Umgebungsvariablen fehlt."
    exit 1
}

Write-Host "Starte M365 Sicherheitscheck..." -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Module prüfen und laden
# ---------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
}

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
}

Import-Module Microsoft.Graph -ErrorAction Stop
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# ---------------------------------------------------------------------------
# 2. Verbindung zu Microsoft Graph herstellen (mit Client Secret)
# ---------------------------------------------------------------------------
Write-Host "Verbinde mit Microsoft Graph..." -ForegroundColor Cyan
$SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$ClientCredential = New-Object System.Management.Automation.PSCredential ($ClientId, $SecureSecret)

try {
    Connect-MgGraph -ClientSecretCredential $ClientCredential -TenantId $TenantId -ErrorAction Stop
    Write-Host "Erfolgreich mit Microsoft Graph verbunden." -ForegroundColor Green
}
catch {
    Write-Error "Fehler bei der Verbindung zu Microsoft Graph: $_"
    exit 1
}

# ---------------------------------------------------------------------------
# 3. Verbindung zu Exchange Online herstellen (mit Zertifikat & Domain)
# ---------------------------------------------------------------------------
Write-Host "Verbinde mit Exchange Online (per Zertifikat)..." -ForegroundColor Cyan
$tempCertPath = $null

try {
    $certBytes = [System.Convert]::FromBase64String($CertBase64)
    $tempCertPath = [System.IO.Path]::GetTempFileName() + ".pfx"
    [System.IO.File]::WriteAllBytes($tempCertPath, $certBytes)
    
    $securePassword = ConvertTo-SecureString $CertPassword -AsPlainText -Force
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tempCertPath, $securePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

    Connect-ExchangeOnline -AppId $ClientId -Organization $M365Domain -Certificate $certificate -ErrorAction Stop
    Write-Host "Erfolgreich mit Exchange Online verbunden." -ForegroundColor Green
}
catch {
    Write-Error "Fehler bei der Verbindung zu Exchange Online: $_"
    if ($tempCertPath -and (Test-Path $tempCertPath)) { Remove-Item $tempCertPath -Force }
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    exit 1
}
finally {
    if ($tempCertPath -and (Test-Path $tempCertPath)) { Remove-Item $tempCertPath -Force }
}

# ==========================================
# 4. SICHERHEITSPRÜFUNGEN & LOGIK
# ==========================================
Write-Host "Führe Postfach-Analysen durch..." -ForegroundColor Yellow

$Report = [System.Collections.Generic.List[PSCustomObject]]::New()
$Mailboxes = Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited

foreach ($Mailbox in $Mailboxes) {
    Write-Host "Prüfe Postfach: $($Mailbox.UserPrincipalName)" -ForegroundColor DarkCyan

    $Rules = Get-InboxRule -Mailbox $Mailbox.UserPrincipalName -ErrorAction SilentlyContinue
    foreach ($Rule in $Rules) {
        if ($Rule.ForwardTo -or $Rule.ForwardAsAttachmentTo -or $Rule.RedirectTo) {
            $Report.Add([PSCustomObject]@{
                UserPrincipalName = $Mailbox.UserPrincipalName
                RuleName          = $Rule.Name
                RiskType          = "Externe Weiterleitung / Regel"
                Details           = "Regel leitet Mails weiter an: $($Rule.ForwardTo -join ', ')"
            })
        }
    }
}

# ==========================================
# 5. HTML-BERICHT ERSTELLEN & AUFRÄUMEN
# ==========================================
$ReportPath = "./security-report.html"

# HTML-Gerüst aufbauen
$HtmlContent = @"
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>M365 Security Check Report</title>
    <style>
        :root {
            --primary-color: #003366;
            --accent-color: #0078d4;
            --text-color: #333333;
            --bg-light: #f8f9fa;
            --border-color: #dddddd;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            max-width: 1000px;
            margin: 0 auto;
            padding: 40px 20px;
            background-color: #f4f6f8;
        }
        .container {
            background: #ffffff;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        }
        header {
            border-bottom: 3px solid var(--primary-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .logo-area {
            font-size: 1.1rem;
            font-weight: bold;
            color: var(--primary-color);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 5px;
        }
        h1 {
            color: var(--primary-color);
            font-size: 2rem;
            margin: 0 0 10px 0;
        }
        .meta-info {
            font-size: 0.95rem;
            color: #666;
        }
        h2 {
            color: var(--primary-color);
            border-left: 4px solid var(--accent-color);
            padding-left: 12px;
            margin-top: 30px;
            font-size: 1.3rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            margin-bottom: 25px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.95rem;
        }
        th {
            background-color: var(--bg-light);
            color: var(--primary-color);
            font-weight: 600;
        }
        tr:hover {
            background-color: #f9fbfd;
        }
        .no-findings {
            padding: 20px;
            background-color: #e6f4ea;
            color: #137333;
            border-radius: 6px;
            font-weight: 500;
            margin-top: 20px;
        }
        .footer-note {
            margin-top: 40px;
            font-size: 0.85rem;
            color: #777;
            text-align: center;
            border-top: 1px solid var(--border-color);
            padding-top: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-area">bits+bytes &bull; Security Operations</div>
            <h1>M365 Security Check Report</h1>
            <div class="meta-info">Erstellungsdatum: $(Get-Date -Format "dd.MM.yyyy HH:mm:ss") Uhr</div>
        </header>
        
        <h2>Gefundene Weiterleitungen & Regeln</h2>
"@

if ($Report.Count -eq 0) {
    $HtmlContent += @"
        <div class="no-findings">
            &check; Keine verdächtigen Weiterleitungen oder Postfachregeln in den geprüften Postfächern gefunden.
        </div>
"@
} else {
    $HtmlContent += @"
        <table>
            <thead>
                <tr>
                    <th>Postfach (UPN)</th>
                    <th>Regel-Name</th>
                    <th>Risikotyp</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($Item in $Report) {
        $HtmlContent += "<tr><td>$($Item.UserPrincipalName)</td><td>$($Item.RuleName)</td><td>$($Item.RiskType)</td><td>$($Item.Details)</td></tr>"
    }

    $HtmlContent += @"
            </tbody>
        </table>
"@
}

# Korrektur hier: $((Get-Date).Year) statt $(Get-Date -Year)
$HtmlContent += @"
        <div class="footer-note">
            &copy; $((Get-Date).Year) bits+bytes Computer GmbH & Co. KG &bull; Automatisiert generierter Bericht via GitHub Actions
        </div>
    </div>
</body>
</html>
"@

$HtmlContent | Out-File -FilePath $ReportPath -Encoding utf8
Write-Host "HTML-Bericht erfolgreich unter $ReportPath gespeichert." -ForegroundColor Green

Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
Disconnect-MgGraph -ErrorAction SilentlyContinue

Write-Host "Sicherheitscheck abgeschlossen." -ForegroundColor Green
