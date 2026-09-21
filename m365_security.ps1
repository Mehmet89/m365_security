# ==========================================
# M365 Postfach-Sicherheitscheck (Cloud / Linux optimiert)
# ==========================================

# Umgebungsvariablen aus GitHub Secrets einlesen
$TenantId     = $env:TENANT_ID
$ClientId     = $env:CLIENT_ID
$ClientSecret = $env:CLIENT_SECRET

# Prüfen, ob die Variablen übergeben wurden
if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
    Write-Error "Fehler: Mindestens eine Verbindungsvariable (TENANT_ID, CLIENT_ID, CLIENT_SECRET) fehlt!"
    exit 1
}

Write-Host "Verbinde mit Microsoft Graph und Exchange Online..."

# Module laden (falls nicht im Runner vorinstalliert)
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
}
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
}

# Verbindung via App-Registrierung (Client Credentials Flow für automatisierte Cloud-Ausführung)
Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret (ConvertTo-SecureString $ClientSecret -AsPlainText -Force)
Connect-ExchangeOnline -AppId $ClientId -Organization $TenantId -CertificateThumbprint $null # Alternativ via Secret wenn vom Skript so unterstützt

# Ausgabeverzeichnis für die Berichte definieren
$OutputDir = "./sicherheits-reports"
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$ReportPathHtml = "$OutputDir/sicherheits-report.html"
$ReportPathCsv  = "$OutputDir/sicherheits-report.csv"

Write-Host "Starte Postfach-Analyse..."

# Beispielhafter Array für die Ergebnisse (ersetze dies durch deine Logik)
$results = @()

# Postfächer abrufen und prüfen (Beispiel-Logik an dein Skript anpassen)
$mailboxes = Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox
foreach ($mbx in $mailboxes) {
    $rules = Get-InboxRule -Mailbox $mbx.UserPrincipalName -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
    
    $externalForward = $false
    foreach ($rule in $rules) {
        if ($rule.ForwardTo -or $rule.RedirectTo) {
            $externalForward = $true
        }
    }

    $results += [PSCustomObject]@{
        UserPrincipalName  = $mbx.UserPrincipalName
        Displayname        = $mbx.DisplayName
        ActiveRulesCount   = $rules.Count
        ExternalForward    = $externalForward
    }
}

# CSV Export
$results | Export-Csv -Path $ReportPathCsv -NoTypeInformation -Encoding utf8

# HTML Export erzeugen
$htmlContent = @"
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>M365 Sicherheitsreport</title>
    <style>
        body { font-family: sans-serif; background: #111827; color: #f3f4f6; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #1f2937; }
        th, td { padding: 12px; border: 1px solid #374151; text-align: left; }
        th { background: #374151; }
    </style>
</head>
<body>
    <h1>M365 Postfach-Sicherheitscheck Report</h1>
    <p>Erstellt am: $(Get-Date)</p>
    <table>
        <tr><th>Benutzer</th><th>Aktive Regeln</th><th>Externe Weiterleitung</th></tr>
        $($results | ForEach-Object { "<tr><td>$($_.UserPrincipalName)</td><td>$($_.ActiveRulesCount)</td><td>$($_.ExternalForward)</td></tr>" } -join "`n")
    </table>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $ReportPathHtml -Encoding utf8

Write-Host "Analyse abgeschlossen. Berichte unter $OutputDir gespeichert."
