<#
.SYNOPSIS
    M365 Security Check - Skript zur Überprüfung von Postfächern auf Sicherheitsrisiken
    (z. B. versteckte Posteingangsregeln, Weiterleitungen etc.)
.DESCRIPTION
    Verbindet sich per App-Only (Client Credentials) mit Microsoft Graph und Exchange Online,
    führt die Sicherheitsprüfungen durch und generiert einen Bericht.
#>

# Parameter oder Umgebungsvariablen (werden idealerweise aus GitHub Secrets übergeben)
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $env:TENANT_ID,

    [Parameter(Mandatory=$false)]
    [string]$ClientId = $env:CLIENT_ID,

    [Parameter(Mandatory=$false)]
    [string]$ClientSecret = $env:CLIENT_SECRET
)

# Überprüfung, ob die Anmeldedaten vorhanden sind
if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
    Write-Error "Fehler: TenantId, ClientId oder ClientSecret wurden nicht übergeben oder sind leer."
    exit 1
}

Write-Host "Starte M365 Sicherheitscheck..." -ForegroundColor Cyan
Write-Host "Verbinde mit Microsoft Graph und Exchange Online..." -ForegroundColor Cyan

# 1. Client Secret in einen SecureString konvertieren und das PSCredential-Objekt erstellen
$SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$ClientCredential = New-Object System.Management.Automation.PSCredential ($ClientId, $SecureSecret)

# 2. Verbindung zu Microsoft Graph herstellen (App-Only / ClientSecretCredential)
try {
    Connect-MgGraph -ClientSecretCredential $ClientCredential -TenantId $TenantId -ErrorAction Stop
    Write-Host "Erfolgreich mit Microsoft Graph verbunden." -ForegroundColor Green
}
catch {
    Write-Error "Fehler bei der Verbindung zu Microsoft Graph: $_"
    exit 1
}

# 3. Verbindung zu Exchange Online herstellen (App-Only)
try {
    Connect-ExchangeOnline -AppId $ClientId -Organization $TenantId -Credential $ClientCredential -ErrorAction Stop
    Write-Host "Erfolgreich mit Exchange Online verbunden." -ForegroundColor Green
}
catch {
    Write-Error "Fehler bei der Verbindung zu Exchange Online: $_"
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    exit 1
}

# ==========================================
# 4. SICHERHEITSPRÜFUNGEN & LOGIK
# ==========================================
Write-Host "Führe Postfach-Analysen durch..." -ForegroundColor Yellow

$Report = [System.Collections.Generic.List[PSCustomObject]]::New()

# Beispiel: Alle Postfächer abrufen und prüfen (anpassbar an deine bisherige Logik)
$Mailboxes = Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited

foreach ($Mailbox in $Mailboxes) {
    Write-Host "Prüfe Postfach: $($Mailbox.UserPrincipalName)" -ForegroundColor DarkCyan

    # Posteingangsregeln prüfen
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
# 5. BERICHT ERSTELLEN & AUFRÄUMEN
# ==========================================
$ReportPath = "./security-report.json"
$Report | ConvertTo-Json -Depth 5 | Out-File -FilePath $ReportPath -Encoding utf8
Write-Host "Bericht erfolgreich unter $ReportPath gespeichert." -ForegroundColor Green

# Verbindungen sauber trennen
Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
Disconnect-MgGraph -ErrorAction SilentlyContinue

Write-Host "Sicherheitscheck abgeschlossen." -ForegroundColor Green
