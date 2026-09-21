<#
.SYNOPSIS
    M365 Security Check - Skript zur Überprüfung von Postfächern auf Sicherheitsrisiken
.DESCRIPTION
    Verbindet sich per App-Only mit Microsoft Graph und Exchange Online.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = $env:TENANT_ID,

    [Parameter(Mandatory=$false)]
    [string]$ClientId = $env:CLIENT_ID,

    [Parameter(Mandatory=$false)]
    [string]$ClientSecret = $env:CLIENT_SECRET
)

# Überprüfung der Anmeldedaten
if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
    Write-Error "Fehler: TenantId, ClientId oder ClientSecret wurden nicht übergeben oder sind leer."
    exit 1
}

Write-Host "Starte M365 Sicherheitscheck..." -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Module prüfen und installieren / laden
# ---------------------------------------------------------------------------
Write-Host "Überprüfe benötigte PowerShell-Module..." -ForegroundColor Cyan

# Microsoft.Graph prüfen
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Host "Installiere Microsoft.Graph Modul..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
}

# ExchangeOnlineManagement prüfen
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Host "Installiere ExchangeOnlineManagement Modul..." -ForegroundColor Yellow
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
}

Import-Module Microsoft.Graph -ErrorAction Stop
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# ---------------------------------------------------------------------------
# 2. Verbindung zu Microsoft Graph herstellen
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
# 3. Verbindung zu Exchange Online herstellen (App-Only für Exchange)
# ---------------------------------------------------------------------------
Write-Host "Verbinde mit Exchange Online..." -ForegroundColor Cyan
try {
    # Für Exchange Online App-Only wird das Secret direkt als SecureString übergeben
    Connect-ExchangeOnline -AppId $ClientId -Organization $TenantId -ClientSecret $SecureSecret -ErrorAction Stop
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
# 5. BERICHT ERSTELLEN & AUFRÄUMEN
# ==========================================
$ReportPath = "./security-report.json"
$Report | ConvertTo-Json -Depth 5 | Out-File -FilePath $ReportPath -Encoding utf8
Write-Host "Bericht erfolgreich unter $ReportPath gespeichert." -ForegroundColor Green

# Verbindungen sauber trennen
Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
Disconnect-MgGraph -ErrorAction SilentlyContinue

Write-Host "Sicherheitscheck abgeschlossen." -ForegroundColor Green
