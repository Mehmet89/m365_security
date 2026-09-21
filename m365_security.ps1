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
# 5. BERICHT ERSTELLEN & AUFRÄUMEN
# ==========================================
$ReportPath = "./security-report.json"
$Report | ConvertTo-Json -Depth 5 | Out-File -FilePath $ReportPath -Encoding utf8
Write-Host "Bericht erfolgreich unter $ReportPath gespeichert." -ForegroundColor Green

Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
Disconnect-MgGraph -ErrorAction SilentlyContinue

Write-Host "Sicherheitscheck abgeschlossen." -ForegroundColor Green
