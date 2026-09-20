<#
.SYNOPSIS
    Postfach-Sicherheitscheck v7.6 - PS2EXE / Windows PowerShell 5.1 + PowerShell-7-Backend
.DESCRIPTION
    Meldet sich am gewünschten M365-Tenant an (Microsoft Graph + Exchange Online, zwei separate
    Logins) und prüft:
      1) Alle Postfächer auf versteckte Posteingangsregeln sowie Weiterleitungen an externe
         Adressen (klassische Anzeichen für kompromittierte Konten / BEC).
      2) Erfolgreiche Anmeldungen aus Ländern außerhalb der konfigurierten Whitelist.

    Ergebnis: CSV mit allen Funden sowie ein interaktives HTML-Dashboard.

    WICHTIG: "Versteckte Regeln" lassen sich nur über Exchange Online PowerShell zuverlässig
    finden (Get-InboxRule -IncludeHidden), nicht über Microsoft Graph - deshalb der zweite Login.
    Die Erkennung erfolgt per Differenzbildung: Regeln, die mit -IncludeHidden auftauchen, aber
    nicht in der normalen Abfrage. Die bekannte Microsoft-Systemregel "Junk E-mail Rule" wird nicht als versteckter Fund gewertet.
    Externe Weiterleitungen werden weiterhin separat ueber alle Regeln geprueft.

.NOTES
    Der Hauptprozess kann unter Windows PowerShell 5.1 laufen und ist damit fuer PS2EXE geeignet.
    Nur die Exchange-Online-Pruefung verwendet im Hintergrund einen separaten PowerShell-7-Prozess
    (pwsh.exe), weil Connect-ExchangeOnline -Device dort zuverlaessig funktioniert.

    PS2EXE: mit -STA kompilieren, z. B.
    Invoke-ps2exe .\Postfach_Sicherheitscheck_v7_6_PS2EXE.ps1 .\Postfach_Sicherheitscheck.exe -STA -noConsole
#>

# Der Hauptprozess darf unter Windows PowerShell 5.1 bzw. als PS2EXE laufen.
# PowerShell 7 wird nur fuer den isolierten Exchange-Online-Unterprozess benoetigt.
function Get-PowerShell7Path {
    $Candidates = @()

    try {
        $Cmd = Get-Command pwsh.exe -ErrorAction SilentlyContinue
        if ($Cmd -and $Cmd.Source) { $Candidates += $Cmd.Source }
    } catch { }

    if ($env:ProgramFiles) {
        $Candidates += (Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe')
    }

    if (${env:ProgramFiles(x86)}) {
        $Candidates += (Join-Path ${env:ProgramFiles(x86)} 'PowerShell\7\pwsh.exe')
    }

    foreach ($Candidate in ($Candidates | Select-Object -Unique)) {
        if ($Candidate -and (Test-Path -LiteralPath $Candidate -PathType Leaf)) {
            return $Candidate
        }
    }

    return $null
}

# WPF/Clipboard benoetigen STA. Bei PS2EXE deshalb unbedingt mit -STA kompilieren.
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
        "Dieses Programm muss im STA-Modus laufen. Bei PS2EXE bitte mit dem Parameter -STA kompilieren.",
        "STA-Modus erforderlich",
        "OK",
        "Error"
    ) | Out-Null
    exit 1
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName PresentationFramework

# ============================================================================
# Konfiguration - bei Bedarf anpassen
# ============================================================================
$AllowedCountries      = @("DE", "AT", "CH")   # ISO-3166 Alpha-2 Ländercodes, die als "normal" gelten
$SignInLookbackDays    = 7                     # Ohne Entra ID P1/P2 sind ohnehin nur 7 Tage Log verfügbar
$MailboxTypesToCheck   = @("UserMailbox", "SharedMailbox")  # Room/Equipment standardmäßig ausgeschlossen

# ============================================================================
# Ordnerstruktur & Logging
# ============================================================================
$tempFolderPath = "C:\Temp"
$reportFolderPath = "C:\Temp\sicherheits-reports"
$logfolder = "C:\Temp\export-logs"
$logPath   = "C:\Temp\export-logs\postfach-sicherheitscheck.txt"

foreach ($folder in @($tempFolderPath, $reportFolderPath, $logfolder)) {
    if (-not (Test-Path -Path $folder -PathType Container)) {
        New-Item -Path $folder -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
    }
}

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts - $Message" | Out-File -Append -FilePath $logPath
}

# Farbpalette für alle Dialoge (dunkles Design)
$AccentColor = [System.Drawing.ColorTranslator]::FromHtml("#38bdf8")
$BgColor     = [System.Drawing.ColorTranslator]::FromHtml("#0f172a")
$FieldColor  = [System.Drawing.ColorTranslator]::FromHtml("#1e293b")
$BorderColor = [System.Drawing.ColorTranslator]::FromHtml("#334155")
$TextColor   = [System.Drawing.ColorTranslator]::FromHtml("#e2e8f0")
$MutedColor  = [System.Drawing.ColorTranslator]::FromHtml("#94a3b8")

# ============================================================================
# Ladefenster (WPF)
# ============================================================================
$ProgressWindow = [Windows.Markup.XamlReader]::Parse(@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Postfach-Sicherheitscheck" Height="180" Width="460"
        WindowStartupLocation="Manual" WindowStyle="ToolWindow" ResizeMode="NoResize"
        Background="#0f172a" Topmost="True" ShowInTaskbar="False">
    <Grid Margin="15">
        <StackPanel>
            <TextBlock Name="TxtStatus" Text="Initialisiere..." Foreground="#38bdf8" FontSize="13" FontWeight="Bold" Margin="0,0,0,8" TextWrapping="Wrap"/>
            <TextBlock Name="TxtCode" Text="" Foreground="#facc15" FontSize="22" FontWeight="Bold" FontFamily="Consolas" HorizontalAlignment="Center" Margin="0,0,0,10"/>
            <ProgressBar Name="ProgBar" Height="20" Minimum="0" Maximum="9" Value="0" Foreground="#38bdf8" Background="#1e293b"/>
        </StackPanel>
    </Grid>
</Window>
"@)
$TxtStatus = $ProgressWindow.FindName("TxtStatus")
$TxtCode   = $ProgressWindow.FindName("TxtCode")
$ProgBar   = $ProgressWindow.FindName("ProgBar")

# Fortschrittsfenster immer im Vordergrund und unten rechts auf dem Bildschirm
# positionieren, auf dem sich beim Start der Mauszeiger befindet. Die Umrechnung
# in WPF-Koordinaten beruecksichtigt die Windows-DPI-Skalierung soweit moeglich.
$ProgressWindow.Add_Loaded({
    try {
        $Screen = [System.Windows.Forms.Screen]::FromPoint([System.Windows.Forms.Cursor]::Position)
        $WorkingArea = $Screen.WorkingArea
        $Source = [System.Windows.PresentationSource]::FromVisual($ProgressWindow)

        if ($Source -and $Source.CompositionTarget) {
            $Transform = $Source.CompositionTarget.TransformFromDevice
            $BottomRight = $Transform.Transform([System.Windows.Point]::new($WorkingArea.Right, $WorkingArea.Bottom))
            $ProgressWindow.Left = $BottomRight.X - $ProgressWindow.ActualWidth - 20
            $ProgressWindow.Top  = $BottomRight.Y - $ProgressWindow.ActualHeight - 20
        } else {
            $ProgressWindow.Left = [System.Windows.SystemParameters]::WorkArea.Right - $ProgressWindow.ActualWidth - 20
            $ProgressWindow.Top  = [System.Windows.SystemParameters]::WorkArea.Bottom - $ProgressWindow.ActualHeight - 20
        }

        $ProgressWindow.Topmost = $true
    } catch {
        $ProgressWindow.Left = [System.Windows.SystemParameters]::WorkArea.Right - $ProgressWindow.ActualWidth - 20
        $ProgressWindow.Top  = [System.Windows.SystemParameters]::WorkArea.Bottom - $ProgressWindow.ActualHeight - 20
        $ProgressWindow.Topmost = $true
    }
})

function Update-Progress {
    param ([string]$StatusText, [switch]$Indeterminate)
    $ProgBar.IsIndeterminate = [bool]$Indeterminate
    if (-not $Indeterminate) { $ProgBar.Value++ }
    $TxtStatus.Text = $StatusText
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
}

function Set-StatusText {
    param ([string]$StatusText)
    $TxtStatus.Text = $StatusText
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
}

function Wait-DeviceCodeJob {
    param(
        [Parameter(Mandatory = $true)]$Job,
        [Parameter(Mandatory = $true)][string]$LoginName
    )

    function Process-JobItems {
        param([object[]]$Items)

        foreach ($Item in @($Items)) {
            $script:__DeviceJobOutput += $Item
            $Text = [string]$Item

            if ($Text -match '^__STATUS__\|(.*)$') {
                # Sobald nach dem Login der erste Arbeitsstatus kommt, ist die
                # Device-Code-Anmeldung abgeschlossen. Den alten Code dann sofort
                # ausblenden, damit die GUI nicht so aussieht, als wuerde sie noch
                # auf die Anmeldung warten.
                if ($script:__DeviceCodeHandled) {
                    $TxtCode.Text = ''
                }
                Set-StatusText $Matches[1]
                Write-Log "${LoginName}: $($Matches[1])"
                continue
            }

            if (-not $script:__DeviceCodeHandled) {
                $Code = $null
                if ($Text -match '(?i)\bcode\s+([A-Z0-9-]{6,15})\s+(?:to|at|on|unter|auf)\b') {
                    $Code = $Matches[1]
                }
                elseif ($Text -match '(?i)\bcode[:\s]+([A-Z0-9-]{6,15})\b') {
                    $Code = $Matches[1]
                }

                if ($Code) {
                    try {
                        [System.Windows.Forms.Clipboard]::SetText($Code)
                    } catch {
                        try { Set-Clipboard -Value $Code -ErrorAction Stop } catch { }
                    }

                    $TxtCode.Text = $Code
                    $TxtStatus.Text = "${LoginName}: Code ist kopiert. Im Browser nur Strg+V druecken."
                    $script:__DeviceCodeHandled = $true

                    if (-not $script:__DeviceBrowserOpened) {
                        try {
                            Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList 'https://microsoft.com/devicelogin'
                            $script:__DeviceBrowserOpened = $true
                        } catch {
                            Write-Log "Konnte Device-Login-Seite nicht automatisch oeffnen: $($_.Exception.Message)"
                        }
                    }
                }
            }
        }
    }

    $script:__DeviceJobOutput = @()
    $script:__DeviceCodeHandled = $false
    $script:__DeviceBrowserOpened = $false

    while ($Job.State -eq 'Running' -or $Job.State -eq 'NotStarted') {
        $Items = @(Receive-Job -Job $Job -ErrorAction SilentlyContinue *>&1)
        Process-JobItems -Items $Items

        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke(
            [Action]{},
            [System.Windows.Threading.DispatcherPriority]::Background
        )
        Start-Sleep -Milliseconds 200
    }

    $Items = @(Receive-Job -Job $Job -ErrorAction SilentlyContinue *>&1)
    Process-JobItems -Items $Items

    $TxtCode.Text = ''
    $ProgBar.IsIndeterminate = $false

    if ($Job.State -eq 'Failed') {
        $Reason = $null
        try { $Reason = $Job.ChildJobs[0].JobStateInfo.Reason.Message } catch { }
        if (-not $Reason) {
            try { $Reason = ($Job.ChildJobs[0].Error | Select-Object -Last 1).Exception.Message } catch { }
        }
        if (-not $Reason) { $Reason = "$LoginName Anmeldung ist fehlgeschlagen." }
        throw $Reason
    }

    $Result = @($script:__DeviceJobOutput)
    Remove-Variable __DeviceJobOutput, __DeviceCodeHandled, __DeviceBrowserOpened -Scope Script -ErrorAction SilentlyContinue
    return ,$Result
}

function Wait-DeviceCodeProcess {
    param(
        [Parameter(Mandatory = $true)]$Process,
        [Parameter(Mandatory = $true)][string]$LoginName,
        [int]$CodeTimeoutSeconds = 90,
        [int]$LoginTimeoutMinutes = 15
    )

    $State = @{
        CodeHandled   = $false
        BrowserOpened = $false
        CodeDetectedAt = $null
    }
    $StartedAt = Get-Date
    $ErrorLines = [System.Collections.Generic.List[string]]::new()

    function Process-ExternalLine {
        param(
            [AllowNull()][string]$Line,
            [switch]$FromErrorStream
        )

        if ($null -eq $Line) { return }
        $Clean = $Line -replace '\x1B\[[0-?]*[ -/]*[@-~]', ''
        $Clean = $Clean.Trim()
        if ([string]::IsNullOrWhiteSpace($Clean)) { return }

        if ($FromErrorStream) {
            $ErrorLines.Add($Clean)
            Write-Log "${LoginName} ERR: $Clean"
        } else {
            Write-Log "${LoginName} OUT: $Clean"
        }

        if ($Clean -match '^__STATUS__\|(.*)$') {
            $TxtCode.Text = ''
            Set-StatusText $Matches[1]
            return
        }

        if (-not $State.CodeHandled) {
            $Code = $null
            if ($Clean -match '(?i)\bcode\s*[:<]?\s*([A-Z0-9-]{6,15})\b') {
                $Code = $Matches[1]
            }

            if ($Code) {
                try {
                    [System.Windows.Forms.Clipboard]::SetText($Code)
                } catch {
                    try { Set-Clipboard -Value $Code -ErrorAction Stop } catch { }
                }

                $TxtCode.Text = $Code
                $TxtStatus.Text = "${LoginName}: Code ist kopiert. Im Browser nur Strg+V druecken."
                $State.CodeHandled = $true
                $State.CodeDetectedAt = Get-Date

                if (-not $State.BrowserOpened) {
                    try {
                        Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList 'https://microsoft.com/devicelogin'
                        $State.BrowserOpened = $true
                    } catch {
                        Write-Log "Konnte Device-Login-Seite nicht automatisch oeffnen: $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    $OutEnded = $false
    $ErrEnded = $false
    $OutTask = $Process.StandardOutput.ReadLineAsync()
    $ErrTask = $Process.StandardError.ReadLineAsync()

    while (-not $Process.HasExited -or -not $OutEnded -or -not $ErrEnded) {
        if (-not $OutEnded -and $OutTask.IsCompleted) {
            $Line = $OutTask.GetAwaiter().GetResult()
            if ($null -eq $Line) {
                $OutEnded = $true
            } else {
                Process-ExternalLine -Line $Line
                $OutTask = $Process.StandardOutput.ReadLineAsync()
            }
        }

        if (-not $ErrEnded -and $ErrTask.IsCompleted) {
            $Line = $ErrTask.GetAwaiter().GetResult()
            if ($null -eq $Line) {
                $ErrEnded = $true
            } else {
                Process-ExternalLine -Line $Line -FromErrorStream
                $ErrTask = $Process.StandardError.ReadLineAsync()
            }
        }

        if (-not $State.CodeHandled -and ((Get-Date) - $StartedAt).TotalSeconds -gt $CodeTimeoutSeconds) {
            try { $Process.Kill($true) } catch { }
            $Details = if ($ErrorLines.Count -gt 0) { $ErrorLines -join ' | ' } else { 'Keine weitere Fehlerausgabe.' }
            throw "Exchange Online hat innerhalb von $CodeTimeoutSeconds Sekunden keinen Device-Code ausgegeben. $Details"
        }

        if ($State.CodeHandled -and $State.CodeDetectedAt -and ((Get-Date) - $State.CodeDetectedAt).TotalMinutes -gt $LoginTimeoutMinutes) {
            try { $Process.Kill($true) } catch { }
            throw "Die Exchange-Online-Anmeldung wurde nach $LoginTimeoutMinutes Minuten nicht abgeschlossen."
        }

        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke(
            [Action]{},
            [System.Windows.Threading.DispatcherPriority]::Background
        )
        Start-Sleep -Milliseconds 100
        $Process.Refresh()
    }

    $TxtCode.Text = ''
    $ProgBar.IsIndeterminate = $false

    if ($Process.ExitCode -ne 0) {
        $Details = if ($ErrorLines.Count -gt 0) { $ErrorLines -join "`r`n" } else { "Exchange-Online-Unterprozess wurde mit ExitCode $($Process.ExitCode) beendet." }
        throw $Details
    }

    if (-not $State.CodeHandled) {
        throw 'Der Exchange-Online-Prozess wurde beendet, ohne dass ein Device-Code erkannt wurde.'
    }
}

$ProgressWindow.Show()

try {
    # 1) Module pruefen/installieren.
    # Microsoft Graph wird spaeter in einem isolierten Job geladen, damit dessen
    # MSAL-Assemblies nicht mit ExchangeOnlineManagement im Hauptprozess kollidieren.
    Update-Progress "Pruefe Microsoft Graph und Exchange Online Module..."

    foreach ($Mod in @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Reports",
        "Microsoft.Graph.Identity.DirectoryManagement"
    )) {
        if (-not (Get-Module -Name $Mod -ListAvailable)) {
            Write-Log "Installiere $Mod Modul..."
            Install-Module -Name $Mod -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
        }
    }

    # PowerShell 7 wird ausschliesslich als Backend fuer Exchange Online benoetigt.
    # Die EXO-Modulpruefung/-installation erfolgt spaeter direkt im pwsh-Unterprozess,
    # damit das Modul auch im korrekten PowerShell-7-Modulpfad liegt.
    $PowerShell7Backend = Get-PowerShell7Path
    if (-not $PowerShell7Backend) {
        throw 'PowerShell 7 (pwsh.exe) ist nicht installiert. Das Programm kann unter PowerShell 5.1/als EXE laufen, benoetigt PowerShell 7 aber als Exchange-Online-Backend.'
    }
    Write-Log "PowerShell-7-Backend gefunden: $PowerShell7Backend"

    # 2) Login 1/2: Microsoft Graph und Graph-Daten im selben isolierten Job laden.
    Update-Progress "Login 1/2: Microsoft Graph - Code wird vorbereitet..." -Indeterminate
    Write-Log "Starte Graph-Anmeldung im isolierten Job..."

    $GraphScopes = @(
        "AuditLog.Read.All",
        "Directory.Read.All",
        "Domain.Read.All",
        "Organization.Read.All",
        "User.Read.All"
    )

    # Arrays nicht direkt ueber Start-Job -ArgumentList uebergeben. Dabei koennen
    # verschachtelte Object[] entstehen, die Connect-MgGraph -Scopes nicht akzeptiert.
    # Deshalb serialisieren wir die Werte als JSON und bauen im Job string[] daraus.
    $GraphScopesJson = ConvertTo-Json -InputObject @($GraphScopes) -Compress
    $AllowedCountriesJson = ConvertTo-Json -InputObject @($AllowedCountries) -Compress

    $GraphLoginJob = Start-Job -ScriptBlock {
        param(
            [string]$ScopesJson,
            [string]$AllowedCountriesJson,
            [int]$LookbackDaysJob
        )

        $ErrorActionPreference = 'Stop'

        [string[]]$Scopes = @((ConvertFrom-Json -InputObject $ScopesJson))
        [string[]]$AllowedCountriesJob = @((ConvertFrom-Json -InputObject $AllowedCountriesJson))

        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Reports -ErrorAction Stop
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop

        Connect-MgGraph -Scopes $Scopes -UseDeviceCode -ContextScope Process -NoWelcome -ErrorAction Stop

        $Ctx = Get-MgContext
        if (-not $Ctx) { throw 'Microsoft Graph Anmeldung fehlgeschlagen.' }

        $OrgInfoJob = Get-MgOrganization -ErrorAction SilentlyContinue | Select-Object -First 1
        $SuggestedNameJob = if ($OrgInfoJob -and $OrgInfoJob.DisplayName) { $OrgInfoJob.DisplayName } else { $Ctx.TenantId }

        $VerifiedDomainsJob = @(
            (Get-MgDomain -All -ErrorAction SilentlyContinue |
                Where-Object { $_.IsVerified }).Id |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object { ([string]$_).ToLowerInvariant() }
        )

        # Sign-In-Logs koennen in groesseren/lizenzierten Tenants sehr viele Datensaetze
        # enthalten. Eine einzige -All-Abfrage ueber sieben Tage wirkt dann wie ein Haenger.
        # Deshalb wird der Zeitraum in 24h-Bloecke geteilt und nur erfolgreiche Logins
        # serverseitig angefordert. Nach jedem Block aktualisieren wir die GUI.
        $SignInsJob = @()
        $NowUtc = [DateTimeOffset]::UtcNow
        $WindowStartUtc = $NowUtc.AddDays(-$LookbackDaysJob)
        $SignInQueryAvailable = $true

        for ($ChunkIndex = 0; $ChunkIndex -lt $LookbackDaysJob; $ChunkIndex++) {
            if (-not $SignInQueryAvailable) { break }

            $ChunkStart = $WindowStartUtc.AddDays($ChunkIndex)
            $ChunkEnd = $ChunkStart.AddDays(1)
            if ($ChunkEnd -gt $NowUtc) { $ChunkEnd = $NowUtc }

            $ChunkNumber = $ChunkIndex + 1
            Write-Output "__STATUS__|Pruefe Anmeldungen: Zeitraum $ChunkNumber/$LookbackDaysJob..."

            $StartText = $ChunkStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
            $EndText = $ChunkEnd.ToString('yyyy-MM-ddTHH:mm:ssZ')
            $Filter = "createdDateTime ge $StartText and createdDateTime lt $EndText and status/errorCode eq 0"

            try {
                $ChunkSignIns = @(
                    Get-MgAuditLogSignIn `
                        -Filter $Filter `
                        -All `
                        -PageSize 999 `
                        -Property @('createdDateTime','userDisplayName','userPrincipalName','ipAddress','location','status') `
                        -ErrorAction Stop
                )

                foreach ($SignIn in $ChunkSignIns) {
                    if (-not $SignIn) { continue }

                    $Country = $null
                    if ($SignIn.Location) {
                        $Country = [string]$SignIn.Location.CountryOrRegion
                    }

                    if ([string]::IsNullOrWhiteSpace($Country)) { continue }
                    $Country = $Country.ToUpperInvariant()

                    if ($AllowedCountriesJob -notcontains $Country) {
                        $SignInsJob += $SignIn
                    }
                }
            } catch {
                $SignInError = [string]$_.Exception.Message

                if ($SignInError -match 'Authentication_RequestFromNonPremiumTenantOrB2CTenant|premium license|Authorization_RequestDenied|Insufficient privileges') {
                    # Ohne passende Entra-ID-Premium-Lizenz bzw. Berechtigung sind die
                    # Sign-In-Logs nicht abrufbar. Das darf den Postfachcheck nicht stoppen.
                    Write-Output '__STATUS__|Anmeldeprotokolle nicht verfuegbar - fahre mit Postfachpruefung fort.'
                    $SignInQueryAvailable = $false
                    break
                }

                # Ein einzelner Zeitraum darf den kompletten Sicherheitscheck nicht stoppen.
                Write-Output "__STATUS__|Anmeldeprotokolle fuer Zeitraum $ChunkNumber konnten nicht geladen werden - fahre fort."
            }
        }

        $SignInGroupsJob = @(
            $SignInsJob |
                Where-Object {
                    $_ -and
                    -not [string]::IsNullOrWhiteSpace([string]$_.UserPrincipalName) -and
                    $_.Location -and
                    -not [string]::IsNullOrWhiteSpace([string]$_.Location.CountryOrRegion)
                } |
                Group-Object -Property {
                    $CountryKey = ([string]$_.Location.CountryOrRegion).ToUpperInvariant()
                    "{0}|{1}" -f ([string]$_.UserPrincipalName).ToLowerInvariant(), $CountryKey
                }
        )

        $SignInFindingsJob = @(
            foreach ($Grp in $SignInGroupsJob) {
                if (-not $Grp -or -not $Grp.Group) { continue }

                $Latest = $Grp.Group |
                    Sort-Object CreatedDateTime -Descending |
                    Select-Object -First 1

                if (-not $Latest) { continue }

                $CountryText = ''
                $CityText = ''
                if ($Latest.Location) {
                    $CountryText = [string]$Latest.Location.CountryOrRegion
                    $CityText = [string]$Latest.Location.City
                }

                $CreatedText = 'unbekannt'
                if ($null -ne $Latest.CreatedDateTime -and -not [string]::IsNullOrWhiteSpace([string]$Latest.CreatedDateTime)) {
                    try {
                        $CreatedText = ([DateTimeOffset]$Latest.CreatedDateTime).ToLocalTime().ToString('dd.MM.yyyy HH:mm')
                    } catch {
                        $CreatedText = [string]$Latest.CreatedDateTime
                    }
                }

                [PSCustomObject]@{
                    DisplayName       = [string]$Latest.UserDisplayName
                    UserPrincipalName = [string]$Latest.UserPrincipalName
                    FindingTyp        = 'ANMELDUNG'
                    Schweregrad       = 'MITTEL'
                    Beschreibung      = "Anmeldung aus $CountryText ($CityText)"
                    Detail            = "$($Grp.Count)x in den letzten $LookbackDaysJob Tagen, zuletzt am $CreatedText Uhr von IP $([string]$Latest.IpAddress)"
                }
            }
        )

        [PSCustomObject]@{
            __Kind          = 'GraphResult'
            Account         = $Ctx.Account
            TenantId        = $Ctx.TenantId
            SuggestedName   = $SuggestedNameJob
            VerifiedDomains = @($VerifiedDomainsJob)
            SignInFindings  = @($SignInFindingsJob)
        }

        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    } -ArgumentList $GraphScopesJson, $AllowedCountriesJson, $SignInLookbackDays

    $GraphJobOutput = Wait-DeviceCodeJob -Job $GraphLoginJob -LoginName 'Microsoft Graph'
    $GraphResult = @($GraphJobOutput | Where-Object { $_.__Kind -eq 'GraphResult' }) | Select-Object -Last 1

    if (-not $GraphResult) {
        throw 'Microsoft Graph Anmeldung wurde abgeschlossen, aber es konnten keine Graph-Daten uebernommen werden.'
    }

    $Context = [PSCustomObject]@{
        Account  = $GraphResult.Account
        TenantId = $GraphResult.TenantId
    }
    $SuggestedName = $GraphResult.SuggestedName
    $VerifiedDomains = @($GraphResult.VerifiedDomains)
    $SignInFindings = @($GraphResult.SignInFindings)

    Write-Log "Graph: angemeldet als $($Context.Account) im Tenant $($Context.TenantId)"

    # 4) Bezeichnung für die Reportdateien abfragen
    # Der vorgeschlagene Name wurde bereits im Graph-Job ermittelt.
    Update-Progress "Warte auf Bezeichnung für den Report..."

    $NameForm = New-Object Windows.Forms.Form
    $NameForm.Text = "Report-Name festlegen"
    $NameForm.Width = 520
    $NameForm.Height = 220
    $NameForm.StartPosition = "CenterScreen"
    $NameForm.ControlBox = $false
    $NameForm.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog
    $NameForm.BackColor = $BgColor
    $NameForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $NameForm.TopMost = $true

    $NameAccentBar = New-Object Windows.Forms.Panel
    $NameAccentBar.Location = New-Object Drawing.Point(0, 0)
    $NameAccentBar.Size = New-Object Drawing.Size(520, 4)
    $NameAccentBar.BackColor = $AccentColor
    $NameForm.Controls.Add($NameAccentBar)

    $NameLabel = New-Object Windows.Forms.Label
    $NameLabel.Location = New-Object Drawing.Point(25, 25)
    $NameLabel.Size = New-Object Drawing.Size(460, 26)
    $NameLabel.Text = "Report-Name festlegen"
    $NameLabel.ForeColor = $AccentColor
    $NameLabel.BackColor = $BgColor
    $NameLabel.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
    $NameForm.Controls.Add($NameLabel)

    $NameSubLabel = New-Object Windows.Forms.Label
    $NameSubLabel.Location = New-Object Drawing.Point(25, 58)
    $NameSubLabel.Size = New-Object Drawing.Size(460, 20)
    $NameSubLabel.Text = "Wird für Datei- und Ordnernamen der Reports verwendet:"
    $NameSubLabel.ForeColor = $MutedColor
    $NameSubLabel.BackColor = $BgColor
    $NameForm.Controls.Add($NameSubLabel)

    $NameTextBox = New-Object Windows.Forms.TextBox
    $NameTextBox.Location = New-Object Drawing.Point(25, 88)
    $NameTextBox.Size = New-Object Drawing.Size(460, 26)
    $NameTextBox.BackColor = $FieldColor
    $NameTextBox.ForeColor = $TextColor
    $NameTextBox.BorderStyle = [Windows.Forms.BorderStyle]::FixedSingle
    $NameTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $NameTextBox.Text = $SuggestedName
    $NameForm.Controls.Add($NameTextBox)

    $NameOkButton = New-Object Windows.Forms.Button
    $NameOkButton.Location = New-Object Drawing.Point(25, 135)
    $NameOkButton.Size = New-Object Drawing.Size(140, 38)
    $NameOkButton.Text = "Weiter"
    $NameOkButton.DialogResult = [Windows.Forms.DialogResult]::OK
    $NameOkButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $NameOkButton.FlatAppearance.BorderSize = 0
    $NameOkButton.BackColor = $AccentColor
    $NameOkButton.ForeColor = $BgColor
    $NameOkButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $NameForm.Controls.Add($NameOkButton)

    $NameCancelButton = New-Object Windows.Forms.Button
    $NameCancelButton.Location = New-Object Drawing.Point(175, 135)
    $NameCancelButton.Size = New-Object Drawing.Size(140, 38)
    $NameCancelButton.Text = "Abbrechen"
    $NameCancelButton.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $NameCancelButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $NameCancelButton.FlatAppearance.BorderSize = 1
    $NameCancelButton.FlatAppearance.BorderColor = $BorderColor
    $NameCancelButton.BackColor = $FieldColor
    $NameCancelButton.ForeColor = $TextColor
    $NameCancelButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $NameForm.Controls.Add($NameCancelButton)

    $NameForm.AcceptButton = $NameOkButton
    $NameForm.CancelButton = $NameCancelButton

    $NameResult = $NameForm.ShowDialog()
    if ($NameResult -ne [Windows.Forms.DialogResult]::OK -or [string]::IsNullOrWhiteSpace($NameTextBox.Text)) {
        Write-Log "Benutzer hat die Namensvergabe abgebrochen."
        $ProgressWindow.Close()
        return
    }
    $ReportLabel = $NameTextBox.Text.Trim()
    Write-Log "Report-Bezeichnung: $ReportLabel"

    # 5) Graph-Daten wurden bereits im Graph-Job geladen.
    Update-Progress "Graph-Daten uebernommen..."

    # 6) Login 2/2: Exchange Online in einem echten separaten pwsh.exe-Prozess.
    # Connect-ExchangeOnline -Device schreibt den Geraetecode direkt an den Console-Host.
    # In Start-Job wird diese Ausgabe nicht zuverlaessig an Receive-Job weitergereicht.
    # Deshalb wird EXO hier in einem eigenen pwsh.exe-Prozess gestartet und dessen
    # STDOUT fortlaufend gelesen. So kann der Code sicher erkannt, kopiert und der
    # Browser automatisch geoeffnet werden.
    Update-Progress "Login 2/2: Exchange Online - Code wird vorbereitet..." -Indeterminate
    Write-Log "Starte Exchange-Online-Anmeldung im separaten PowerShell-7-Prozess..."

    $RunId = [Guid]::NewGuid().ToString('N')
    $ExoChildScript = Join-Path $tempFolderPath "exo_securitycheck_${RunId}.ps1"
    $ExoConfigPath  = Join-Path $tempFolderPath "exo_securitycheck_${RunId}_config.json"
    $ExoResultPath  = Join-Path $tempFolderPath "exo_securitycheck_${RunId}_result.json"
    $ExoTempFiles   = @($ExoChildScript, $ExoConfigPath, $ExoResultPath)

    [PSCustomObject]@{
        MailboxTypes    = @($MailboxTypesToCheck)
        VerifiedDomains = @($VerifiedDomains)
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ExoConfigPath -Encoding utf8

$ExoChildContent = @'
param(
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [Parameter(Mandatory = $true)][string]$ResultPath
)

$ErrorActionPreference = 'Stop'

try {
    $Config = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    [string[]]$MailboxTypesJob = @($Config.MailboxTypes | ForEach-Object { [string]$_ })
    [string[]]$VerifiedDomainsJob = @($Config.VerifiedDomains | ForEach-Object { [string]$_ })

    # ExchangeOnlineManagement direkt unter PowerShell 7 pruefen/installieren.
    $MinExoVersion = [Version]'3.4.0'
    $ExoModule = Get-Module -Name ExchangeOnlineManagement -ListAvailable |
                 Sort-Object Version -Descending |
                 Select-Object -First 1

    if (-not $ExoModule -or $ExoModule.Version -lt $MinExoVersion) {
        Write-Output "__STATUS__|Installiere/aktualisiere ExchangeOnlineManagement..."
        Install-Module -Name ExchangeOnlineManagement -MinimumVersion $MinExoVersion -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
        $ExoModule = Get-Module -Name ExchangeOnlineManagement -ListAvailable |
                     Sort-Object Version -Descending |
                     Select-Object -First 1
    }

    if (-not $ExoModule) {
        throw 'ExchangeOnlineManagement konnte unter PowerShell 7 nicht gefunden oder installiert werden.'
    }

    Import-Module $ExoModule.Path -Force -ErrorAction Stop

    $ConnectCommand = Get-Command Connect-ExchangeOnline -ErrorAction Stop
    if (-not $ConnectCommand.Parameters.ContainsKey('Device')) {
        throw 'Connect-ExchangeOnline stellt den Parameter -Device nicht bereit. Bitte ExchangeOnlineManagement aktualisieren.'
    }

    Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop

    Write-Output '__STATUS__|Lade Postfachliste...'
    $MailboxesJob = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails $MailboxTypesJob -ErrorAction Stop
    $MailboxTotalJob = @($MailboxesJob).Count
    $MailboxIndexJob = 0
    $RuleFindingsJob = @()
    $MailboxResultsJob = @()

    foreach ($Mbx in $MailboxesJob) {
        $MailboxIndexJob++
        Write-Output "__STATUS__|Pruefe Postfachregeln [$MailboxIndexJob/$MailboxTotalJob]: $($Mbx.DisplayName)"

        try {
            $VisibleRules = Get-InboxRule -Mailbox $Mbx.PrimarySmtpAddress -ErrorAction Stop
            $AllRules     = Get-InboxRule -Mailbox $Mbx.PrimarySmtpAddress -IncludeHidden -ErrorAction Stop
        } catch {
            $MailboxResultsJob += [PSCustomObject]@{
                DisplayName       = [string]$Mbx.DisplayName
                UserPrincipalName = [string]$Mbx.PrimarySmtpAddress
                MailboxType       = [string]$Mbx.RecipientTypeDetails
                CheckSucceeded    = $false
                CheckDetail       = "Regeln konnten nicht geladen werden: $($_.Exception.Message)"
            }
            Write-Warning "Konnte Regeln fuer $($Mbx.PrimarySmtpAddress) nicht laden: $($_.Exception.Message)"
            continue
        }

        $VisibleIds     = @($VisibleRules | Select-Object -ExpandProperty Identity)
        $AllHiddenRules = @($AllRules | Where-Object { $VisibleIds -notcontains $_.Identity })
        $HiddenIds      = @($AllHiddenRules | Select-Object -ExpandProperty Identity)

        # Microsoft-Systemregel: "Junk E-mail Rule" ist eine erwartete versteckte
        # Exchange-Regel und wird NICHT als versteckter Sicherheitsfund gewertet.
        # Wichtig: Die nachfolgende Weiterleitungspruefung laeuft weiterhin ueber
        # $AllRules. Externe Forward-/Redirect-Ziele werden daher trotzdem erkannt.
        $HiddenRules = @(
            $AllHiddenRules | Where-Object {
                ([string]$_.Name).Trim() -notmatch '^(?i:Junk E-mail Rule)$'
            }
        )

        foreach ($Rule in $HiddenRules) {
            $RuleFindingsJob += [PSCustomObject]@{
                DisplayName       = [string]$Mbx.DisplayName
                UserPrincipalName = [string]$Mbx.PrimarySmtpAddress
                FindingTyp        = 'REGEL'
                Schweregrad       = 'HOCH'
                Beschreibung      = "Versteckte Regel gefunden: '$($Rule.Name)'"
                Detail            = "DeleteMessage=$($Rule.DeleteMessage); MarkAsRead=$($Rule.MarkAsRead); StopProcessing=$($Rule.StopProcessingRules)"
            }
        }

        foreach ($Rule in $AllRules) {
            $Targets = @()
            if ($Rule.ForwardTo)             { $Targets += $Rule.ForwardTo }
            if ($Rule.RedirectTo)            { $Targets += $Rule.RedirectTo }
            if ($Rule.ForwardAsAttachmentTo) { $Targets += $Rule.ForwardAsAttachmentTo }

            foreach ($Target in $Targets) {
                $TargetText = [string]$Target
                if ($TargetText -match '([\w\.\-]+@[\w\.\-]+)') {
                    $Addr = $Matches[1]
                    $Domain = (($Addr -split '@')[1]).ToLowerInvariant()

                    if ($Domain -and ($VerifiedDomainsJob -notcontains $Domain)) {
                        $IsHidden = $HiddenIds -contains $Rule.Identity
                        $RuleFindingsJob += [PSCustomObject]@{
                            DisplayName       = [string]$Mbx.DisplayName
                            UserPrincipalName = [string]$Mbx.PrimarySmtpAddress
                            FindingTyp        = 'REGEL'
                            Schweregrad       = 'HOCH'
                            Beschreibung      = "Weiterleitung an externe Adresse: $Addr (Regel: '$($Rule.Name)')"
                            Detail            = if ($IsHidden) { 'Zusaetzlich: Regel ist versteckt' } else { 'Regel ist sichtbar' }
                        }
                    }
                }
            }
        }

        $MailboxResultsJob += [PSCustomObject]@{
            DisplayName       = [string]$Mbx.DisplayName
            UserPrincipalName = [string]$Mbx.PrimarySmtpAddress
            MailboxType       = [string]$Mbx.RecipientTypeDetails
            CheckSucceeded    = $true
            CheckDetail       = 'Postfachregeln und Weiterleitungen erfolgreich geprueft.'
        }
    }

    [PSCustomObject]@{
        MailboxTotal = $MailboxTotalJob
        RuleFindings = @($RuleFindingsJob)
        Mailboxes    = @($MailboxResultsJob)
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ResultPath -Encoding utf8

    Write-Output '__STATUS__|Exchange-Online-Pruefung abgeschlossen.'
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    exit 0
} catch {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
    Write-Error ("EXO-Fehler: " + $_.Exception.Message)
    exit 1
}
'@

    Set-Content -LiteralPath $ExoChildScript -Value $ExoChildContent -Encoding utf8

    $PwshExe = Get-PowerShell7Path
    if (-not $PwshExe) {
        throw 'pwsh.exe konnte fuer den Exchange-Online-Unterprozess nicht gefunden werden.'
    }

    # ProcessStartInfo.ArgumentList existiert unter .NET Framework/Windows PowerShell 5.1
    # nicht. Deshalb verwenden wir bewusst die kompatible Arguments-Eigenschaft.
    $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $PwshExe
    $StartInfo.UseShellExecute = $false
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $StartInfo.CreateNoWindow = $true
    $StartInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ExoChildScript`" -ConfigPath `"$ExoConfigPath`" -ResultPath `"$ExoResultPath`""

    $ExoProcess = New-Object System.Diagnostics.Process
    $ExoProcess.StartInfo = $StartInfo
    if (-not $ExoProcess.Start()) {
        throw 'Der Exchange-Online-Unterprozess konnte nicht gestartet werden.'
    }

    Wait-DeviceCodeProcess -Process $ExoProcess -LoginName 'Exchange Online'

    if (-not (Test-Path -LiteralPath $ExoResultPath -PathType Leaf)) {
        throw 'Exchange Online wurde beendet, aber die Ergebnisdatei wurde nicht erstellt.'
    }

    $ExchangeResult = Get-Content -LiteralPath $ExoResultPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $MailboxTotal = [int]$ExchangeResult.MailboxTotal
    $RuleFindings = @($ExchangeResult.RuleFindings)
    $Mailboxes = @($ExchangeResult.Mailboxes)
    Write-Log "Exchange Online verbunden und $MailboxTotal Postfaecher geprueft."

    # 9) CSV & HTML-Dashboard erstellen
    Update-Progress "Erstelle Report..."

    # Postfaecher, deren Regelabfrage fehlgeschlagen ist, duerfen nicht als OK gelten.
    # Sie werden als eigener Hinweis in den Report aufgenommen.
    $CheckFindings = @(
        foreach ($Mbx in ($Mailboxes | Where-Object { -not [bool]$_.CheckSucceeded })) {
            [PSCustomObject]@{
                DisplayName       = [string]$Mbx.DisplayName
                UserPrincipalName = [string]$Mbx.UserPrincipalName
                FindingTyp        = 'PRUEFUNG'
                Schweregrad       = 'MITTEL'
                Beschreibung      = 'Postfach konnte nicht vollstaendig geprueft werden'
                Detail            = [string]$Mbx.CheckDetail
            }
        }
    )

    $AllFindings = @($RuleFindings) + @($SignInFindings) + @($CheckFindings)

    # Ein Postfach gilt fuer den Report als OK, wenn die EXO-Pruefung erfolgreich war
    # und fuer seine Adresse in keiner der durchgefuehrten Pruefungen ein Fund existiert.
    $FindingUpns = @(
        $AllFindings |
            ForEach-Object { ([string]$_.UserPrincipalName).Trim().ToLowerInvariant() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )

    $OkMailboxes = @(
        $Mailboxes |
            Where-Object {
                $MailboxUpn = ([string]$_.UserPrincipalName).Trim().ToLowerInvariant()
                [bool]$_.CheckSucceeded -and ($FindingUpns -notcontains $MailboxUpn)
            } |
            Sort-Object DisplayName
    )

    $SafeReportName = ($ReportLabel -replace '[\\/:\*\?"<>\|]', '_')
    $Timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $CsvFileName  = Join-Path $reportFolderPath "Sicherheitscheck_${SafeReportName}_$Timestamp.csv"
    $HtmlFileName = Join-Path $reportFolderPath "Sicherheitscheck_${SafeReportName}_$Timestamp.html"

    $AllFindings | Export-Csv -Path $CsvFileName -NoTypeInformation -Encoding utf8
    Write-Log "CSV erfolgreich erstellt: $CsvFileName"

    $HiddenRuleCount    = ($RuleFindings | Where-Object { $_.Beschreibung -like "Versteckte Regel*" }).Count
    $ForwardCount       = ($RuleFindings | Where-Object { $_.Beschreibung -like "Weiterleitung*" }).Count
    $ForeignSignInCount = $SignInFindings.Count
    $CheckErrorCount    = $CheckFindings.Count
    $OkMailboxCount     = $OkMailboxes.Count
    $FindingCount       = $AllFindings.Count
    $CriticalCount      = ($AllFindings | Where-Object { $_.Schweregrad -eq "HOCH" }).Count

    $HtmlHeader = @"
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>Postfach-Sicherheitscheck - $ReportLabel</title>
    <style>
        html { scroll-behavior: smooth; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #1e293b, #0f172a); border: 1px solid #334155; border-radius: 10px; padding: 25px; margin-bottom: 20px; }
        h1 { margin: 0 0 10px 0; color: #38bdf8; font-size: 28px; text-transform: uppercase; letter-spacing: 1px; }
        .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }
        .meta-item { background: #1e293b; padding: 10px 15px; border-radius: 6px; border-left: 3px solid #38bdf8; font-size: 14px; }
        .meta-label { color: #94a3b8; font-size: 12px; display: block; }

        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }

        .card-clickable { background: #1e293b; border-radius: 10px; padding: 20px; text-align: center; border: 1px solid #334155; cursor: pointer; transition: transform 0.15s ease, border-color 0.15s ease; user-select: none; }
        .card-clickable:hover { transform: translateY(-3px); border-color: #38bdf8; }
        .card-clickable.active-filter { border: 2px solid #38bdf8; background: #26334d; }

        .score-value { font-size: 42px; font-weight: bold; margin: 10px 0; }
        .score-good { color: #22c55e; }
        .score-warn { color: #eab308; }
        .score-bad { color: #ef4444; }

        .accordion-item { background: #1e293b; border: 1px solid #334155; border-radius: 8px; margin-bottom: 12px; overflow: hidden; transition: opacity 0.2s ease; }
        .accordion-header { padding: 15px 20px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; user-select: none; }
        .accordion-header:hover { background: #334155; }
        .status-badge { padding: 4px 12px; border-radius: 20px; font-weight: bold; font-size: 12px; }
        .badge-fail { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }
        .badge-warn { background: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid #eab308; }
        .badge-good { background: rgba(34, 197, 94, 0.2); color: #22c55e; border: 1px solid #22c55e; }
        .badge-type { background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid #38bdf8; margin-left: 6px; }

        .accordion-content { padding: 20px; background: #0f172a; border-top: 1px solid #334155; display: none; font-size: 14px; line-height: 1.6; }
        .ref-tag { display: inline-block; background: #334155; color: #cbd5e1; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-top: 10px; }

        #scrollTopBtn { display: none; position: fixed; bottom: 30px; right: 30px; z-index: 99; border: 1px solid #38bdf8; outline: none; background-color: #1e293b; color: #38bdf8; cursor: pointer; padding: 12px 18px; border-radius: 8px; font-weight: bold; font-size: 14px; box-shadow: 0 4px 10px rgba(0,0,0,0.5); transition: background-color 0.2s, transform 0.2s; }
        #scrollTopBtn:hover { background-color: #38bdf8; color: #0f172a; transform: translateY(-2px); }
    </style>
</head>
<body>
    <button onclick="scrollToTop()" id="scrollTopBtn" title="Ganz nach oben scrollen">↑ Nach oben</button>

    <div class="container">
        <div class="header">
            <h1>Postfach-Sicherheitscheck</h1>
            <div>Versteckte Regeln, externe Weiterleitungen & Anmeldungen aus dem Ausland</div>
            <div class="meta-grid">
                <div class="meta-item"><span class="meta-label">KUNDE</span>$ReportLabel</div>
                <div class="meta-item"><span class="meta-label">TENANT</span>$($Context.TenantId)</div>
                <div class="meta-item"><span class="meta-label">GEPRÜFTE POSTFÄCHER</span>$MailboxTotal</div>
                <div class="meta-item"><span class="meta-label">LÄNDER-WHITELIST</span>$($AllowedCountries -join ', ')</div>
                <div class="meta-item"><span class="meta-label">PRÜFDATUM</span>$((Get-Date).ToString("dd.MM.yyyy HH:mm")) Uhr</div>
            </div>
        </div>

        <div class="dashboard">
            <div class="card-clickable" onclick="filterByStatus('FINDING', this)">
                <div>Auffaelligkeiten</div>
                <div class="score-value $(if($FindingCount -gt 0){'score-bad'}else{'score-good'})">$FindingCount</div>
                <div style="font-size: 12px; color: #94a3b8;">Klick: Alle Auffaelligkeiten</div>
            </div>
            <div class="card-clickable" onclick="filterByStatus('HIDDEN', this)">
                <div>Versteckte Regeln</div>
                <div class="score-value $(if($HiddenRuleCount -gt 0){'score-bad'}else{'score-good'})">$HiddenRuleCount</div>
                <div style="font-size: 12px; color: #94a3b8;">Klick: Nur versteckte Regeln</div>
            </div>
            <div class="card-clickable" onclick="filterByStatus('FORWARD', this)">
                <div>Externe Weiterleitungen</div>
                <div class="score-value $(if($ForwardCount -gt 0){'score-bad'}else{'score-good'})">$ForwardCount</div>
                <div style="font-size: 12px; color: #94a3b8;">Klick: Nur Weiterleitungen</div>
            </div>
            <div class="card-clickable" onclick="filterByStatus('ANMELDUNG', this)">
                <div>Anmeldungen a.d. Ausland</div>
                <div class="score-value $(if($ForeignSignInCount -gt 0){'score-warn'}else{'score-good'})">$ForeignSignInCount</div>
                <div style="font-size: 12px; color: #94a3b8;">Klick: Nur Auslands-Logins</div>
            </div>
            <div class="card-clickable" onclick="filterByStatus('OK', this)">
                <div>Postfaecher OK</div>
                <div class="score-value $(if($OkMailboxCount -eq $MailboxTotal){'score-good'}elseif($OkMailboxCount -gt 0){'score-warn'}else{'score-bad'})">$OkMailboxCount</div>
                <div style="font-size: 12px; color: #94a3b8;">Klick: Unauffaellige Postfaecher</div>
            </div>
            <div class="card-clickable" onclick="filterByStatus('CHECK', this)">
                <div>Prueffehler</div>
                <div class="score-value $(if($CheckErrorCount -gt 0){'score-warn'}else{'score-good'})">$CheckErrorCount</div>
                <div style="font-size: 12px; color: #94a3b8;">Klick: Nicht vollstaendig geprueft</div>
            </div>
        </div>

        <h2>Pruefergebnisse im Detail</h2>
"@

    $HtmlBody = ""
    foreach ($item in ($AllFindings | Sort-Object @{Expression = { if ($_.Schweregrad -eq "HOCH") { 0 } else { 1 } } })) {
        $BadgeClass = if ($item.Schweregrad -eq "HOCH") { "badge-fail" } else { "badge-warn" }
        $FilterKey = if ($item.Beschreibung -like "Versteckte Regel*") { "HIDDEN" }
                     elseif ($item.Beschreibung -like "Weiterleitung*") { "FORWARD" }
                     elseif ($item.FindingTyp -eq 'PRUEFUNG') { "CHECK" }
                     else { "ANMELDUNG" }

        $Recommendation = if ($item.FindingTyp -eq 'PRUEFUNG') {
            'Pruefung wiederholen und Berechtigungen/Erreichbarkeit des Postfachs kontrollieren.'
        } else {
            'Konto/Regel manuell pruefen, ggf. Passwort zuruecksetzen & Sitzungen widerrufen.'
        }

        $HtmlBody += @"
        <div class="accordion-item" data-filter="$FilterKey" data-group="FINDING">
            <div class="accordion-header" onclick="toggleAccordion(this)">
                <div>
                    <strong>$($item.DisplayName)</strong>
                    <span style="font-size: 12px; color: #94a3b8; margin-left: 10px;">$($item.UserPrincipalName)</span>
                </div>
                <div>
                    <span class="status-badge badge-type">$($item.FindingTyp)</span>
                    <span class="status-badge $BadgeClass">$($item.Schweregrad)</span>
                </div>
            </div>
            <div class="accordion-content">
                <div><strong>Fund:</strong> $($item.Beschreibung)</div>
                <div><strong>Details:</strong> $($item.Detail)</div>
                <div><span class="ref-tag">Empfehlung: $Recommendation</span></div>
            </div>
        </div>
"@
    }

    foreach ($Mbx in $OkMailboxes) {
        $MailboxTypeText = if ([string]::IsNullOrWhiteSpace([string]$Mbx.MailboxType)) { 'POSTFACH' } else { [string]$Mbx.MailboxType }
        $HtmlBody += @"
        <div class="accordion-item" data-filter="OK" data-group="OK">
            <div class="accordion-header" onclick="toggleAccordion(this)">
                <div>
                    <strong>$($Mbx.DisplayName)</strong>
                    <span style="font-size: 12px; color: #94a3b8; margin-left: 10px;">$($Mbx.UserPrincipalName)</span>
                </div>
                <div>
                    <span class="status-badge badge-type">$MailboxTypeText</span>
                    <span class="status-badge badge-good">OK</span>
                </div>
            </div>
            <div class="accordion-content">
                <div><strong>Status:</strong> Keine Auffaelligkeiten in den durchgefuehrten Pruefungen gefunden.</div>
                <div><strong>Postfachpruefung:</strong> Versteckte Regeln und externe Weiterleitungen wurden geprueft.</div>
                <div><span class="ref-tag">Anmeldeprotokolle werden zusaetzlich beruecksichtigt, sofern sie im Tenant verfuegbar sind.</span></div>
            </div>
        </div>
"@
    }

    if ($AllFindings.Count -eq 0 -and $OkMailboxes.Count -eq 0) {
        $HtmlBody = "<div class='accordion-item' data-filter='ALL'><div class='accordion-header'><div><strong>Keine auswertbaren Postfaecher gefunden</strong></div></div></div>"
    }

    $HtmlFooter = @"
    </div>
    <script>
        function toggleAccordion(element) {
            var content = element.nextElementSibling;
            if (content) { content.style.display = (content.style.display === "block") ? "none" : "block"; }
        }

        function filterByStatus(target, cardElem) {
            var cards = document.querySelectorAll('.card-clickable');
            if (cardElem && cardElem.classList.contains('active-filter')) {
                cards.forEach(c => c.classList.remove('active-filter'));
                applyFilter('ALL');
                return;
            }
            cards.forEach(c => c.classList.remove('active-filter'));
            if (cardElem) cardElem.classList.add('active-filter');
            applyFilter(target);
        }

        function applyFilter(target) {
            var items = document.querySelectorAll('.accordion-item');
            items.forEach(item => {
                var f = item.getAttribute('data-filter');
                var group = item.getAttribute('data-group');
                var show = (target === 'ALL') ||
                           (target === 'FINDING' && group === 'FINDING') ||
                           (f === target);
                item.style.display = show ? "" : "none";
            });
        }

        window.onscroll = function() {
            var topBtn = document.getElementById("scrollTopBtn");
            if (document.body.scrollTop > 300 || document.documentElement.scrollTop > 300) { topBtn.style.display = "block"; }
            else { topBtn.style.display = "none"; }
        };
        function scrollToTop() { window.scrollTo({top: 0, behavior: 'smooth'}); }
    </script>
</body>
</html>
"@

    ($HtmlHeader + $HtmlBody + $HtmlFooter) | Out-File -FilePath $HtmlFileName -Encoding utf8
    Write-Log "HTML-Report erfolgreich erstellt: $HtmlFileName"

    Update-Progress "Report abgeschlossen! Öffne Dashboard..."
    Start-Sleep -Milliseconds 400
    Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList ('"{0}"' -f $HtmlFileName)

} catch {
    $errorMessage = [string]$_.Exception.Message
    $errorLine = $_.InvocationInfo.ScriptLineNumber
    $errorPosition = [string]$_.InvocationInfo.PositionMessage
    $errorStack = [string]$_.ScriptStackTrace

    Write-Log "Fehler in Zeile ${errorLine}: $errorMessage"
    if ($errorPosition) { Write-Log "Position: $errorPosition" }
    if ($errorStack) { Write-Log "Stack: $errorStack" }

    if ($ProgressWindow) { $ProgressWindow.Close() }

    $DialogText = "Fehler bei der Verarbeitung: $errorMessage"
    if ($errorLine) { $DialogText += "`r`n`r`nSkriptzeile: $errorLine" }

    [System.Windows.Forms.MessageBox]::Show($DialogText, "Fehler", "OK", "Error")
    return
} finally {
    if ($GraphLoginJob) { Remove-Job -Job $GraphLoginJob -Force -ErrorAction SilentlyContinue }
    if ($ExoProcess -and -not $ExoProcess.HasExited) {
        try { $ExoProcess.Kill($true) } catch { }
    }
    foreach ($TempFile in @($ExoTempFiles)) {
        if ($TempFile) { Remove-Item -LiteralPath $TempFile -Force -ErrorAction SilentlyContinue }
    }
    if ($ProgressWindow) { $ProgressWindow.Close() }
}