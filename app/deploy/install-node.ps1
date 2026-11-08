<#
SigmaDesk node installer. Run in an administrator PowerShell on the computer you want to control
remotely (for example inside your RDP session on that computer):

  irm http://<server>:21180/download/install-node.ps1 -OutFile $env:TEMP\install-node.ps1
  powershell -ExecutionPolicy Bypass -File $env:TEMP\install-node.ps1 -Server http://<server>:21180 -Team default -Key <node key>

It mirrors Parsec's "Per Computer" team-computer install (installer flags /percomputer /silent
/team_id= /team_computer_key=): one account for the machine, settings in %ProgramData%, works
before anyone logs in, and the app starts silently in the background.

Steps: download sigmadesk.exe from the SigmaDesk server -> install RustDesk silently if missing
-> optional RustDesk permanent password for unattended access -> register this computer with the
node key (sigmadesk.exe --provision ... --per-computer) -> start-up task running
"sigmadesk.exe --host-service" as SYSTEM -> sigmadesk:// link -> start it now.
Use -Uninstall to remove SigmaDesk (RustDesk is left installed).
#>
param(
    [string]$Server = "",
    [string]$Team = "default",
    [string]$Key = "",
    [string]$InstallDir = "$env:ProgramFiles\SigmaDesk",
    # A local path or URL of the RustDesk installer. Empty = the GitHub release below.
    [string]$RustDeskInstaller = "",
    # RustDesk release used when downloading from GitHub (estimated; change to the version you use).
    [string]$RustDeskVersion = "1.4.2",
    # Optional permanent RustDesk password so the node can be controlled without someone clicking Accept.
    [string]$NodePassword = "",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$TaskName = "SigmaDesk Host"

function Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Run this script in an administrator PowerShell." }

if ($Uninstall) {
    Step "Removing SigmaDesk"
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-Process sigmadesk -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item "HKLM:\Software\Classes\sigmadesk" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:ProgramData\SigmaDesk" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "SigmaDesk removed. RustDesk was left installed." -ForegroundColor Green
    return
}

if (-not $Server -or -not $Key) { throw "Give -Server and -Key (copy the command from the admin console)." }
$Server = $Server.TrimEnd('/')

Step "Checking the SigmaDesk server $Server"
Invoke-WebRequest -Uri "$Server/" -UseBasicParsing -TimeoutSec 10 | Out-Null

Step "Installing the SigmaDesk client to $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Get-Process sigmadesk -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
$exe = Join-Path $InstallDir "sigmadesk.exe"
Invoke-WebRequest -Uri "$Server/download/sigmadesk.exe" -OutFile $exe -UseBasicParsing

$rustdesk = Join-Path $env:ProgramFiles "RustDesk\rustdesk.exe"
if (-not (Test-Path $rustdesk)) {
    Step "Installing RustDesk (screen and input engine)"
    $setup = Join-Path $env:TEMP "rustdesk-setup.exe"
    if ($RustDeskInstaller -and (Test-Path $RustDeskInstaller)) {
        Copy-Item $RustDeskInstaller $setup -Force
    } else {
        $url = if ($RustDeskInstaller) { $RustDeskInstaller } else { "https://github.com/rustdesk/rustdesk/releases/download/$RustDeskVersion/rustdesk-$RustDeskVersion-x86_64.exe" }
        Write-Host "    downloading $url"
        Invoke-WebRequest -Uri $url -OutFile $setup -UseBasicParsing
    }
    Start-Process -FilePath $setup -ArgumentList "--silent-install" -Wait
    for ($i = 0; $i -lt 60 -and -not (Test-Path $rustdesk); $i++) { Start-Sleep -Seconds 2 }
    if (-not (Test-Path $rustdesk)) { throw "RustDesk did not install. Install it by hand and run this script again." }
    Start-Sleep -Seconds 5
} else {
    Step "RustDesk already installed"
}

if ($NodePassword) {
    Step "Setting the RustDesk permanent password (unattended access)"
    Start-Process -FilePath $rustdesk -ArgumentList "--password", $NodePassword -Wait -WindowStyle Hidden
}

Step "Registering this computer with the node key"
$p = Start-Process -FilePath $exe -ArgumentList "--provision", $Server, $Team, $Key, "--per-computer" -Wait -PassThru -WindowStyle Hidden
$log = Join-Path $env:ProgramData "SigmaDesk\sigmadesk.log"
if (Test-Path $log) { Get-Content $log -Tail 8 | ForEach-Object { Write-Host "    $_" } }
if ($p.ExitCode -ne 0) { throw "Registration failed (exit code $($p.ExitCode)). Check the key and the server address." }

Step "Start-up task '$TaskName' (runs sigmadesk --host-service as SYSTEM)"
$action = New-ScheduledTaskAction -Execute $exe -Argument "--host-service"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Step "Registering the sigmadesk:// link"
New-Item -Path "HKLM:\Software\Classes\sigmadesk\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Classes\sigmadesk" -Name "(default)" -Value "URL:sigmadesk Protocol"
Set-ItemProperty -Path "HKLM:\Software\Classes\sigmadesk" -Name "URL Protocol" -Value ""
Set-ItemProperty -Path "HKLM:\Software\Classes\sigmadesk\shell\open\command" -Name "(default)" -Value "`"$exe`" `"%1`""

Write-Host ""
Write-Host "Done. This computer ($env:COMPUTERNAME) now appears in the admin console node list;" -ForegroundColor Green
Write-Host "use 'SigmaDesk로 제어' there to control it instead of RDP." -ForegroundColor Green
