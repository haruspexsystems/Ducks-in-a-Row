<#
.SYNOPSIS
    Installs the Ducks in a Row Windows Service.

.DESCRIPTION
    Registers Ducks in a Row as a Windows Service using sc.exe. For
    development use; production installs use the MSI, which also records the
    data directory in the registry.
    Must be run as Administrator.

.PARAMETER InstallPath
    Path to DucksInARow.Service.exe. Default: .\DucksInARow.Service.exe

.PARAMETER ServiceName
    Windows Service name. Default: DucksInARow

.PARAMETER DisplayName
    Display name in Services console. Default: Ducks in a Row Certificate Proxy

.PARAMETER StartType
    Startup type: auto, delayed-auto, demand. Default: auto
#>

param(
    [string]$InstallPath = (Join-Path $PSScriptRoot "DucksInARow.Service.exe"),
    [string]$ServiceName = "DucksInARow",
    [string]$DisplayName = "Ducks in a Row Certificate Proxy",
    [ValidateSet("auto", "delayed-auto", "demand")]
    [string]$StartType = "auto"
)

$ErrorActionPreference = "Stop"

# Check for admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

$exePath = Resolve-Path $InstallPath -ErrorAction SilentlyContinue
if (-not $exePath) {
    Write-Host "DucksInARow.Service.exe not found at: $InstallPath" -ForegroundColor Red
    exit 1
}

# Check if service already exists
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Service '$ServiceName' already exists (Status: $($existing.Status))." -ForegroundColor Yellow
    Write-Host "Use .\uninstall-service.ps1 to remove it first." -ForegroundColor Yellow
    exit 1
}

Write-Host "Installing the Ducks in a Row service..." -ForegroundColor Cyan
Write-Host "  Path: $exePath" -ForegroundColor Gray
Write-Host "  Name: $ServiceName" -ForegroundColor Gray
Write-Host "  Start: $StartType" -ForegroundColor Gray

sc.exe create $ServiceName `
    binPath= "`"$exePath`"" `
    DisplayName= "$DisplayName" `
    start= $StartType `
    obj= "LocalSystem" `
    depend= ""

sc.exe description $ServiceName "Ducks in a Row ACME-to-ADCS certificate proxy. Provides RFC 8555 ACME protocol access to Active Directory Certificate Services."
# Recovery actions, the same as the MSI's since issue #495 (util:ServiceConfig
# in Certus.wxs): restart 30 seconds after the first and second failures, no
# action on the third, and the count forgotten after a day. See "If the service
# stops" in docs/installation.md for why. The third entry must be an explicit
# none (the empty action between the two slashes): Windows repeats the last
# action in the list for every later failure, so a list of two restarts would
# restart for ever. Test-BuildScripts.ps1 holds this line to the MSI's values.
sc.exe failure $ServiceName reset= 86400 actions= restart/30000/restart/30000//0

Write-Host ""
Write-Host "Service installed successfully." -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Start the service: Start-Service $ServiceName"
Write-Host "  2. Open http://localhost:5000 and complete the setup wizard"
Write-Host "     (it discovers your CA, tests the connection, and applies the configuration)"
