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
# Recovery actions, for development boxes only. The MSI deliberately does not
# configure these, and never has: see "If the service stops" in
# docs/installation.md for the reasoning. Do not read this line as a
# description of what a production install does. The installation guide once
# did, and was wrong about the product for as long as it said so (issue #338).
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000

Write-Host ""
Write-Host "Service installed successfully." -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Start the service: Start-Service $ServiceName"
Write-Host "  2. Open http://localhost:5000 and complete the setup wizard"
Write-Host "     (it discovers your CA, tests the connection, and applies the configuration)"
