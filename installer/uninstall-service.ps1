<#
.SYNOPSIS
    Uninstalls the Ducks in a Row Windows Service.

.DESCRIPTION
    Stops and removes the Ducks in a Row Windows Service.
    Must be run as Administrator. Does NOT remove data files.

.PARAMETER ServiceName
    Windows Service name. Default: DucksInARow
#>

param(
    [string]$ServiceName = "DucksInARow"
)

$ErrorActionPreference = "Stop"

# Check for admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host "Service '$ServiceName' not found." -ForegroundColor Yellow
    exit 0
}

# Stop if running
if ($existing.Status -eq "Running") {
    Write-Host "Stopping service..." -ForegroundColor Yellow
    Stop-Service $ServiceName -Force
    Start-Sleep -Seconds 2
}

Write-Host "Removing service '$ServiceName'..." -ForegroundColor Yellow
sc.exe delete $ServiceName

Write-Host ""
Write-Host "Service removed successfully." -ForegroundColor Green
Write-Host ""
Write-Host "Note: Data files in the data directory (default %ProgramData%\Ducks in a Row) were NOT removed." -ForegroundColor DarkYellow
Write-Host "Delete them manually if no longer needed." -ForegroundColor DarkYellow
