<#
.SYNOPSIS
    Installs the appEcosystem Hub & Registry runtime on Windows to an internal-disk
    virtual environment (%LOCALAPPDATA%\Ecosystem) and registers it as an OS service
    via pywin32, NSSM, or a User Logon Scheduled Task fallback.
#>
[CmdletBinding()]
param(
    [string]$PythonBin = "python",
    [int]$Port = 8500,
    [ValidateSet("local", "lan")]
    [string]$Mode = "local"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Prefix = Join-Path $env:LOCALAPPDATA "Ecosystem"
$VenvDir = Join-Path $Prefix "venv"
$DataDir = Join-Path $Prefix "data"
$LogDir  = Join-Path $Prefix "logs"

New-Item -ItemType Directory -Force -Path $Prefix, $DataDir, $LogDir | Out-Null

Write-Host "==> Provisioning appEcosystem Windows runtime in $Prefix"
if (-not (Test-Path (Join-Path $VenvDir "Scripts\python.exe"))) {
    & $PythonBin -m venv $VenvDir
}
$VenvPy  = Join-Path $VenvDir "Scripts\python.exe"
$VenvPip = Join-Path $VenvDir "Scripts\pip.exe"

& $VenvPip install --upgrade pip wheel | Out-Null
& $VenvPip install $RepoRoot `
    (Join-Path $RepoRoot "auth\python") `
    (Join-Path $RepoRoot "packages\ecosystem-ai") `
    (Join-Path $RepoRoot "packages\ecosystem-client") `
    (Join-Path $RepoRoot "packages\ecosystem-hub")

# Provision shared HMAC secret with restricted user-only ACL
$SecretDir = Join-Path $env:USERPROFILE ".config\ecosystem"
New-Item -ItemType Directory -Force -Path $SecretDir | Out-Null
& $VenvPy -c "from ecosystem_auth.tokens import ensure_ecosystem_secret; ensure_ecosystem_secret()"
$SecretFile = Join-Path $SecretDir "secret.env"
if (Test-Path $SecretFile) {
    icacls $SecretFile /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
}
Write-Host "==> Shared HMAC secret ready ($SecretFile)"

$SvcScript = Join-Path $RepoRoot "scripts\windows_service.py"
$NssmCmd = Get-Command nssm -ErrorAction SilentlyContinue

# Prefer NSSM if installed, else pywin32 if available, else Scheduled Task ONLOGON
if ($null -ne $NssmCmd) {
    Write-Host "==> Registering Windows Service via NSSM (EcosystemHubService)"
    & nssm install EcosystemHubService $VenvPy "`"$SvcScript`" run"
    & nssm set EcosystemHubService AppDirectory $Prefix
    & nssm set EcosystemHubService AppStdout (Join-Path $LogDir "hub.stdout.log")
    & nssm set EcosystemHubService AppStderr (Join-Path $LogDir "hub.stderr.log")
    & nssm set EcosystemHubService AppEnvironmentExtra "ECOSYSTEM_MODE=$Mode" "ECOSYSTEM_REGISTRY_PORT=$Port"
    & nssm start EcosystemHubService
} else {
    $HasPyWin32 = $false
    try {
        & $VenvPy -c "import win32serviceutil" 2>$null
        if ($LASTEXITCODE -eq 0) { $HasPyWin32 = $true }
    } catch {}

    if ($HasPyWin32) {
        Write-Host "==> Registering Windows Service via pywin32 (EcosystemHubService)"
        & $VenvPy $SvcScript --startup auto install
        & $VenvPy $SvcScript start
    } else {
        Write-Host "==> Neither NSSM nor pywin32 found; registering Scheduled Task (EcosystemHubUserAgent)"
        $Action = New-ScheduledTaskAction -Execute $VenvPy -Argument "`"$SvcScript`" run" -WorkingDirectory $Prefix
        $Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
        Register-ScheduledTask -TaskName "EcosystemHubUserAgent" -Action $Action -Trigger $Trigger -Force | Out-Null
        Start-ScheduledTask -TaskName "EcosystemHubUserAgent"
    }
}

Write-Host "==> appEcosystem Hub Windows installation complete (port $Port, mode $Mode)."

