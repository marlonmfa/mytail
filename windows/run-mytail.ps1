[CmdletBinding()]
param(
    [string]$ServerUrl = $env:MYTAIL_SERVER_URL,
    [string]$MachineToken = $env:MYTAIL_MACHINE_TOKEN,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdministrator) {
    # Elevate before prompting, keeping the enrollment token out of the process list.
    $env:MYTAIL_SERVER_URL = $ServerUrl
    $env:MYTAIL_MACHINE_TOKEN = $MachineToken
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    if ($NoOpen) { $arguments += '-NoOpen' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
    exit
}

$candidates = @(@(
    $env:MYTAIL_AGENT,
    (Join-Path $PSScriptRoot 'mytail-agent.exe'),
    (Join-Path $env:ProgramFiles 'MyTail\mytail-agent.exe')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) })

if ($candidates.Count -eq 0) {
    $command = Get-Command mytail-agent.exe -ErrorAction SilentlyContinue
    if ($command) { $candidates = @($command.Source) }
}
if ($candidates.Count -eq 0) {
    throw 'mytail-agent.exe was not found. Install MyTail or place it beside this script.'
}
$agent = $candidates[0]

if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
    $ServerUrl = Read-Host 'MyTail server URL'
}
if ([string]::IsNullOrWhiteSpace($MachineToken)) {
    $secureToken = Read-Host 'Machine enrollment token' -AsSecureString
    $tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    try { $MachineToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer) }
}
if ([string]::IsNullOrWhiteSpace($ServerUrl) -or [string]::IsNullOrWhiteSpace($MachineToken)) {
    throw 'Server URL and token are required.'
}

$env:MYTAIL_SERVER_URL = $ServerUrl
$env:MYTAIL_MACHINE_TOKEN = $MachineToken
$agentArguments = @()
if (-not $NoOpen) { $agentArguments += '--open' }
Write-Host 'Starting MyTail. Press Ctrl+C to disconnect this directly-run agent.'
& $agent @agentArguments
exit $LASTEXITCODE
