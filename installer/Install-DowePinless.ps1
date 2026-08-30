[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string] $BuildDirectory
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this installer from an elevated PowerShell session.' }
$source = (Resolve-Path -LiteralPath $BuildDirectory).Path
$required = 'DowePinlessService.exe','DowePinlessEnroll.exe','DowePinlessCredentialProvider.dll'
foreach ($name in $required) { if (-not (Test-Path -LiteralPath (Join-Path $source $name))) { throw "Missing build artifact: $name" } }
$target = Join-Path $env:ProgramFiles 'Dowe Pinless'
if ($PSCmdlet.ShouldProcess($target, 'Install Dowe Pinless proof-of-concept')) {
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    foreach ($name in $required) { Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $target $name) -Force }
    $serviceExe = Join-Path $target 'DowePinlessService.exe'
    $existingService = Get-Service -Name DowePinless -ErrorAction SilentlyContinue
    if ($null -eq $existingService) {
        & sc.exe create DowePinless binPath= "`"$serviceExe`"" start= auto DisplayName= 'Dowe Pinless Validator' | Out-Null
    }
    else {
        & sc.exe stop DowePinless 2>$null | Out-Null
        & sc.exe config DowePinless binPath= "`"$serviceExe`"" start= auto DisplayName= 'Dowe Pinless Validator' | Out-Null
    }
    & sc.exe description DowePinless 'Validates Dowe Pinless TOTP and single-use recovery codes.' | Out-Null
    & sc.exe failure DowePinless reset= 86400 actions= restart/5000/restart/15000/''/0 | Out-Null
    & sc.exe start DowePinless 2>$null | Out-Null
    $clsid = '{852F9C7D-92B2-4F93-9CCB-1B707841D702}'
    $comKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$clsid"
    $providerKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
    New-Item -Path "$comKey\InprocServer32" -Force | Out-Null
    Set-Item -Path "$comKey\InprocServer32" -Value (Join-Path $target 'DowePinlessCredentialProvider.dll')
    New-ItemProperty -Path "$comKey\InprocServer32" -Name ThreadingModel -Value Apartment -PropertyType String -Force | Out-Null
    New-Item -Path $providerKey -Force | Out-Null
    Set-Item -Path $providerKey -Value 'Dowe Pinless'
    Write-Host 'Dowe Pinless POC installed. Built-in Windows credential providers were not changed.'
    Write-Host "Enroll from an elevated console: $target\DowePinlessEnroll.exe"
}
