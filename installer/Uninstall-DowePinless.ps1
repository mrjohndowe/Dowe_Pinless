[CmdletBinding(SupportsShouldProcess)] param([switch] $RemoveEnrollmentData)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this uninstaller from an elevated PowerShell session.' }
$target = Join-Path $env:ProgramFiles 'Dowe Pinless'; $clsid = '{852F9C7D-92B2-4F93-9CCB-1B707841D702}'
if ($PSCmdlet.ShouldProcess($target, 'Uninstall Dowe Pinless proof-of-concept')) {
    & sc.exe stop DowePinless 2>$null | Out-Null
    & sc.exe delete DowePinless 2>$null | Out-Null
    Remove-Item -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$clsid" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
    if ($RemoveEnrollmentData) { Remove-Item -LiteralPath (Join-Path $env:ProgramData 'Dowe Pinless') -Recurse -Force -ErrorAction SilentlyContinue; Write-Host 'Enrollment records were permanently removed.' }
    else { Write-Host 'Enrollment records were preserved. Pass -RemoveEnrollmentData to delete them.' }
    Write-Host 'Dowe Pinless uninstalled. Restart Windows to unload the Credential Provider DLL.'
}
