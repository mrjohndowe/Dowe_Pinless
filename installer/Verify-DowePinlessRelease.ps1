[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ZipPath,
    [Parameter(Mandatory)] [string] $ManifestPath
)

$ErrorActionPreference = 'Stop'
$zip = (Get-Item -LiteralPath $ZipPath).FullName
$manifest = Get-Content -LiteralPath $ManifestPath
if ($manifest.Count -lt 3) { throw 'Release manifest is incomplete.' }

$expected = ($manifest[0] -split '\s+')[0].ToUpperInvariant()
$actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToUpperInvariant()
if ($actual -ne $expected) { throw 'Release ZIP hash does not match the manifest.' }

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
try {
    $required = @('DowePinlessService.exe', 'DowePinlessEnroll.exe', 'DowePinlessCredentialProvider.dll')
    $names = @($archive.Entries | ForEach-Object { $_.Name })
    foreach ($name in $required) {
        if ($name -notin $names) { throw "Release ZIP is missing required file: $name" }
    }
} finally {
    $archive.Dispose()
}

[pscustomobject]@{
    ZipPath = $zip
    Sha256 = $actual
    BuildRun = $manifest[1]
    Commit = $manifest[2]
    RequiredFilesPresent = $true
}

