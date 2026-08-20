[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Destination
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$wikiRoot = (Resolve-Path $Destination).Path

function Write-WikiPage {
    param(
        [Parameter(Mandatory)] [string]$Source,
        [Parameter(Mandatory)] [string]$Target,
        [Parameter(Mandatory)] [string]$SourceLabel
    )

    $body = Get-Content -LiteralPath $Source -Raw
    $header = "<!-- Generated from $SourceLabel. Edit the source file in the main repository. -->`n`n"
    Set-Content -LiteralPath $Target -Value ($header + $body) -Encoding utf8NoBOM
}

Write-WikiPage `
    -Source (Join-Path $repositoryRoot 'README.md') `
    -Target (Join-Path $wikiRoot 'Home.md') `
    -SourceLabel 'README.md'

Write-WikiPage `
    -Source (Join-Path $repositoryRoot 'CHANGELOG.md') `
    -Target (Join-Path $wikiRoot 'Changelog.md') `
    -SourceLabel 'CHANGELOG.md'

Write-WikiPage `
    -Source (Join-Path $repositoryRoot 'docs\Architecture.md') `
    -Target (Join-Path $wikiRoot 'Architecture.md') `
    -SourceLabel 'docs/Architecture.md'

Write-WikiPage `
    -Source (Join-Path $repositoryRoot 'docs\Operations.md') `
    -Target (Join-Path $wikiRoot 'Operations.md') `
    -SourceLabel 'docs/Operations.md'

$sidebar = @'
**Dowe Pinless**

- [[Home]]
- [[Architecture]]
- [[Operations]]
- [[Security]]
- [[Backup Recovery Codes|Backup-Recovery-Codes]]
- [[Development]]
- [[Changelog]]
'@
Set-Content -LiteralPath (Join-Path $wikiRoot '_Sidebar.md') -Value $sidebar -Encoding utf8NoBOM

