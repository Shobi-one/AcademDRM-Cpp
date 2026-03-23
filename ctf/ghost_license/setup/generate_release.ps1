$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceDir = Join-Path $scriptRoot '..\source'
$challengeDir = Join-Path $scriptRoot '..\challenge'
$buildDir = Join-Path $sourceDir 'build'

cmake -S $sourceDir -B $buildDir -DCMAKE_BUILD_TYPE=Release
cmake --build $buildDir --config Release

$releaseBinary = Join-Path $buildDir 'Release\GhostLicense.exe'
$fallbackBinary = Join-Path $buildDir 'GhostLicense.exe'

if (Test-Path $releaseBinary) {
    Copy-Item $releaseBinary (Join-Path $challengeDir 'GhostLicense.exe') -Force
} elseif (Test-Path $fallbackBinary) {
    Copy-Item $fallbackBinary (Join-Path $challengeDir 'GhostLicense.exe') -Force
} else {
    throw 'Could not find GhostLicense binary after build.'
}

Write-Host 'Challenge binary copied to challenge\GhostLicense.exe'
