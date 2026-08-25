param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [ValidateRange(1, 4096)]
    [int]$MaxMiB = 50
)

$ErrorActionPreference = 'Stop'
$resolvedPackage = (Resolve-Path -LiteralPath $PackagePath).Path
$package = Get-Item -LiteralPath $resolvedPackage
$packageMiB = $package.Length / 1MB

Write-Output ("Package: {0}" -f $package.FullName)
Write-Output ("Compressed size: {0:N2} MiB" -f $packageMiB)

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
try {
    $nativeEntries = $archive.Entries |
        Where-Object { $_.FullName -match '^lib/[^/]+/.+\.so$' }

    if ($nativeEntries.Count -gt 0) {
        Write-Output 'Native libraries by ABI:'
        $nativeEntries |
            Group-Object { ($_.FullName -split '/')[1] } |
            Sort-Object Name |
            ForEach-Object {
                $uncompressed = ($_.Group | Measure-Object Length -Sum).Sum / 1MB
                $compressed = ($_.Group | Measure-Object CompressedLength -Sum).Sum / 1MB
                Write-Output ("  {0}: {1:N2} MiB compressed, {2:N2} MiB uncompressed" -f `
                    $_.Name, $compressed, $uncompressed)
            }
    }
} finally {
    $archive.Dispose()
}

if ($package.Extension -eq '.aab') {
    Write-Warning 'An AAB contains files for multiple device configurations. Use the Play Console report for the per-device size.'
    exit 0
}

if ($packageMiB -gt $MaxMiB) {
    Write-Error ("Package exceeds the {0} MiB limit by {1:N2} MiB." -f `
        $MaxMiB, ($packageMiB - $MaxMiB))
}

Write-Output ("PASS: package is within the {0} MiB limit." -f $MaxMiB)
