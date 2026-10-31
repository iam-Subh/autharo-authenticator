# Builds the signed Android release, and installs it only if the build succeeded.
#
#   .\scripts\build_release.ps1            build only
#   .\scripts\build_release.ps1 -Install   build, then install on the connected phone
#
# The pins name the root authorities Render issues api.authfactor.app from.
# They are public values, not secrets. See docs/production-security.md before
# changing them.

param([switch]$Install)

# Not 'Stop': Windows PowerShell 5.1 turns anything a native command writes to
# stderr into a terminating error, and flutter writes ordinary warnings there.
# Each native step is checked through $LASTEXITCODE instead.

$env:AUTHCORE_PINNED_HOST = 'api.authfactor.app'
$env:AUTHCORE_SPKI_PINS = @(
    'C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=' # ISRG Root X1        (Let's Encrypt)
    'diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=' # ISRG Root X2        (Let's Encrypt)
    'hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=' # GTS Root R1         (Google Trust Services)
    'QXnt2YHvdHR3tJYmQIr0Paosp6t/nggsEGD4QJZ3Q0g=' # GTS Root R3         (Google Trust Services)
    'mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=' # GTS Root R4         (Google Trust Services)
) -join ','

$app = Join-Path $PSScriptRoot '..\app'
Push-Location $app
try {
    if (-not (Test-Path 'android\key.properties')) {
        throw 'android\key.properties is missing, so the APK cannot be release-signed.'
    }

    flutter build apk --release --split-per-abi
    if ($LASTEXITCODE -ne 0) { throw "flutter build failed with exit code $LASTEXITCODE. Nothing was installed." }

    $apk = 'build\app\outputs\flutter-apk\app-arm64-v8a-release.apk'
    if (-not (Test-Path $apk)) { throw "$apk was not produced. Nothing was installed." }
    Write-Host "Built $apk"

    if ($Install) {
        # Never uninstall here: that deletes the phone's vault. A failed install
        # is reported and left for a person to decide about.
        adb install -r $apk
        if ($LASTEXITCODE -ne 0) {
            throw 'adb install failed. If it says INSTALL_FAILED_UPDATE_INCOMPATIBLE, the installed app has a different signing key; back up its vault before uninstalling it.'
        }
    }
} finally {
    Pop-Location
}
