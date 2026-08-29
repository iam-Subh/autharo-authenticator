[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$secretDirectory = 'D:\Autharo Secrets'
$keyStorePath = Join-Path $secretDirectory 'autharo-release.jks'
$fingerprintPath = Join-Path $secretDirectory 'autharo-release-fingerprints.txt'
$certificatePath = Join-Path $secretDirectory 'autharo-release-certificate.pem'
$instructionsPath = Join-Path $secretDirectory 'README.txt'
$propertiesPath = Join-Path $PSScriptRoot '..\android\key.properties'
$keyAlias = 'autharo'

$existingTargets = @(
    $keyStorePath,
    $fingerprintPath,
    $certificatePath,
    $propertiesPath
) | Where-Object { Test-Path -LiteralPath $_ }

if ($existingTargets.Count -gt 0) {
    throw "Release-signing output already exists. No file was overwritten: $($existingTargets -join ', ')"
}

$keyTool = (Get-Command keytool -ErrorAction Stop).Source

function New-RandomPassword {
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $characters = ''
        while ($characters.Length -lt 48) {
            $bytes = New-Object byte[] 48
            $generator.GetBytes($bytes)
            $characters += [Convert]::ToBase64String($bytes) -replace '[^A-Za-z0-9]', ''
        }
        return $characters.Substring(0, 48)
    }
    finally {
        $generator.Dispose()
    }
}

New-Item -ItemType Directory -Path $secretDirectory | Out-Null
$password = New-RandomPassword
$env:AUTHARO_RELEASE_PASSWORD = $password

try {
    & $keyTool -genkeypair -v `
        -keystore $keyStorePath `
        -storetype PKCS12 `
        -alias $keyAlias `
        -keyalg RSA `
        -keysize 4096 `
        -sigalg SHA256withRSA `
        -validity 10000 `
        -dname 'CN=Autharo Authenticator, OU=Android, O=Autharo, C=IN' `
        '-storepass:env' AUTHARO_RELEASE_PASSWORD `
        '-keypass:env' AUTHARO_RELEASE_PASSWORD

    if ($LASTEXITCODE -ne 0) {
        throw "keytool failed with exit code $LASTEXITCODE."
    }

    $properties = @"
storeFile=D:/Autharo Secrets/autharo-release.jks
storePassword=$password
keyAlias=$keyAlias
keyPassword=$password
"@
    [System.IO.File]::WriteAllText(
        [System.IO.Path]::GetFullPath($propertiesPath),
        $properties,
        [System.Text.UTF8Encoding]::new($false)
    )

    $details = & $keyTool -list -v `
        -keystore $keyStorePath `
        -alias $keyAlias `
        '-storepass:env' AUTHARO_RELEASE_PASSWORD 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "keytool could not read the generated key."
    }

    $fingerprints = $details | Where-Object { $_ -match '^\s*SHA(1|256):' }
    if ($fingerprints.Count -ne 2) {
        throw 'keytool did not return both SHA-1 and SHA-256 fingerprints.'
    }
    [System.IO.File]::WriteAllLines(
        $fingerprintPath,
        $fingerprints,
        [System.Text.UTF8Encoding]::new($false)
    )

    & $keyTool -exportcert -rfc `
        -keystore $keyStorePath `
        -alias $keyAlias `
        -file $certificatePath `
        '-storepass:env' AUTHARO_RELEASE_PASSWORD
    if ($LASTEXITCODE -ne 0) {
        throw 'keytool could not export the public signing certificate.'
    }

    $instructions = @"
Autharo Android release signing files

Private keystore:
$keyStorePath

Gradle signing configuration:
$([System.IO.Path]::GetFullPath($propertiesPath))

Public certificate:
$certificatePath

Public fingerprints:
$fingerprintPath

The password is stored only in the ignored key.properties file. Copy it to a
password manager. Back up the keystore and password separately. Never commit,
upload, or send the keystore or key.properties file.
"@
    [System.IO.File]::WriteAllText(
        $instructionsPath,
        $instructions,
        [System.Text.UTF8Encoding]::new($false)
    )
}
finally {
    Remove-Item Env:AUTHARO_RELEASE_PASSWORD -ErrorAction SilentlyContinue
    $password = $null
}

Write-Output 'Autharo release signing key created.'
Write-Output "Keystore: $keyStorePath"
Write-Output "Fingerprints: $fingerprintPath"
