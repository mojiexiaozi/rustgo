$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $FilePath $($Arguments -join ' ')"
    }
}

function Invoke-CapturedNative {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [string[]]$Arguments = @()
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.Arguments = $Arguments -join " "
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Could not start captured command: $FilePath"
    }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    [PSCustomObject]@{
        ExitCode = $process.ExitCode
        Output = $stdout + $stderr
    }
}

$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryDirectory = Join-Path $systemTemp ("rustgo-e2e-" + [Guid]::NewGuid().ToString("N"))
$originalLocation = Get-Location
$originalTemp = $env:TEMP
$originalTmp = $env:TMP
$savedEnvironment = @{}
$environmentNames = @(
    "RUSTGO_E2E_BIN_PROFILE",
    "RUSTGO_SERVER_CERTIFICATE_FILE",
    "RUSTGO_SERVER_PRIVATE_KEY_FILE",
    "RUSTGO_CERTIFICATE_AUTHORITY_FILE",
    "RUSTGO_DEVICE_PRIVATE_KEY_FILE",
    "RUSTGO_DEVICE_PUBLIC_KEY"
)
foreach ($name in $environmentNames) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

try {
    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    $resolvedTemporaryDirectory = [IO.Path]::GetFullPath($temporaryDirectory)
    if (-not $resolvedTemporaryDirectory.StartsWith($systemTemp, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFileName($resolvedTemporaryDirectory)).StartsWith("rustgo-e2e-", [StringComparison]::Ordinal)) {
        throw "Refusing unsafe temporary directory: $resolvedTemporaryDirectory"
    }

    $env:TEMP = $resolvedTemporaryDirectory
    $env:TMP = $resolvedTemporaryDirectory
    $env:RUSTGO_E2E_BIN_PROFILE = "release"
    Set-Location -LiteralPath $workspace

    Invoke-Native -FilePath "cargo" -Arguments @("build", "--workspace", "--release")

    $clientDirectory = Join-Path $resolvedTemporaryDirectory "client"
    $serverDirectory = Join-Path $resolvedTemporaryDirectory "server"
    $clientKeyDirectory = Join-Path $clientDirectory "keys"
    $serverAuthorizedDirectory = Join-Path $serverDirectory "authorized"
    New-Item -ItemType Directory -Path $clientDirectory, $serverDirectory, $serverAuthorizedDirectory | Out-Null

    $clientBinary = Join-Path $workspace "target\release\rustgoc.exe"
    $serverBinary = Join-Path $workspace "target\release\rustgos.exe"
    Invoke-Native -FilePath $clientBinary -Arguments @("keygen", "-o", $clientKeyDirectory)

    $devicePublicFile = Join-Path $clientKeyDirectory "device.pub"
    $serverPublicFile = Join-Path $serverAuthorizedDirectory "device.pub"
    Copy-Item -LiteralPath $devicePublicFile -Destination $serverPublicFile

    $serverCertificate = Join-Path $serverDirectory "server.crt"
    $serverPrivateKey = Join-Path $serverDirectory "server.key"
    $certificateAuthority = Join-Path $clientDirectory "ca.crt"
    New-Item -ItemType File -Path $serverCertificate, $serverPrivateKey, $certificateAuthority | Out-Null

    $env:RUSTGO_SERVER_CERTIFICATE_FILE = $serverCertificate.Replace('\', '/')
    $env:RUSTGO_SERVER_PRIVATE_KEY_FILE = $serverPrivateKey.Replace('\', '/')
    $env:RUSTGO_CERTIFICATE_AUTHORITY_FILE = $certificateAuthority.Replace('\', '/')
    $env:RUSTGO_DEVICE_PRIVATE_KEY_FILE = (Join-Path $clientKeyDirectory "device.key").Replace('\', '/')
    $env:RUSTGO_DEVICE_PUBLIC_KEY = (Get-Content -Raw -LiteralPath $serverPublicFile).Trim()

    Invoke-Native -FilePath $serverBinary -Arguments @("check", "-c", (Join-Path $workspace "examples\server.toml"))
    Invoke-Native -FilePath $clientBinary -Arguments @("check", "-c", (Join-Path $workspace "examples\client.toml"))

    foreach ($binaryGate in @(
        @{ Binary = $serverBinary; Config = "server.toml"; Source = (Join-Path $workspace "examples\server.toml") },
        @{ Binary = $clientBinary; Config = "client.toml"; Source = (Join-Path $workspace "examples\client.toml") }
    )) {
        $gateDirectory = Join-Path $resolvedTemporaryDirectory ("default-" + [IO.Path]::GetFileNameWithoutExtension($binaryGate.Config))
        New-Item -ItemType Directory -Path $gateDirectory | Out-Null
        Copy-Item -LiteralPath $binaryGate.Source -Destination (Join-Path $gateDirectory $binaryGate.Config)
        $defaultResult = Invoke-CapturedNative -FilePath $binaryGate.Binary -WorkingDirectory $gateDirectory
        $explicitResult = Invoke-CapturedNative -FilePath $binaryGate.Binary -WorkingDirectory $gateDirectory -Arguments @("-c", $binaryGate.Config)
        if ($defaultResult.ExitCode -eq 0 -or $defaultResult.ExitCode -ne $explicitResult.ExitCode -or $defaultResult.Output -ne $explicitResult.Output) {
            throw "No-argument startup is not equivalent to explicit -c for $($binaryGate.Binary)"
        }
    }

    Invoke-Native -FilePath "cargo" -Arguments @("test", "-p", "rustgo-e2e", "--test", "tcp", "tcp_echo", "--", "--exact", "--test-threads=1")
    Invoke-Native -FilePath "cargo" -Arguments @("test", "-p", "rustgo-e2e", "--test", "udp", "udp_echo", "--", "--exact", "--test-threads=1")
}
finally {
    Set-Location $originalLocation
    $env:TEMP = $originalTemp
    $env:TMP = $originalTmp
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], "Process")
    }

    if (Test-Path -LiteralPath $temporaryDirectory) {
        $cleanupTarget = [IO.Path]::GetFullPath($temporaryDirectory)
        if ($cleanupTarget.StartsWith($systemTemp, [StringComparison]::OrdinalIgnoreCase) -and
            ([IO.Path]::GetFileName($cleanupTarget)).StartsWith("rustgo-e2e-", [StringComparison]::Ordinal)) {
            Remove-Item -LiteralPath $cleanupTarget -Recurse -Force
        }
        else {
            Write-Error "Refusing unsafe cleanup target: $cleanupTarget"
        }
    }
}
