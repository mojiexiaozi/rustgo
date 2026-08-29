param(
    [switch]$StartupGateOnly
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ("Command failed with exit code {0}: {1} {2}" -f $LASTEXITCODE, $FilePath, ($Arguments -join " "))
    }
}

function Start-ManagedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [string[]]$Arguments = @()
    )

    $script:managedProcessSequence += 1
    $stdoutFile = Join-Path $script:resolvedTemporaryDirectory ("process-{0}-{1}.stdout.log" -f $script:managedProcessSequence, $Name)
    $stderrFile = Join-Path $script:resolvedTemporaryDirectory ("process-{0}-{1}.stderr.log" -f $script:managedProcessSequence, $Name)
    $parameters = @{
        FilePath = $FilePath
        WorkingDirectory = $WorkingDirectory
        PassThru = $true
        WindowStyle = "Hidden"
        RedirectStandardOutput = $stdoutFile
        RedirectStandardError = $stderrFile
    }
    if ($null -ne $Arguments -and @($Arguments).Count -gt 0) {
        $parameters.ArgumentList = $Arguments
    }

    # File redirection drains stdout and stderr independently while the child
    # runs, so readiness polling cannot deadlock on a full anonymous pipe.
    $process = Start-Process @parameters
    $record = [PSCustomObject]@{
        Name = $Name
        Process = $process
        StdoutFile = $stdoutFile
        StderrFile = $stderrFile
    }
    [void]$script:managedProcesses.Add($record)
    return $record
}

function Get-ManagedOutput {
    param([Parameter(Mandatory = $true)]$Record)

    $stdout = if (Test-Path -LiteralPath $Record.StdoutFile) {
        Get-Content -Raw -LiteralPath $Record.StdoutFile
    }
    else {
        ""
    }
    $stderr = if (Test-Path -LiteralPath $Record.StderrFile) {
        Get-Content -Raw -LiteralPath $Record.StderrFile
    }
    else {
        ""
    }
    return $stdout + [Environment]::NewLine + $stderr
}

function Wait-ForManagedOutput {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [int]$TimeoutSeconds = 15
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $output = Get-ManagedOutput -Record $Record
        if ($output.Contains($Pattern)) {
            return $output
        }
        $Record.Process.Refresh()
        if ($Record.Process.HasExited) {
            throw ("{0} exited before readiness marker '{1}' (exit {2}):{3}{4}" -f $Record.Name, $Pattern, $Record.Process.ExitCode, [Environment]::NewLine, $output)
        }
        Start-Sleep -Milliseconds 100
    }
    throw ("{0} did not reach readiness marker '{1}' before the {2}s deadline:{3}{4}" -f $Record.Name, $Pattern, $TimeoutSeconds, [Environment]::NewLine, (Get-ManagedOutput -Record $Record))
}

function Stop-ManagedProcess {
    param([Parameter(Mandatory = $true)]$Record)

    $Record.Process.Refresh()
    if (-not $Record.Process.HasExited) {
        $Record.Process.Kill()
    }
    if (-not $Record.Process.WaitForExit(10000)) {
        throw "Owned process $($Record.Name) did not exit within the 10s reap deadline"
    }
}

function Write-StartupServerConfig {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$CertificateFile,
        [Parameter(Mandatory = $true)][string]$PrivateKeyFile,
        [Parameter(Mandatory = $true)][string]$PublicKey,
        [Parameter(Mandatory = $true)][int]$Port
    )

    @"
[server]
bind_addr = "127.0.0.1:$Port"
certificate_file = "$CertificateFile"
private_key_file = "$PrivateKeyFile"
heartbeat_timeout_secs = 10

[limits]
max_clients = 4
max_tunnels_per_client = 4
max_tcp_connections_per_tunnel = 4
max_udp_sessions_per_tunnel = 4
max_udp_payload_bytes = 65507

[[clients]]
name = "home-pc"
public_key = "$PublicKey"
enabled = true
"@ | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Write-StartupClientConfig {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServerAddress,
        [Parameter(Mandatory = $true)][string]$CertificateAuthorityFile,
        [Parameter(Mandatory = $true)][string]$PrivateKeyFile
    )

    @"
[client]
name = "home-pc"
server_addr = "$ServerAddress"
server_name = "localhost"
certificate_authority_file = "$CertificateAuthorityFile"
private_key_file = "$PrivateKeyFile"
heartbeat_interval_secs = 2
"@ | Set-Content -LiteralPath $Path -Encoding UTF8
}

$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryDirectory = Join-Path $systemTemp ("rustgo-e2e-" + [Guid]::NewGuid().ToString("N"))
$originalLocation = Get-Location
$originalTemp = $env:TEMP
$originalTmp = $env:TMP
$managedProcesses = [Collections.ArrayList]::new()
$managedProcessSequence = 0
$resolvedTemporaryDirectory = $null
$savedEnvironment = @{}
$environmentNames = @(
    "RUST_LOG",
    "RUSTGO_E2E_BIN_PROFILE",
    "RUSTGO_SERVER_UDP_BIND_IP",
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
    $env:RUST_LOG = "info"
    $env:RUSTGO_E2E_BIN_PROFILE = "release"
    Set-Location -LiteralPath $workspace

    Invoke-Native -FilePath "cargo" -Arguments @("build", "--workspace", "--release")

    $clientDirectory = Join-Path $resolvedTemporaryDirectory "client"
    $serverDirectory = Join-Path $resolvedTemporaryDirectory "server"
    $clientKeyDirectory = Join-Path $clientDirectory "keys"
    $serverAuthorizedDirectory = Join-Path $serverDirectory "authorized"
    $pkiDirectory = Join-Path $resolvedTemporaryDirectory "pki"
    New-Item -ItemType Directory -Path $clientDirectory, $serverDirectory, $serverAuthorizedDirectory, $pkiDirectory | Out-Null

    $clientBinary = Join-Path $workspace "target\release\rustgoc.exe"
    $serverBinary = Join-Path $workspace "target\release\rustgos.exe"
    $pkiGenerator = Join-Path $workspace "target\release\generate_ephemeral_pki.exe"
    $portAllocator = Join-Path $workspace "target\release\find_available_tcp_port.exe"
    Invoke-Native -FilePath $clientBinary -Arguments @("keygen", "-o", $clientKeyDirectory)
    Invoke-Native -FilePath $pkiGenerator -Arguments @($pkiDirectory, "localhost")

    $devicePublicFile = Join-Path $clientKeyDirectory "device.pub"
    $serverPublicFile = Join-Path $serverAuthorizedDirectory "device.pub"
    Copy-Item -LiteralPath $devicePublicFile -Destination $serverPublicFile

    $serverCertificate = Join-Path $pkiDirectory "server.crt"
    $serverPrivateKey = Join-Path $pkiDirectory "server.key"
    $certificateAuthority = Join-Path $pkiDirectory "ca.crt"
    $devicePrivateKey = Join-Path $clientKeyDirectory "device.key"
    $devicePublicKey = (Get-Content -Raw -LiteralPath $serverPublicFile).Trim()

    $env:RUSTGO_SERVER_CERTIFICATE_FILE = $serverCertificate.Replace('\', '/')
    $env:RUSTGO_SERVER_PRIVATE_KEY_FILE = $serverPrivateKey.Replace('\', '/')
    $env:RUSTGO_SERVER_UDP_BIND_IP = "127.0.0.1"
    $env:RUSTGO_CERTIFICATE_AUTHORITY_FILE = $certificateAuthority.Replace('\', '/')
    $env:RUSTGO_DEVICE_PRIVATE_KEY_FILE = $devicePrivateKey.Replace('\', '/')
    $env:RUSTGO_DEVICE_PUBLIC_KEY = $devicePublicKey

    Invoke-Native -FilePath $serverBinary -Arguments @("check", "-c", (Join-Path $workspace "examples\server.toml"))
    Invoke-Native -FilePath $clientBinary -Arguments @("check", "-c", (Join-Path $workspace "examples\client.toml"))

    foreach ($invocation in @("default", "explicit")) {
        $gateDirectory = Join-Path $resolvedTemporaryDirectory "startup-$invocation"
        New-Item -ItemType Directory -Path $gateDirectory | Out-Null
        $serverConfig = Join-Path $gateDirectory "server.toml"
        $clientConfig = Join-Path $gateDirectory "client.toml"
        $serverPort = & $portAllocator
        if ($LASTEXITCODE -ne 0) {
            throw "Could not allocate a loopback TCP port for startup readiness"
        }
        Write-StartupServerConfig -Path $serverConfig -CertificateFile $serverCertificate.Replace('\', '/') -PrivateKeyFile $serverPrivateKey.Replace('\', '/') -PublicKey $devicePublicKey -Port ([int]$serverPort.Trim())

        $serverArguments = if ($invocation -eq "explicit") { @("-c", "server.toml") } else { @() }
        $server = Start-ManagedProcess -Name "$invocation-server" -FilePath $serverBinary -WorkingDirectory $gateDirectory -Arguments $serverArguments
        $serverOutput = Wait-ForManagedOutput -Record $server -Pattern "event=server_listening"
        $addressMatch = [regex]::Match($serverOutput, "address=([^\s]+)")
        if (-not $addressMatch.Success) {
            throw ("Could not recover listening address from {0} server output:{1}{2}" -f $invocation, [Environment]::NewLine, $serverOutput)
        }
        Write-StartupClientConfig -Path $clientConfig -ServerAddress $addressMatch.Groups[1].Value -CertificateAuthorityFile $certificateAuthority.Replace('\', '/') -PrivateKeyFile $devicePrivateKey.Replace('\', '/')

        $clientArguments = if ($invocation -eq "explicit") { @("-c", "client.toml") } else { @() }
        $client = Start-ManagedProcess -Name "$invocation-client" -FilePath $clientBinary -WorkingDirectory $gateDirectory -Arguments $clientArguments
        [void](Wait-ForManagedOutput -Record $client -Pattern "event=registration_ready")
        Stop-ManagedProcess -Record $client
        Stop-ManagedProcess -Record $server
    }

    if (-not $StartupGateOnly) {
        Invoke-Native -FilePath "cargo" -Arguments @("test", "-p", "rustgo-e2e", "--test", "tcp", "tcp_echo", "--", "--exact", "--test-threads=1")
        Invoke-Native -FilePath "cargo" -Arguments @("test", "-p", "rustgo-e2e", "--test", "udp", "udp_echo", "--", "--exact", "--test-threads=1")
        Invoke-Native -FilePath "cargo" -Arguments @("test", "-p", "rustgo-e2e", "--test", "p2p", "--", "--test-threads=1")
    }
}
finally {
    foreach ($record in $managedProcesses) {
        try {
            Stop-ManagedProcess -Record $record
        }
        catch {
            Write-Warning "Could not reap owned process $($record.Name): $_"
        }
    }

    Set-Location -LiteralPath $originalLocation.Path
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
