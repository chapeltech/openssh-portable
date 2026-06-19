$ErrorActionPreference = 'Stop'

$realm = 'EXAMPLE.COM'
$userName = 'user'
$userPrincipal = "$userName@$realm"
$userPassword = 'GssproxyUser!2026'
$computerPassword = 'GssproxyHost!2026'
$kdcHost = 'kdc1.example.com'
$linuxHost = 'linux.example.com'
$windowsHost = 'win.example.com'
$linuxPort = 2222
$windowsPort = 2223

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$logRoot = Join-Path $repo 'gsskex-interop-logs'
$testRoot = Join-Path $repo 'gsskex-interop'
$buildDir = Join-Path $repo 'bin\x64\Release'
$linuxWork = '/tmp/openssh-gsskex-interop'
New-Item -ItemType Directory -Path $logRoot, $testRoot -Force | Out-Null

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$File failed with exit code $LASTEXITCODE"
    }
}

function Quote-CmdArg([string]$Arg) {
    '"' + ($Arg -replace '"', '\"') + '"'
}

function Join-CmdLine([string[]]$Items) {
    ($Items | ForEach-Object { Quote-CmdArg $_ }) -join ' '
}

function Add-HostsLine([string]$Line) {
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $current = if (Test-Path $hosts) { Get-Content $hosts -Raw } else { '' }
    if ($current -notmatch [regex]::Escape($Line)) {
        Add-Content -Path $hosts -Value $Line
    }
}

function Convert-ToWslPath([string]$Path) {
    $full = (Resolve-Path $Path).Path
    if ($full -match '^([A-Za-z]):\\(.*)$') {
        $drive = $Matches[1].ToLowerInvariant()
        $rest = $Matches[2] -replace '\\', '/'
        return "/mnt/$drive/$rest"
    }
    throw "cannot convert path to WSL form: $Path"
}

function Remove-TestNrptRule() {
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Comment -eq 'OpenSSH GSS KEX test' } |
        ForEach-Object {
            Remove-DnsClientNrptRule -Name $_.Name -Force `
                -ErrorAction SilentlyContinue
        }
}

function Wait-TestTcpPort([int]$Port) {
    $deadline = (Get-Date).AddSeconds(20)
    do {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(500)) {
                $client.EndConnect($async)
                return
            }
        } catch {
        } finally {
            $client.Close()
        }
        if ($script:locatorProcess -and $script:locatorProcess.HasExited) {
            throw "Windows Kerberos locator helper exited while waiting for TCP port $Port"
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    throw "Windows Kerberos locator helper did not open TCP port $Port"
}

function Start-TestLocator([string]$WslIp) {
    $locator = Join-Path $repo '.github\scripts\gsskex-locator.py'
    $locatorLog = Join-Path $logRoot 'locator.log'
    $locatorOut = Join-Path $logRoot 'locator.out.log'
    $locatorErr = Join-Path $logRoot 'locator.err.log'
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    $locatorArgs = @(
        $locator,
        '--realm', $realm,
        '--kdc-udp-target', $WslIp,
        '--kdc-udp-port', '88',
        '--kdc-tcp-target', '127.0.0.1',
        '--kdc-tcp-port', '88',
        '--kdc-tcp-via-wsl',
        '--wsl-distribution', 'Debian-12',
        '--log', $locatorLog
    )

    if (-not $python) {
        $python = Get-Command py.exe -ErrorAction Stop
        $locatorArgs = @('-3') + $locatorArgs
    }

    Remove-TestNrptRule
    Add-DnsClientNrptRule `
        -Namespace @($realm, ".$realm") `
        -NameServers '127.0.0.1' `
        -Comment 'OpenSSH GSS KEX test' |
        Out-Null

    $script:locatorProcess = Start-Process `
        -FilePath $python.Source `
        -ArgumentList $locatorArgs `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput $locatorOut `
        -RedirectStandardError $locatorErr
    Start-Sleep -Seconds 2
    if ($script:locatorProcess.HasExited) {
        if (Test-Path $locatorErr) {
            Get-Content $locatorErr
        }
        throw 'Windows Kerberos locator helper exited early'
    }
    "Locator PID: $($script:locatorProcess.Id)" |
        Out-File -FilePath (Join-Path $logRoot 'network.txt') -Append
    "Locator command: $($python.Source) $(Join-CmdLine $locatorArgs)" |
        Out-File -FilePath (Join-Path $logRoot 'network.txt') -Append
    Wait-TestTcpPort 53
    Wait-TestTcpPort 88
    Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 53 `
        -ErrorAction SilentlyContinue |
        Format-List |
        Out-File -FilePath (Join-Path $logRoot 'network.txt') -Append
    Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 88 `
        -ErrorAction SilentlyContinue |
        Format-List |
        Out-File -FilePath (Join-Path $logRoot 'network.txt') -Append
    Get-NetUDPEndpoint -LocalAddress 127.0.0.1 -LocalPort 88 `
        -ErrorAction SilentlyContinue |
        Format-List |
        Out-File -FilePath (Join-Path $logRoot 'network.txt') -Append
}

function Stop-TestLocator() {
    if ($script:locatorProcess -and -not $script:locatorProcess.HasExited) {
        Stop-Process -Id $script:locatorProcess.Id -Force `
            -ErrorAction SilentlyContinue
    }
    Remove-TestNrptRule
}

function Compile-RunNetonly() {
    $source = Join-Path $repo '.github\scripts\run_netonly.c'
    $out = Join-Path $testRoot 'run_netonly.exe'
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vsPath = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
    if (-not $vsPath) {
        throw 'Visual Studio with VC tools was not found'
    }
    $vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'
    $cmd = 'call ' + (Quote-CmdArg $vcvars) + ' >nul && cl /nologo /W4 /O2 ' +
        (Quote-CmdArg $source) + ' /Fe:' + (Quote-CmdArg $out) +
        ' advapi32.lib'
    $null = Invoke-Checked cmd.exe @('/c', $cmd)
    return $out
}

function Invoke-NetonlyCommand(
    [string]$Name,
    [string[]]$CommandArgs,
    [string]$Log
) {
    $cmdFile = Join-Path $testRoot "run-$Name.cmd"
    $commandLine = (Join-CmdLine $CommandArgs) + ' > ' +
        (Quote-CmdArg $Log) + ' 2>&1'
    Set-Content -Path $cmdFile -Encoding ASCII -Value @(
        '@echo off',
        ('cd /d ' + (Quote-CmdArg $testRoot)),
        $commandLine,
        'exit /b %ERRORLEVEL%'
    )

    $env:RUN_NETONLY_USER = $userPrincipal
    Remove-Item Env:RUN_NETONLY_DOMAIN -ErrorAction SilentlyContinue
    $env:RUN_NETONLY_PASSWORD = $userPassword
    $env:RUN_NETONLY_CWD = $testRoot
    & $script:runNetonly --cmdline ('cmd.exe /c ' + (Quote-CmdArg $cmdFile))
    $status = $LASTEXITCODE
    if (Test-Path $Log) {
        Get-Content $Log |
            Select-String -Pattern 'kex: algorithm:|Authenticated to|Host key verification failed|Permission denied|gss|GSS|gsskex-ok' |
            ForEach-Object { "[$Name] $($_.Line)" }
    }
    if ($status -ne 0) {
        if (Test-Path $Log) {
            Get-Content $Log
        }
        throw "$Name failed with exit code $status"
    }
}

function Assert-GssKex([string]$Name, [string]$Log) {
    $text = Get-Content $Log -Raw
    if ($text -notmatch 'kex: algorithm: gss-curve25519-sha256-') {
        throw "$Name did not use gss-curve25519-sha256-"
    }
}

function Stop-TestSshd() {
    Stop-Service sshd -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

function Start-WindowsSshd([string]$AuthorizedKeys) {
    $sshd = Join-Path $buildDir 'sshd.exe'
    $sshKeygen = Join-Path $buildDir 'ssh-keygen.exe'
    $sftpServer = Join-Path $buildDir 'sftp-server.exe'
    foreach ($path in @($sshd, $sshKeygen, $sftpServer)) {
        if (-not (Test-Path $path)) {
            throw "missing required Windows binary: $path"
        }
    }

    $hostKey = Join-Path $testRoot 'windows-ssh-host-ed25519'
    Remove-Item "$hostKey*" -Force -ErrorAction SilentlyContinue
    Invoke-Checked $sshKeygen @('-q', '-t', 'ed25519', '-N', '', '-f', $hostKey)
    Invoke-Checked icacls.exe @($hostKey, '/inheritance:r')
    Invoke-Checked icacls.exe @($hostKey, '/grant:r',
        '*S-1-5-18:F', '*S-1-5-32-544:F')
    Invoke-Checked icacls.exe @($hostKey, '/setowner', '*S-1-5-32-544')

    $cfg = Join-Path $testRoot 'windows_sshd_config'
    $serverLog = Join-Path $logRoot 'windows-sshd.log'
@"
Port $windowsPort
ListenAddress 0.0.0.0
PidFile $testRoot/windows-sshd.pid
HostKey $hostKey
LogLevel DEBUG3
GSSAPIAuthentication yes
GSSAPIKeyExchange yes
GSSAPIKexAlgorithms gss-curve25519-sha256-
GSSAPIStrictAcceptorCheck no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthorizedKeysFile $AuthorizedKeys
PermitRootLogin no
AllowUsers $userName
StrictModes no
Subsystem sftp $sftpServer
"@ | Set-Content -Path $cfg -Encoding ASCII

    Stop-TestSshd
    if (Get-Service sshd -ErrorAction SilentlyContinue) {
        & sc.exe delete sshd | Out-Null
        Start-Sleep -Seconds 1
    }
    $binPath = "$sshd -f $cfg -E $serverLog"
    & sc.exe create sshd binPath= $binPath start= demand obj= LocalSystem |
        Out-Null
    & sc.exe privs sshd `
        SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege |
        Out-Null
    Start-Service sshd
    Start-Sleep -Seconds 2
    if ((Get-Service sshd).Status -ne 'Running') {
        if (Test-Path $serverLog) {
            Get-Content $serverLog
        }
        throw 'Windows sshd did not start'
    }
}

function Collect-InteropLogs() {
    Copy-Item -Path (Join-Path $testRoot '*') -Destination $logRoot `
        -Recurse -Force -ErrorAction SilentlyContinue
    try {
        & wsl.exe -u root -- sh -lc `
            "test -d $linuxWork/logs && tar -C /tmp -czf /tmp/openssh-gsskex-interop-logs.tar.gz openssh-gsskex-interop/logs"
        if ($LASTEXITCODE -eq 0) {
            & wsl.exe -u root -- cat /tmp/openssh-gsskex-interop-logs.tar.gz > `
                (Join-Path $logRoot 'wsl-logs.tar.gz')
        }
    } catch {
        Write-Output "log collection failed: $($_.Exception.Message)"
    }
}

try {
    foreach ($name in @('ssh.exe', 'sshd.exe', 'ssh-keygen.exe')) {
        $path = Join-Path $buildDir $name
        if (-not (Test-Path $path)) {
            throw "missing Windows build output: $path"
        }
    }
    $winKlist = Join-Path $env:SystemRoot 'System32\klist.exe'

    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
        -Force | Out-Null
    New-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
        -Name MaxPacketSize -Value 1 -PropertyType DWord -Force |
        Out-Null
    New-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
        -Name FarKdcTimeout -Value 0 -PropertyType DWord -Force |
        Out-Null

    $wslIp = (& wsl.exe -u root -- sh -lc "hostname -I | cut -d ' ' -f 1").Trim()
    if (-not $wslIp) {
        throw 'could not determine WSL IP address'
    }
    $windowsIp = (& wsl.exe -u root -- sh -lc "sed -n 's/^nameserver[[:space:]][[:space:]]*//p' /etc/resolv.conf | head -n 1").Trim()
    if (-not $windowsIp) {
        throw 'could not determine Windows host IP from WSL'
    }
    "WSL IP: $wslIp" | Tee-Object -FilePath (Join-Path $logRoot 'network.txt')
    "Windows host IP from WSL: $windowsIp" |
        Tee-Object -FilePath (Join-Path $logRoot 'network.txt') -Append

    Add-HostsLine "127.0.0.1 $kdcHost"
    Add-HostsLine "$wslIp $linuxHost"
    Add-HostsLine "127.0.0.1 $windowsHost"
    Resolve-DnsName $kdcHost |
        Format-List |
        Out-File -FilePath (Join-Path $logRoot 'network.txt') -Append

    ipconfig /flushdns | Out-Null

    $linuxScript = Convert-ToWslPath (Join-Path $repo '.github\scripts\gsskex-wsl-linux.sh')
    $sourceTar = Join-Path $testRoot 'source.tar'
    Remove-Item $sourceTar -Force -ErrorAction SilentlyContinue
    Write-Output 'Creating tracked source archive for Debian build'
    Invoke-Checked git.exe @('-C', $repo, 'archive', '--format=tar',
        "--output=$sourceTar", 'HEAD')
    $sourceTarWsl = Convert-ToWslPath $sourceTar
    $computerLower = $env:COMPUTERNAME.ToLowerInvariant()
    Write-Output 'Running Debian Heimdal/OpenSSH setup in WSL'
    & wsl.exe -u root -- env `
        "USER_PASSWORD=$userPassword" `
        "COMPUTER_PASSWORD=$computerPassword" `
        bash $linuxScript setup $sourceTarWsl $wslIp $windowsIp $computerLower
    if ($LASTEXITCODE -ne 0) {
        throw "Linux setup failed with $LASTEXITCODE"
    }
    & wsl.exe --distribution Debian-12 --user root -- python3 -c `
        "import socket; socket.create_connection(('127.0.0.1', 88), 5).close(); print('wsl-kdc-tcp-ok')"
    if ($LASTEXITCODE -ne 0) {
        throw 'Debian Heimdal KDC is not reachable on WSL loopback'
    }

    Start-TestLocator $wslIp
    Get-DnsClientNrptRule |
        Where-Object { $_.Comment -eq 'OpenSSH GSS KEX test' } |
        Format-List |
        Out-File -FilePath (Join-Path $logRoot 'network.txt') -Append
    Resolve-DnsName "_kerberos._tcp.dc._msdcs.$($realm.ToLowerInvariant())" `
        -Type SRV |
        Format-List |
        Out-File -FilePath (Join-Path $logRoot 'network.txt') -Append
    & nltest.exe "/dsgetdc:$realm" /force |
        Out-File -FilePath (Join-Path $logRoot 'network.txt') -Append
    Test-NetConnection -ComputerName $kdcHost -Port 88 |
        Format-List |
        Out-File -FilePath (Join-Path $logRoot 'network.txt') -Append

    Write-Output 'Compiling run_netonly helper'
    $script:runNetonly = Compile-RunNetonly

    $emptyConfig = Join-Path $testRoot 'empty_config'
    $knownHosts = Join-Path $testRoot 'known_hosts.empty'
    $globalKnownHosts = Join-Path $testRoot 'global_known_hosts.empty'
    Set-Content -Path $emptyConfig -Value '' -NoNewline
    Set-Content -Path $knownHosts -Value '' -NoNewline
    Set-Content -Path $globalKnownHosts -Value '' -NoNewline

    $winSsh = Join-Path $buildDir 'ssh.exe'
    $winKlistLog = Join-Path $logRoot 'windows-klist-linux.log'
    Write-Output 'Checking Windows Kerberos service ticket for Debian sshd'
    Invoke-NetonlyCommand -Name 'windows-klist-linux' `
        -CommandArgs @($winKlist, 'get', "host/$linuxHost@$realm") `
        -Log $winKlistLog

    $winToLinuxLog = Join-Path $logRoot 'windows-to-linux-ssh.log'
    $winToLinux = @(
        $winSsh, '-vvv',
        '-F', $emptyConfig,
        '-o', 'BatchMode=yes',
        '-o', "HostName=$wslIp",
        '-o', 'AddressFamily=inet',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', "UserKnownHostsFile=$knownHosts",
        '-o', "GlobalKnownHostsFile=$globalKnownHosts",
        '-o', 'GSSAPIAuthentication=yes',
        '-o', 'GSSAPIKeyExchange=yes',
        '-o', 'GSSAPIKexAlgorithms=gss-curve25519-sha256-',
        '-o', "GSSAPIServerIdentity=$linuxHost@$realm",
        '-o', 'PreferredAuthentications=gssapi-with-mic',
        '-o', 'PubkeyAuthentication=no',
        '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'NumberOfPasswordPrompts=0',
        '-o', 'ConnectTimeout=30',
        '-o', 'ConnectionAttempts=1',
        '-p', "$linuxPort",
        "$userName@$linuxHost",
        '/bin/echo', 'windows-to-linux-gsskex-ok'
    )
    Write-Output 'Running Windows client to Debian sshd GSS KEX test'
    Invoke-NetonlyCommand -Name 'windows-to-linux' `
        -CommandArgs $winToLinux -Log $winToLinuxLog
    Assert-GssKex 'windows-to-linux' $winToLinuxLog
    if ((Get-Item $knownHosts).Length -ne 0 -or
        (Get-Item $globalKnownHosts).Length -ne 0) {
        throw 'Windows known_hosts files were modified'
    }

    $localPassword = ConvertTo-SecureString 'L0cal!Account!2026' `
        -AsPlainText -Force
    if (-not (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $userName -Password $localPassword `
            -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
    }
    Enable-LocalUser -Name $userName
    Add-LocalGroupMember -Group 'Users' -Member $userName `
        -ErrorAction SilentlyContinue

    $authorizedKeys = Join-Path $testRoot 'windows_authorized_keys'
    & wsl.exe -u root -- cat "$linuxWork/linux-to-windows-ed25519.pub" |
        Set-Content -Path $authorizedKeys -Encoding ASCII
    Write-Output 'Starting Windows sshd test peer'
    Start-WindowsSshd -AuthorizedKeys $authorizedKeys

    Write-Output 'Running Debian client to Windows sshd GSS KEX test'
    & wsl.exe -u root -- env "USER_PASSWORD=$userPassword" `
        bash $linuxScript linux-to-windows
    if ($LASTEXITCODE -ne 0) {
        throw "Linux to Windows SSH failed with $LASTEXITCODE"
    }

    Collect-InteropLogs

    Write-Output 'Windows/Linux forced GSSAPIKeyExchange tests passed with empty known_hosts'
} finally {
    Stop-TestLocator
    Collect-InteropLogs
    Stop-TestSshd
    if (Test-Path (Join-Path $repo '.github\scripts\gsskex-wsl-linux.sh')) {
        try {
            $linuxScript = Convert-ToWslPath (Join-Path $repo '.github\scripts\gsskex-wsl-linux.sh')
            & wsl.exe -u root -- bash $linuxScript cleanup | Out-Null
        } catch {
            Write-Output "cleanup failed: $($_.Exception.Message)"
        }
    }
}
