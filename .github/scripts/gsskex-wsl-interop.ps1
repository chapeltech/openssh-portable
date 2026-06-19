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
    $converted = (& wsl.exe -u root -- wslpath -a $Path).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($converted)) {
        throw "wslpath failed for $Path"
    }
    $converted
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
    Invoke-Checked cmd.exe @('/c', $cmd)
    $out
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
        'cd /d ' + (Quote-CmdArg $testRoot),
        $commandLine,
        'exit /b %ERRORLEVEL%'
    )

    $env:RUN_NETONLY_USER = $userPrincipal
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

    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
        -Force | Out-Null
    New-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
        -Name MaxPacketSize -Value 1 -PropertyType DWord -Force |
        Out-Null

    $wslIp = (& wsl.exe -u root -- sh -lc "hostname -I | awk '{print `$1; exit}'").Trim()
    if (-not $wslIp) {
        throw 'could not determine WSL IP address'
    }
    $windowsIp = (& wsl.exe -u root -- sh -lc "awk '/nameserver/ {print `$2; exit}' /etc/resolv.conf").Trim()
    if (-not $windowsIp) {
        throw 'could not determine Windows host IP from WSL'
    }
    "WSL IP: $wslIp" | Tee-Object -FilePath (Join-Path $logRoot 'network.txt')
    "Windows host IP from WSL: $windowsIp" |
        Tee-Object -FilePath (Join-Path $logRoot 'network.txt') -Append

    Add-HostsLine "$wslIp $kdcHost $linuxHost"
    Add-HostsLine "127.0.0.1 $windowsHost"

    & ksetup /addkdc $realm $kdcHost | Out-Null
    & ksetup /addhosttorealmmap $kdcHost $realm | Out-Null
    & ksetup /addhosttorealmmap $linuxHost $realm | Out-Null
    & ksetup /addhosttorealmmap $windowsHost $realm | Out-Null
    & ksetup /mapuser $userPrincipal $userName | Out-Null
    & ksetup /setrealm $realm | Out-Null
    & ksetup /setcomputerpassword $computerPassword | Out-Null
    & ksetup /dumpstate | Tee-Object -FilePath (Join-Path $logRoot 'ksetup.txt')
    ipconfig /flushdns | Out-Null

    $linuxScript = Convert-ToWslPath (Join-Path $repo '.github\scripts\gsskex-wsl-linux.sh')
    $repoWsl = Convert-ToWslPath $repo
    $computerLower = $env:COMPUTERNAME.ToLowerInvariant()
    & wsl.exe -u root -- env `
        "USER_PASSWORD=$userPassword" `
        "COMPUTER_PASSWORD=$computerPassword" `
        bash $linuxScript setup $repoWsl $wslIp $windowsIp $computerLower
    if ($LASTEXITCODE -ne 0) {
        throw "Linux setup failed with $LASTEXITCODE"
    }

    $script:runNetonly = Compile-RunNetonly

    $emptyConfig = Join-Path $testRoot 'empty_config'
    $knownHosts = Join-Path $testRoot 'known_hosts.empty'
    $globalKnownHosts = Join-Path $testRoot 'global_known_hosts.empty'
    Set-Content -Path $emptyConfig -Value '' -NoNewline
    Set-Content -Path $knownHosts -Value '' -NoNewline
    Set-Content -Path $globalKnownHosts -Value '' -NoNewline

    $winSsh = Join-Path $buildDir 'ssh.exe'
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
        '-o', "GSSAPIServerIdentity=$linuxHost",
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
    Start-WindowsSshd -AuthorizedKeys $authorizedKeys

    & wsl.exe -u root -- env "USER_PASSWORD=$userPassword" `
        bash $linuxScript linux-to-windows
    if ($LASTEXITCODE -ne 0) {
        throw "Linux to Windows SSH failed with $LASTEXITCODE"
    }

    Collect-InteropLogs

    Write-Output 'Windows/Linux forced GSSAPIKeyExchange tests passed with empty known_hosts'
} finally {
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
