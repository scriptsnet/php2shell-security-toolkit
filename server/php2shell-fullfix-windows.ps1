[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Check,
    [string[]]$HttpUrl = @(),
    [string]$OnlyPath = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Cve1 = "CVE-2026-109618"
$Cve2 = "CVE-2026-109619"
$WorkRoot = Join-Path $env:ProgramData "PHP2ShellFullFix"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$WorkDir = Join-Path $WorkRoot $Stamp
$BackupRoot = Join-Path $WorkDir "backups"
$ReportPath = Join-Path $WorkDir "report.txt"
$ReportJson = Join-Path $WorkDir "report.json"
$BackupManifest = Join-Path $WorkDir "backup-manifest.json"
$RollbackScript = Join-Path $WorkDir "rollback.ps1"
$Mode = if ($Apply) { "apply" } else { "check" }
$script:Results = @()
$script:Backups = @()

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line
    Add-Content -LiteralPath $ReportPath -Value $line -Encoding UTF8
}

function Fail {
    param([string]$Message)
    Write-Log $Message "ERROR"
    throw $Message
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Confirm-Phrase {
    param([string]$Expected, [string]$Prompt)
    Write-Host ""
    Write-Host $Prompt
    $answer = Read-Host ("请输入 {0} 继续" -f $Expected)
    if ($answer -cne $Expected) {
        Fail "确认口令不匹配，已停止。"
    }
}

function Get-OfficialFixedVersion {
    param([string]$Version)
    if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)') { return $null }
    $branch = "{0}.{1}" -f $Matches[1], $Matches[2]
    switch ($branch) {
        "8.2" { return "8.2.35" }
        "8.3" { return "8.3.36" }
        "8.4" { return "8.4.27" }
        "8.5" { return "8.5.12" }
        default { return $null }
    }
}

function Get-VersionState {
    param([string]$Version, [string]$Fixed)
    if (-not $Version) { return "unknown" }
    if ($Fixed) {
        $current = [version]($Version -replace '(?<=\d)[^\d.].*$', '')
        $target = [version]$Fixed
        if ($current -lt $target) { return "vulnerable" }
        return "fixed"
    }
    if ($Version -match '^8\.6\.') { return "review" }
    return "eol"
}

function Get-PhpVersion {
    param([string]$PhpExe)
    try {
        $raw = & $PhpExe -v 2>&1 | Out-String
        if ($raw -match '(?m)^PHP\s+(\d+\.\d+\.\d+)') { return $Matches[1] }
    } catch {}
    return $null
}

function Get-PhpModules {
    param([string]$PhpExe)
    try {
        return @(& $PhpExe -r "echo implode(PHP_EOL, array_unique(array_merge(get_loaded_extensions(false), get_loaded_extensions(true)))), PHP_EOL;" 2>$null |
            Where-Object { $_ -and $_ -notmatch '^\[' } | Sort-Object)
    } catch {
        return @()
    }
}

function Get-PhpProperty {
    param([string]$PhpExe, [string]$Name)
    try {
        $text = & $PhpExe -i 2>$null | Out-String
        if ($text -match "(?m)^$([regex]::Escape($Name))\s*=>\s*(.+)$") {
            return $Matches[1].Trim()
        }
    } catch {}
    return ""
}

function Get-PhpCandidates {
    $items = New-Object System.Collections.Generic.List[string]

    try {
        Get-Command php -All -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Source) { $items.Add($_.Source) }
        }
    } catch {}

    $registryRoots = @(
        "HKLM:\SOFTWARE\PHP",
        "HKLM:\SOFTWARE\WOW6432Node\PHP"
    )
    foreach ($regRoot in $registryRoots) {
        if (Test-Path $regRoot) {
            Get-ChildItem $regRoot -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $value = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).InstallDir
                    if ($value) {
                        $items.Add((Join-Path $value "php.exe"))
                    }
                } catch {}
            }
        }
    }

    $common = @(
        "C:\php\php.exe",
        "C:\php*\php.exe",
        "C:\Program Files\PHP\*\php.exe",
        "C:\Program Files\PHP\php.exe",
        "C:\Program Files (x86)\PHP\*\php.exe",
        "C:\Program Files (x86)\PHP\php.exe",
        "C:\xampp\php\php.exe",
        "C:\wamp*\bin\php\php*\php.exe",
        "C:\laragon\bin\php\php*\php.exe",
        "C:\tools\php\php.exe"
    )
    foreach ($pattern in $common) {
        Get-Item -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            $items.Add($_.FullName)
        }
    }

    try {
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
            $pathName = [string]$_.PathName
            if ($pathName -match '(?i)([A-Z]:\\[^"]*?php(?:-cgi)?\.exe)') {
                $items.Add($Matches[1].Trim())
            }
        }
    } catch {}

    $unique = @{}
    $result = @()
    foreach ($item in $items) {
        try {
            if (-not (Test-Path -LiteralPath $item -PathType Leaf)) { continue }
            $resolved = (Resolve-Path -LiteralPath $item).Path
            $key = $resolved.ToLowerInvariant()
            if ($unique.ContainsKey($key)) { continue }
            $unique[$key] = $true
            $result += $resolved
        } catch {}
    }
    return $result
}

function Get-RestartServices {
    param([string]$Root, [string]$PhpExe)
    $services = @{}

    try {
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
            $pathName = [string]$_.PathName
            if ($pathName -and $pathName.IndexOf($Root, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $services[$_.Name] = $true
            }
        }
    } catch {}

    $hasApacheModule = Test-Path -LiteralPath (Join-Path $Root "php8apache2_4.dll")
    if ($hasApacheModule) {
        try {
            Get-Service -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -match '(?i)apache|httpd|wamp|xampp|litespeed' -or
                $_.DisplayName -match '(?i)apache|httpd|wamp|xampp|litespeed'
            } | ForEach-Object { $services[$_.Name] = $true }
        } catch {}
    }

    $appcmd = Join-Path $env:WINDIR "System32\inetsrv\appcmd.exe"
    if ((Test-Path -LiteralPath $appcmd) -and (Test-Path -LiteralPath $PhpExe)) {
        try {
            $fastCgi = (& $appcmd list config /section:system.webServer/fastCgi 2>$null | Out-String)
            if ($fastCgi -and $fastCgi.IndexOf($Root, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $services["W3SVC"] = $true
            }
        } catch {}
    }

    $result = @()
    foreach ($name in $services.Keys) {
        try {
            $svc = Get-Service -Name $name -ErrorAction Stop
            $result += [pscustomobject]@{
                Name = $svc.Name
                DisplayName = $svc.DisplayName
                Status = [string]$svc.Status
            }
        } catch {}
    }
    return @($result | Sort-Object Name)
}

function Test-OomSecurityBehavior {
    param([string]$PhpExe, [string]$OutBase)
    $testPhp = "$OutBase.php"
    $marker = "$OutBase.marker"
    $output = "$OutBase.txt"
    Remove-Item -LiteralPath $marker, $output -Force -ErrorAction SilentlyContinue
    @'
<?php
$marker = $argv[1];
register_shutdown_function(function () use ($marker) {
    file_put_contents($marker, "shutdown-ran\n");
});
str_repeat("A", 8 * 1024 * 1024);
'@ | Set-Content -LiteralPath $testPhp -Encoding UTF8

    $p = Start-Process -FilePath $PhpExe `
        -ArgumentList @("-n", "-d", "display_errors=1", "-d", "log_errors=0", "-d", "memory_limit=4M", $testPhp, $marker) `
        -Wait -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $output -RedirectStandardError "$OutBase.err.txt"
    $text = ""
    if (Test-Path -LiteralPath $output) { $text += Get-Content -LiteralPath $output -Raw }
    if (Test-Path -LiteralPath "$OutBase.err.txt") { $text += Get-Content -LiteralPath "$OutBase.err.txt" -Raw }
    return ($p.ExitCode -ne 0 -and -not (Test-Path -LiteralPath $marker) -and $text -match '(?i)Allowed memory size')
}

function Get-InstallationInfo {
    param([string]$PhpExe)
    $root = Split-Path -Parent $PhpExe
    if ([string]::IsNullOrWhiteSpace($root)) {
        return $null
    }
    $normalizedRoot = $root.TrimEnd('\')
    $volumeRoot = [IO.Path]::GetPathRoot($root).TrimEnd('\')
    if ($normalizedRoot -eq $volumeRoot) {
        return $null
    }
    if ($root -notmatch '(?i)php|xampp|wamp|laragon') {
        return $null
    }

    $version = Get-PhpVersion $PhpExe
    if (-not $version) { return $null }
    $fixed = Get-OfficialFixedVersion $version
    $state = Get-VersionState -Version $version -Fixed $fixed
    $threadSafety = Get-PhpProperty $PhpExe "Thread Safety"
    $arch = (& $PhpExe -r "echo PHP_INT_SIZE;" 2>$null)
    $services = Get-RestartServices -Root $root -PhpExe $PhpExe
    $rootProcesses = @()
    try {
        $rootProcesses = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.ExecutablePath -and
            $_.ExecutablePath.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -and
            $_.ProcessId -ne $PID
        })
    } catch {}
    $blockingProcesses = @($rootProcesses | Where-Object {
        $_.Name -ieq "php.exe" -or $services.Count -eq 0
    })
    $branch = (($version -split '\.')[0..1] -join '.')
    $zts = $threadSafety -match '(?i)Enabled'
    $is64 = "$arch" -eq "8"
    $vs = if ($branch -in @("8.2", "8.3")) { "vs16" } elseif ($branch -in @("8.4", "8.5")) { "vs17" } else { "" }
    $tsPart = if ($zts) { "" } else { "nts-" }
    $archPart = if ($is64) { "x64" } else { "x86" }
    $zipName = if ($fixed -and $vs) { "php-$fixed-${tsPart}Win32-$vs-$archPart.zip" } else { "" }

    return [pscustomobject]@{
        PhpExe = $PhpExe
        Root = $root
        Version = $version
        Branch = $branch
        Fixed = $fixed
        State = $state
        ThreadSafety = $threadSafety
        Zts = $zts
        Architecture = $archPart
        ZipName = $zipName
        Services = @($services)
        BlockingProcesses = @($blockingProcesses | ForEach-Object {
            [pscustomobject]@{
                ProcessId = $_.ProcessId
                Name = $_.Name
                CommandLine = $_.CommandLine
            }
        })
        Modules = @(Get-PhpModules $PhpExe)
        IniFile = Get-PhpProperty $PhpExe "Loaded Configuration File"
        AutoSupported = ($state -eq "vulnerable" -and $fixed -and $vs)
    }
}

function Get-FreeSpaceGb {
    param([string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $drive = New-Object IO.DriveInfo -ArgumentList ([IO.Path]::GetPathRoot($full))
    return [math]::Round($drive.AvailableFreeSpace / 1GB, 2)
}

function Copy-DirectorySnapshot {
    param([string]$Source, [string]$Destination)
    if (Test-Path -LiteralPath $Destination) {
        Fail "备份目标已存在：$Destination"
    }
    New-Item -ItemType Directory -Path (Split-Path $Destination -Parent) -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
}

function Backup-Installation {
    param($Info)
    $sha = [Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Info.Root.ToLowerInvariant()))
    $id = (-join ($hashBytes | ForEach-Object { $_.ToString("x2") })).Substring(0, 12)
    $base = Join-Path $BackupRoot $id
    $runtime = Join-Path $base "runtime"
    $servicesPath = Join-Path $base "services.json"
    New-Item -ItemType Directory -Path $base -Force | Out-Null

    $free = Get-FreeSpaceGb $WorkRoot
    if ($free -lt 2) { Fail "备份至少需要 2 GiB 空闲空间，当前 $free GiB。" }
    Write-Log "备份 PHP 安装目录：$($Info.Root) -> $runtime"
    Copy-DirectorySnapshot -Source $Info.Root -Destination $runtime
    $Info.Services | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $servicesPath -Encoding UTF8
    & $Info.PhpExe -v *> (Join-Path $base "php-before.txt")
    & $Info.PhpExe --ini *> (Join-Path $base "php-ini-before.txt")
    $Info.Modules | Set-Content -LiteralPath (Join-Path $base "modules-before.txt") -Encoding UTF8
    [pscustomobject]@{
        Root = $Info.Root
        PhpExe = $Info.PhpExe
        BackupRuntime = $runtime
        ServicesFile = $servicesPath
        Version = $Info.Version
        Target = $Info.Fixed
    }
}

function Stop-RecordedServices {
    param($Services)
    foreach ($svc in @($Services)) {
        if ($svc.Status -eq "Running") {
            try {
                Write-Log "停止服务 $($svc.Name)"
                Stop-Service -Name $svc.Name -Force -ErrorAction Stop
            } catch {
                Fail "停止服务 $($svc.Name) 失败：$($_.Exception.Message)"
            }
        }
    }
}

function Start-RecordedServices {
    param($Services)
    foreach ($svc in @($Services)) {
        if ($svc.Status -eq "Running") {
            try {
                Write-Log "启动服务 $($svc.Name)"
                Start-Service -Name $svc.Name -ErrorAction Stop
            } catch {
                Write-Log "启动服务 $($svc.Name) 失败：$($_.Exception.Message)" "ERROR"
            }
        }
    }
}

function Download-OfficialZip {
    param($Info)
    $downloads = Join-Path $WorkDir "downloads"
    New-Item -ItemType Directory -Path $downloads -Force | Out-Null
    $zipPath = Join-Path $downloads $Info.ZipName
    $shaPath = Join-Path $downloads "sha256sum.txt"
    $baseUrl = "https://windows.php.net/downloads/releases"
    Write-Log "下载官方 Windows PHP：$($Info.ZipName)"
    (New-Object Net.WebClient).DownloadFile("$baseUrl/$($Info.ZipName)", $zipPath)
    (New-Object Net.WebClient).DownloadFile("$baseUrl/sha256sum.txt", $shaPath)

    $shaLine = Get-Content -LiteralPath $shaPath |
        Where-Object { $_ -match [regex]::Escape($Info.ZipName) } |
        Select-Object -First 1
    if (-not $shaLine) { Fail "sha256sum.txt 中没有 $($Info.ZipName)。" }
    $expected = ($shaLine -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        Fail "Windows PHP ZIP 哈希不匹配：期望 $expected，实际 $actual"
    }
    return $zipPath
}

function Invoke-HttpChecks {
    if ($HttpUrl.Count -eq 0) { return $true }
    $ok = $true
    foreach ($url in $HttpUrl) {
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
            Write-Log "HTTP 健康检查：$url -> $($response.StatusCode)"
            if ($response.StatusCode -ge 500) { $ok = $false }
        } catch {
            $status = $null
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            Write-Log "HTTP 健康检查：$url -> $status" "ERROR"
            if (-not $status -or $status -ge 500) { $ok = $false }
        }
    }
    return $ok
}

function Restore-Installation {
    param($Backup)
    $root = $Backup.Root
    $services = @()
    if (Test-Path -LiteralPath $Backup.ServicesFile) {
        $services = @(Get-Content -LiteralPath $Backup.ServicesFile -Raw | ConvertFrom-Json)
    }
    Write-Log "开始回滚：$root"
    Stop-RecordedServices $services
    $failed = "$root.failed-$Stamp"
    $restoreTemp = "$root.restore-$Stamp"
    if (Test-Path -LiteralPath $failed) { Fail "失败版本目录已存在：$failed" }
    if (Test-Path -LiteralPath $restoreTemp) { Fail "恢复临时目录已存在：$restoreTemp" }

    robocopy $Backup.BackupRuntime $restoreTemp /MIR /R:2 /W:1 | Out-Null
    if ($LASTEXITCODE -ge 8) { Fail "复制备份到临时目录失败：robocopy=$LASTEXITCODE" }
    Move-Item -LiteralPath $root -Destination $failed
    Move-Item -LiteralPath $restoreTemp -Destination $root
    Start-RecordedServices $services
    Write-Log "回滚完成。失败版本保留：$failed" "WARN"
}

function Write-RollbackScript {
    $manifestJson = $script:Backups | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $BackupManifest -Value $manifestJson -Encoding UTF8
    $template = @'
<#
.SYNOPSIS
  PHP2Shell 全流程检查/修复脚本，供运行 PHP 的 Windows Server / Windows NT 服务器本机使用。

.DESCRIPTION
  必须在目标 Windows Server 本机以管理员 PowerShell 运行。
  这不是从个人 PC 发起的远程扫描器；默认只检查，-Apply 才修改本机 PHP。
#>
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
$WorkDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ManifestPath = Join-Path $WorkDir "backup-manifest.json"
Write-Host "============================================================"
Write-Host "PHP2Shell Windows 回滚"
Write-Host "将恢复脚本记录的 PHP 安装目录和 PHP 相关服务。"
Write-Host "数据库、业务代码和应用数据不在自动回滚范围内。"
Write-Host "============================================================"
$answer = Read-Host "输入 ROLLBACK 继续"
if ($answer -cne "ROLLBACK") { Write-Host "已取消。"; exit 1 }
$backups = @(Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json)
foreach ($backup in $backups) {
    $services = @()
    if (Test-Path -LiteralPath $backup.ServicesFile) {
        $services = @(Get-Content -LiteralPath $backup.ServicesFile -Raw | ConvertFrom-Json)
    }
    foreach ($svc in $services) {
        if ($svc.Status -eq "Running") { Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue }
    }
    $failed = "$($backup.Root).failed-rollback-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $temp = "$($backup.Root).restore-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    robocopy $backup.BackupRuntime $temp /MIR /R:2 /W:1 | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed: $LASTEXITCODE" }
    Move-Item -LiteralPath $backup.Root -Destination $failed
    Move-Item -LiteralPath $temp -Destination $backup.Root
    foreach ($svc in $services) {
        if ($svc.Status -eq "Running") { Start-Service -Name $svc.Name -ErrorAction SilentlyContinue }
    }
    Write-Host "已回滚：$($backup.Root)；失败版本：$failed"
}
Write-Host "回滚完成。请立即检查网站、服务、日志和 PHP 版本。"
'@
    [IO.File]::WriteAllText(
        $RollbackScript,
        $template,
        (New-Object Text.UTF8Encoding -ArgumentList $true)
    )
}

function Upgrade-Installation {
    param($Info, $Backup)
    $zipPath = Download-OfficialZip $Info
    $stage = Join-Path $WorkDir ("stage-" + [IO.Path]::GetFileNameWithoutExtension($Info.ZipName))
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    Expand-Archive -LiteralPath $zipPath -DestinationPath $stage -Force
    $sourceRoot = $stage
    $nested = Get-ChildItem -LiteralPath $stage -Directory | Where-Object {
        Test-Path -LiteralPath (Join-Path $_.FullName "php.exe")
    } | Select-Object -First 1
    if ($nested) { $sourceRoot = $nested.FullName }
    if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot "php.exe"))) {
        Fail "官方 ZIP 中没有找到 php.exe。"
    }

    $services = @($Info.Services)
    Stop-RecordedServices $services
    try {
        Get-ChildItem -LiteralPath $sourceRoot -Force | ForEach-Object {
            if ($_.Name -ieq "php.ini") { return }
            Copy-Item -LiteralPath $_.FullName -Destination $Info.Root -Recurse -Force
        }
        Start-RecordedServices $services
        Start-Sleep -Seconds 2

        $newVersion = Get-PhpVersion $Info.PhpExe
        if ($newVersion -ne $Info.Fixed) {
            Fail "升级后 PHP 版本为 $newVersion，目标为 $($Info.Fixed)。"
        }
        $newModules = @(Get-PhpModules $Info.PhpExe)
        $missing = @($Info.Modules | Where-Object { $_ -and ($newModules -notcontains $_) })
        if ($missing.Count -gt 0) {
            Fail ("升级后缺少模块：" + ($missing -join ", "))
        }
        $phpCgi = Join-Path $Info.Root "php-cgi.exe"
        if (Test-Path -LiteralPath $phpCgi) {
            $cgiVersion = Get-PhpVersion $phpCgi
            if ($cgiVersion -ne $Info.Fixed) { Fail "php-cgi.exe 版本为 $cgiVersion。" }
        }
        $backupId = (BackupId -Root $Backup.Root)
        if (-not (Test-OomSecurityBehavior -PhpExe $Info.PhpExe -OutBase (Join-Path $WorkDir ("oom-" + $backupId)))) {
            Write-Log "OOM 行为采样：shutdown function 被执行；8.2+ 官方修复不保证此旧版测试结果为否，继续以官方版本、模块和业务验证为准。" "WARN"
        }
        if (-not (Invoke-HttpChecks)) {
            Fail "HTTP 健康检查失败。"
        }
        Write-Log "PHP 升级并验证成功：$($Info.Root) -> $($Info.Fixed)"
    } catch {
        Write-Log "升级验证失败：$($_.Exception.Message)" "ERROR"
        try {
            Restore-Installation $Backup
            Write-Log "已自动回滚到升级前版本。" "WARN"
        } catch {
            Write-Log "自动回滚失败：$($_.Exception.Message)" "ERROR"
        }
        throw
    }
}

function BackupId {
    param([string]$Root)
    $sha = [Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Root.ToLowerInvariant()))
    return (-join ($hashBytes | ForEach-Object { $_.ToString("x2") })).Substring(0, 12)
}

if ($Apply -and $Check) { throw "不能同时使用 -Apply 与 -Check。" }
$osInfo = $null
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
} catch {}
$isWindowsServer = $false
$osCaption = "未知 Windows"
$osBuild = [Environment]::OSVersion.Version.Build
if ($osInfo) {
    $osCaption = [string]$osInfo.Caption
    $isWindowsServer = ([int]$osInfo.ProductType -ne 1)
}
if (-not $osInfo) {
    try {
        $productOptions = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions" -ErrorAction Stop).ProductType
        if ($productOptions -match "ServerNT|LanmanNT") {
            $isWindowsServer = $true
            $osCaption = "Windows Server/NT ($productOptions)"
        }
    } catch {}
}
if ($Apply -and -not $isWindowsServer) {
    throw "此脚本用于 Windows Server/NT 的 PHP 主机本机修复，不能在个人工作站执行。普通 PC 请使用扫描器的 -Check 模式或 Web/PC 扫描端。"
}
if ($Apply -and $osBuild -lt 9200) {
    throw "检测到 Windows Server 2008 R2 或更早系统。现代 PHP 8.2+ 不支持这些系统，不能安全自动修复；请迁移到受支持 Windows Server 和 PHP 8.4/8.5。"
}
if (-not (Test-IsAdmin)) {
    if ($Apply) { throw "修复模式必须以管理员 PowerShell 运行。" }
    Write-Warning "当前不是管理员，部分服务/注册表信息可能不可见。"
}

New-Item -ItemType Directory -Path $WorkDir, $BackupRoot -Force | Out-Null
Set-Content -LiteralPath $ReportPath -Value "" -Encoding UTF8
Set-Content -LiteralPath (Join-Path $WorkRoot "latest.txt") -Value $WorkDir -Encoding UTF8
Set-Location -LiteralPath $WorkDir
$transcriptStarted = $false
try {
    Start-Transcript -Path (Join-Path $WorkDir "transcript.txt") | Out-Null
    $transcriptStarted = $true
} catch {}

Write-Log "============================================================"
Write-Log "PHP2Shell Windows Server/NT 本机全流程检查/修复"
Write-Log "Windows：$osCaption；is_server=$isWindowsServer；build=$osBuild"
Write-Log "模式：$Mode"
Write-Log "漏洞：$Cve1 / $Cve2"
Write-Log "工作目录：$WorkDir"
Write-Log "============================================================"

Write-Host ""
Write-Host "重要提示：" -ForegroundColor Yellow
Write-Host "- 本脚本必须在实际运行 PHP 的 Windows Server/NT 主机本机执行。"
Write-Host "- 默认只检查；只有 -Apply 才会替换 PHP 并重启服务。"
Write-Host "- 建议先在云厂商/虚拟化平台创建整机快照。"
Write-Host "- 脚本内会备份整个 PHP 安装目录，并生成 rollback.ps1。"
Write-Host "- 备份不包含数据库和业务代码，不能替代整机快照。"
Write-Host "- 修复期间网站可能出现 500/502、上传失败或服务短暂中断。"
if (-not $isWindowsServer) {
    Write-Host "- 当前是普通 Windows 工作站：只允许检查，-Apply 会被拒绝。" -ForegroundColor Yellow
}

$candidates = @(Get-PhpCandidates)
if ($OnlyPath) {
    $resolvedOnly = [IO.Path]::GetFullPath($OnlyPath)
    if (Test-Path -LiteralPath $resolvedOnly -PathType Container) {
        $resolvedOnly = Join-Path $resolvedOnly "php.exe"
    }
    if (Test-Path -LiteralPath $resolvedOnly -PathType Leaf) {
        $candidates += $resolvedOnly
    }
    $candidates = @($candidates | Where-Object {
        $_.StartsWith($resolvedOnly, [StringComparison]::OrdinalIgnoreCase) -or
        $resolvedOnly.StartsWith((Split-Path $_ -Parent), [StringComparison]::OrdinalIgnoreCase)
    })
}

$infos = @()
$seenRoots = @{}
foreach ($exe in $candidates) {
    try {
        $info = Get-InstallationInfo -PhpExe $exe
        if ($info -and -not $seenRoots.ContainsKey($info.Root.ToLowerInvariant())) {
            $seenRoots[$info.Root.ToLowerInvariant()] = $true
            $infos += $info
        }
    } catch {
        Write-Log "检查 $exe 失败：$($_.Exception.Message)" "ERROR"
    }
}

if ($infos.Count -eq 0) {
    Write-Log "未在 PATH、注册表、常见目录或服务路径中找到 php.exe。"
    Write-Log "如果 PHP 装在非标准路径，请使用 -OnlyPath 'D:\path\to\php'。"
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
    exit 0
}

foreach ($info in $infos) {
    $serviceText = if ($info.Services.Count) { ($info.Services | ForEach-Object { $_.Name }) -join "," } else { "无" }
    Write-Log "PHP：$($info.PhpExe)；版本=$($info.Version)；状态=$($info.State)；目标=$($info.Fixed)；ZTS=$($info.Zts)；架构=$($info.Architecture)；服务=$serviceText"
    if ($info.BlockingProcesses.Count -gt 0) {
        Write-Log ("检测到可能锁定 PHP 文件的进程：" + (($info.BlockingProcesses | ForEach-Object { "$($_.Name)[$($_.ProcessId)]" }) -join ", ")) "WARN"
    }
    $script:Results += $info
}

$vulnerable = @($infos | Where-Object { $_.State -eq "vulnerable" })
$automatable = @($vulnerable | Where-Object { $_.AutoSupported })
$manual = @($vulnerable | Where-Object { -not $_.AutoSupported })

if ($manual.Count -gt 0) {
    Write-Log "以下版本没有可直接使用的官方 Windows 修复 ZIP，必须升级分支或使用厂商/源码回溯补丁：" "WARN"
    foreach ($item in $manual) {
        Write-Log "  $($item.PhpExe) PHP $($item.Version)" "WARN"
    }
}

if ($Mode -ne "apply" -or $automatable.Count -eq 0) {
    $ref = Join-Path $WorkDir "inventory.json"
    $infos | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ref -Encoding UTF8
    Write-Log "检查完成。未修改任何内容。"
    Write-Log "报告：$ReportPath"
    Write-Log "清单：$ref"
    if ($automatable.Count -gt 0 -and $isWindowsServer) {
        Write-Log "可执行修复：powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Apply"
    } elseif ($automatable.Count -gt 0) {
        Write-Log "当前是普通 Windows 工作站；请把脚本放到实际运行 PHP 的 Windows Server/NT 主机本机执行修复。"
    }
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
    if ($vulnerable.Count -gt 0) { exit 2 }
    exit 0
}

$blocking = @($automatable | Where-Object { $_.BlockingProcesses.Count -gt 0 })
if ($blocking.Count -gt 0) {
    foreach ($item in $blocking) {
        Write-Log "修复前必须人工停止以下进程并确认业务重启方式：" "ERROR"
        foreach ($proc in $item.BlockingProcesses) {
            Write-Log "  $($item.PhpExe) :: PID=$($proc.ProcessId) :: $($proc.CommandLine)" "ERROR"
        }
    }
    Fail "存在运行中的 PHP CLI/FastCGI 进程，无法安全替换文件。"
}

Confirm-Phrase "I_UNDERSTAND_THE_RISK" "第一确认：我已理解 PHP 替换、服务重启和网站中断风险。"
Confirm-Phrase "I_HAVE_A_FULL_SERVER_SNAPSHOT" "第二确认：我已在虚拟化/云平台创建整机快照。"

foreach ($info in $automatable) {
    $backup = Backup-Installation $info
    $script:Backups += $backup
}
Write-RollbackScript

Write-Host ""
Write-Host "备份与回滚信息：" -ForegroundColor Yellow
Write-Host "工作目录：$WorkDir"
Write-Host "回滚脚本：$RollbackScript"
Write-Host "执行回滚：powershell -ExecutionPolicy Bypass -File `"$RollbackScript`""
Write-Host "注意：脚本内回滚只恢复 PHP 安装目录和服务；数据库/业务代码需依赖整机快照。"
Confirm-Phrase "I_HAVE_VERIFIED_THE_BACKUP_AND_ROLLBACK" "第三确认：我已看到备份路径和回滚脚本，并确认可以回滚。"

$failed = $false
foreach ($info in $automatable) {
    $backup = $script:Backups | Where-Object { $_.Root -eq $info.Root } | Select-Object -First 1
    try {
        Upgrade-Installation -Info $info -Backup $backup
        $info.Version = Get-PhpVersion $info.PhpExe
        $info.State = Get-VersionState -Version $info.Version -Fixed $info.Fixed
        $info.Modules = @(Get-PhpModules $info.PhpExe)
    } catch {
        Write-Log "修复中断：$($_.Exception.Message)" "ERROR"
        $failed = $true
        break
    }
}

$infos | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ReportJson -Encoding UTF8
if ($transcriptStarted) { Stop-Transcript | Out-Null }
if ($failed) { exit 1 }

Write-Log "============================================================"
Write-Log "Windows PHP2Shell 修复流程完成。"
@(
    "time=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')",
    "host=$env:COMPUTERNAME",
    "work_dir=$WorkDir",
    "rollback=$RollbackScript",
    "log=$ReportPath"
) | Set-Content -LiteralPath (Join-Path $WorkRoot "last-success.txt") -Encoding UTF8
Write-Log "回滚脚本：$RollbackScript"
Write-Log "请继续人工检查：网站、IIS/FastCGI、Apache、Nginx、上传、支付、数据库和错误日志。"
Write-Log "============================================================"
exit 0
