param([switch]$Recheck, [switch]$Check, [switch]$NoPause)
$ErrorActionPreference = 'Stop'
$taskRoot = $PSScriptRoot
$taskExitCode = 0
$taskTranscriptStarted = $false
$taskDelegated = $false
$taskLog = $null
try {
    $taskLogRoot = Join-Path $taskRoot 'logs'
    New-Item -ItemType Directory -Path $taskLogRoot -Force | Out-Null
    $taskLog = Join-Path $taskLogRoot ('startup-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + $PID + '.txt')
    Start-Transcript -LiteralPath $taskLog -Force | Out-Null
    $taskTranscriptStarted = $true
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $OutputEncoding = [Console]::OutputEncoding
    Write-Host '交换机自学习实验助手' -ForegroundColor Cyan
    Write-Host ('入口日志：' + $taskLog)
    Write-Host ('PowerShell：' + $PSVersionTable.PSVersion.ToString())
    $taskCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $taskCommand) { throw '请安装 Python 3.10 或更新版本，并将 python 加入 PATH。' }
    $taskPython = $taskCommand.Source
    Write-Host ('Python：' + $taskPython)
    $taskEntry = Join-Path $taskRoot '实验助手.py'
    if (-not (Test-Path -LiteralPath $taskEntry -PathType Leaf)) { throw '缺少同目录的实验助手.py，请保留完整副本目录。' }
    if (-not $Recheck -and -not $Check) {
        $taskIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $taskPrincipal = New-Object Security.Principal.WindowsPrincipal($taskIdentity)
        if (-not $taskPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Host '正在打开管理员实验窗口，请在 Windows 权限提示中选择“是”。'
            # 用户需要阅读和操作这个控制台，因此保持可见。
            # NoExit 确保管理员子进程遇到解析或加载错误也保留窗口。
            $taskChild = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -WindowStyle Normal -PassThru -ArgumentList @(
                '-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"')
            )
            Write-Host ('管理员窗口已启动，进程号：' + $taskChild.Id)
            $taskDelegated = $true
        }
    }
    if (-not $taskDelegated) {
        Set-Location -LiteralPath $taskRoot
        if ($Check) {
            Write-Host '仅检查启动环境和新工程，不连接设备、不设置窗口、不发包。'
            & $taskPython -X utf8 -u -B $taskEntry --check
        } elseif ($Recheck) {
            $taskRunId = (Get-Content -LiteralPath (Join-Path $taskRoot '最新一轮.txt') -Raw).Trim()
            if ($taskRunId -notmatch '^\d{8}-\d{6}-\d{6}$') { throw '最新一轮标记无效。' }
            & $taskPython -X utf8 -u -B $taskEntry --recheck (Join-Path $taskRoot ('records\' + $taskRunId))
        } else {
            & $taskPython -X utf8 -u -B $taskEntry
        }
        $taskExitCode = $LASTEXITCODE
        if ($taskExitCode -ne 0) { throw ('Python 助手已停止，退出码：' + $taskExitCode + '。请保留本窗口中的报错。') }
        if ($Check) { Write-Host '启动检查通过，可以使用“开始实验.cmd”。' -ForegroundColor Green }
    }
} catch {
    $taskExitCode = 1
    Write-Host ''
    Write-Host '启动未完成，窗口会保留。' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ($_ | Out-String)
    if ($taskLog) { Write-Host ('日志位置：' + $taskLog) }
} finally {
    if ($taskTranscriptStarted) { Stop-Transcript | Out-Null }
    if (-not $NoPause -and -not $taskDelegated) {
        Write-Host ''
        Read-Host '看完信息后按回车结束，或直接关闭窗口'
    }
}
exit $taskExitCode
