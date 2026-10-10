param(
    [Parameter(Mandatory = $true)] [string] $Output,
    [Parameter(Mandatory = $true)] [int] $GatewayProcessId,
    [Parameter(Mandatory = $true)] [int] $ReplayProcessId,
    [ValidateRange(100, 60000)] [int] $IntervalMs = 2000,
    [ValidateRange(1, 100000)] [int] $MaxSamples = 10000,
    [ValidateSet('baseline', 'observe', 'action')] [string] $Mode = 'action'
)

$target = Get-Process -Id $GatewayProcessId -ErrorAction Stop
$processStart = $target.StartTime.ToUniversalTime().ToString('o')
$previousCpu = $target.TotalProcessorTime.TotalSeconds
$timer = [System.Diagnostics.Stopwatch]::StartNew()
$previousElapsed = 0.0
$encoding = [System.Text.UTF8Encoding]::new($false)
$outputPath = [System.IO.Path]::GetFullPath($Output)
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($outputPath)) | Out-Null

for ($index = 0; $index -lt $MaxSamples; $index++) {
    if (-not (Get-Process -Id $ReplayProcessId -ErrorAction SilentlyContinue)) {
        break
    }
    Start-Sleep -Milliseconds $IntervalMs
    $target = Get-Process -Id $GatewayProcessId -ErrorAction SilentlyContinue
    if (-not $target -or $target.StartTime.ToUniversalTime().ToString('o') -ne $processStart) {
        throw "Gateway process $GatewayProcessId stopped or restarted during sampling"
    }
    $elapsed = $timer.Elapsed.TotalSeconds
    $interval = $elapsed - $previousElapsed
    $cpu = $target.TotalProcessorTime.TotalSeconds
    $corePct = ($cpu - $previousCpu) / $interval * 100
    $record = [ordered]@{
        timestamp = [DateTimeOffset]::UtcNow.ToString('o')
        mode = $Mode
        sample_index = $index
        process_id = $GatewayProcessId
        process_start = $processStart
        interval_seconds = [math]::Round($interval, 3)
        logical_processors = [Environment]::ProcessorCount
        cpu_core_pct = [math]::Round($corePct, 3)
        cpu_host_pct = [math]::Round($corePct / [Environment]::ProcessorCount, 3)
    }
    [System.IO.File]::AppendAllText($outputPath, (($record | ConvertTo-Json -Compress) + "`n"), $encoding)
    $previousCpu = $cpu
    $previousElapsed = $elapsed
}
