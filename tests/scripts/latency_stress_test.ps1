<#
.SYNOPSIS
  Long-running serial latency test for MCBE proxy chain.
  Logs every request with detailed timing. Simple and reliable.
#>

param(
    [string]$Node      = "本地链式-sg-gcp-本地",
    [string]$Address   = "mco.cubecraft.net:19132",
    [int]   $Total     = 200,
    [int]   $DelayMs   = 300,
    [string]$ApiUrl    = "http://127.0.0.1:8081/api/proxy-outbounds/test-mcbe",
    [string]$OutFile   = ""
)

if ($OutFile -eq "") {
    $OutFile = "logs\latency_stress_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
}
if (-not (Test-Path "logs")) { New-Item -ItemType Directory -Path "logs" | Out-Null }

"timestamp,seq,success,latency_ms,ping_ms,open_ms,total_ms,server_name,error" | Out-File -FilePath $OutFile -Encoding UTF8

Write-Host "`n=== Long-Running Latency Test ===" -ForegroundColor Cyan
Write-Host "Node:      $Node"
Write-Host "Address:   $Address"
Write-Host "Total:     $Total requests"
Write-Host "Delay:     ${DelayMs}ms between requests"
Write-Host "Output:    $OutFile"
Write-Host ""

$ok = 0
$fail = 0
$latencies = [System.Collections.Generic.List[double]]::new()
$startTime = Get-Date

for ($i = 1; $i -le $Total; $i++) {
    $ts = (Get-Date).ToString("HH:mm:ss.fff")
    $body = @{ name = $Node; address = $Address } | ConvertTo-Json -Compress
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $success = $false
    $latency = 0; $ping = 0; $open = 0; $totalT = 0; $srvName = ""; $err = ""

    try {
        $resp = Invoke-WebRequest -Uri $ApiUrl -Method Post -Body $bodyBytes -ContentType "application/json; charset=utf-8" -TimeoutSec 15 -UseBasicParsing
        $j = $resp.Content | ConvertFrom-Json
        if ($j.data.success) {
            $success = $true
            $latency = $j.data.latency_ms
            $ping = $j.data.ping_ms
            $open = $j.data.open_ms
            $totalT = $j.data.total_ms
            $srvName = $j.data.server_name
        } else {
            $err = $j.data.error
            if (-not $err) { $err = $j.msg }
        }
    } catch {
        $err = $_.Exception.Message
    }
    $sw.Stop()
    $elapsed = [math]::Round($sw.Elapsed.TotalMilliseconds, 0)

    if ($success) {
        $ok++
        $latencies.Add($latency)
    } else {
        $fail++
    }

    # CSV
    $errClean = ($err -replace '"', '""')
    $srvClean = ($srvName -replace '"', '""')
    Add-Content -Path $OutFile -Value "$ts,$i,$success,$latency,$ping,$open,$totalT,`"$srvClean`",`"$errClean`""

    # Progress
    $pct = [math]::Round($i / $Total * 100, 0)
    if ($success) {
        Write-Host ("[{0}] {1,4}/{2} ({3,3}%) lat={4,4}ms ping={5,4}ms open={6,4}ms total={7,4}ms elapsed={8}ms" -f `
            $ts, $i, $Total, $pct, $latency, $ping, $open, $totalT, $elapsed) -ForegroundColor Green
    } else {
        Write-Host ("[{0}] {1,4}/{2} ({3,3}%) FAIL err={4}" -f $ts, $i, $Total, $pct, $err) -ForegroundColor Red
    }

    if ($DelayMs -gt 0 -and $i -lt $Total) {
        Start-Sleep -Milliseconds $DelayMs
    }
}

# Summary
$elapsedTotal = (Get-Date) - $startTime
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "Total:      $Total requests in $([math]::Round($elapsedTotal.TotalSeconds, 1))s"
Write-Host "Success:    $ok"
Write-Host "Failed:     $fail"
$rate = if (($ok + $fail) -gt 0) { [math]::Round($ok / ($ok + $fail) * 100, 1) } else { 0 }
Write-Host "Rate:       $rate%"

if ($latencies.Count -gt 0) {
    $min = ($latencies | Measure-Object -Min).Minimum
    $avg = [math]::Round(($latencies | Measure-Object -Average).Average, 1)
    $max = ($latencies | Measure-Object -Max).Maximum
    $sorted = $latencies | Sort-Object
    $med = $sorted[[math]::Floor($sorted.Count / 2)]
    $p95idx = [math]::Floor($sorted.Count * 0.95)
    if ($p95idx -ge $sorted.Count) { $p95idx = $sorted.Count - 1 }
    $p95 = $sorted[$p95idx]

    Write-Host ""
    Write-Host "Latency (ms):" -ForegroundColor Yellow
    Write-Host "  Min:    $min"
    Write-Host "  Avg:    $avg"
    Write-Host "  Max:    $max"
    Write-Host "  Median: $med"
    Write-Host "  P95:    $p95"
}

Write-Host ""
Write-Host "CSV: $OutFile"
Write-Host ""
