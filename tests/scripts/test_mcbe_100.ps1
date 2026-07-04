# MCBE UDP 100-request latency test
# Sends 100 consecutive POST requests to /api/proxy-outbounds/test-mcbe
# Records: request index, request start time, response latency_ms, HTTP round-trip ms, success
# Outputs: CSV to stdout and summary at the end

param(
    [string]$Node = "本地链式-sg-gcp-本地",
    [string]$Address = "mco.cubecraft.net:19132",
    [string]$BaseUrl = "http://127.0.0.1:8081",
    [int]$Count = 100,
    [int]$DelayMs = 500
)

$results = @()
$failCount = 0
$latencies = @()
$httpTimes = @()

Write-Host "=== MCBE UDP 100-request latency test ==="
Write-Host "Node: $Node"
Write-Host "Address: $Address"
Write-Host "Count: $Count"
Write-Host "Delay between requests: ${DelayMs}ms"
Write-Host ""
Write-Host ("{0,4} {1,12} {2,8} {3,8} {4,6} {5,8}" -f "Idx", "StartTime", "LatMs", "HttpMs", "OK", "Server")
Write-Host ("{0,4} {1,12} {2,8} {3,8} {4,6} {5,8}" -f "---", "---------", "-----", "------", "--", "------")

for ($i = 1; $i -le $Count; $i++) {
    $body = @{
        name = $Node
        address = $Address
    } | ConvertTo-Json -Compress

    $reqStart = Get-Date
    try {
        $resp = Invoke-RestMethod -Uri "$BaseUrl/api/proxy-outbounds/test-mcbe" `
            -Method Post -Body $body -ContentType "application/json" `
            -TimeoutSec 15
        $reqEnd = Get-Date
        $httpMs = [int]($reqEnd - $reqStart).TotalMilliseconds
        $latMs = $resp.data.latency_ms
        $ok = $resp.data.success
        $server = if ($resp.data.server_name) { $resp.data.server_name.Substring(0, [Math]::Min(8, $resp.data.server_name.Length)) } else { "" }
        
        $results += [PSCustomObject]@{
            Idx = $i
            StartTime = $reqStart.ToString("HH:mm:ss.fff")
            LatMs = $latMs
            HttpMs = $httpMs
            OK = $ok
            Server = $server
        }
        
        if ($ok) { $latencies += $latMs }
        else { $failCount++ }
        $httpTimes += $httpMs
        
        $marker = ""
        if ($httpMs -gt 500) { $marker = " <<< HIGH" }
        if (-not $ok) { $marker = " <<< FAIL" }
        Write-Host ("{0,4} {1,12} {2,8} {3,8} {4,6} {5,8}{6}" -f $i, $reqStart.ToString("HH:mm:ss.fff"), $latMs, $httpMs, $ok, $server, $marker)
    }
    catch {
        $reqEnd = Get-Date
        $httpMs = [int]($reqEnd - $reqStart).TotalMilliseconds
        $failCount++
        $httpTimes += $httpMs
        Write-Host ("{0,4} {1,12} {2,8} {3,8} {4,6} {5,8} <<< ERROR: {6}" -f $i, $reqStart.ToString("HH:mm:ss.fff"), "-", $httpMs, "ERR", "", $_.Exception.Message)
        $results += [PSCustomObject]@{
            Idx = $i
            StartTime = $reqStart.ToString("HH:mm:ss.fff")
            LatMs = -1
            HttpMs = $httpMs
            OK = $false
            Server = ""
        }
    }
    
    if ($i -lt $Count -and $DelayMs -gt 0) {
        Start-Sleep -Milliseconds $DelayMs
    }
}

Write-Host ""
Write-Host "=== Summary ==="
Write-Host "Total requests: $Count"
Write-Host "Successful: $($Count - $failCount)"
Write-Host "Failed: $failCount"

if ($latencies.Count -gt 0) {
    $avg = ($latencies | Measure-Object -Average).Average
    $min = ($latencies | Measure-Object -Minimum).Minimum
    $max = ($latencies | Measure-Object -Maximum).Maximum
    $sorted = $latencies | Sort-Object
    $p50 = $sorted[[int]($sorted.Count * 0.5)]
    $p90 = $sorted[[int]($sorted.Count * 0.9)]
    $p99 = $sorted[[int]($sorted.Count * 0.99)]
    
    Write-Host ""
    Write-Host "MCBE latency_ms stats (successful only):"
    Write-Host "  Min: $min ms"
    Write-Host "  Avg: $([math]::Round($avg, 1)) ms"
    Write-Host "  Max: $max ms"
    Write-Host "  P50: $p50 ms"
    Write-Host "  P90: $p90 ms"
    Write-Host "  P99: $p99 ms"
}

if ($httpTimes.Count -gt 0) {
    $hAvg = ($httpTimes | Measure-Object -Average).Average
    $hMin = ($httpTimes | Measure-Object -Minimum).Minimum
    $hMax = ($httpTimes | Measure-Object -Maximum).Maximum
    $hSorted = $httpTimes | Sort-Object
    $hP50 = $hSorted[[int]($hSorted.Count * 0.5)]
    $hP90 = $hSorted[[int]($hSorted.Count * 0.9)]
    
    Write-Host ""
    Write-Host "HTTP round-trip stats (all requests):"
    Write-Host "  Min: $hMin ms"
    Write-Host "  Avg: $([math]::Round($hAvg, 1)) ms"
    Write-Host "  Max: $hMax ms"
    Write-Host "  P50: $hP50 ms"
    Write-Host "  P90: $hP90 ms"
}

# Find spikes (> 2x average)
if ($latencies.Count -gt 0 -and $avg -gt 0) {
    Write-Host ""
    Write-Host "Spikes (>2x average of $($([math]::Round($avg, 1))) ms):"
    $spikeCount = 0
    foreach ($r in $results) {
        if ($r.OK -and $r.LatMs -gt ($avg * 2)) {
            Write-Host "  #$($r.Idx) start=$($r.StartTime) latMs=$($r.LatMs) httpMs=$($r.HttpMs)"
            $spikeCount++
        }
    }
    if ($spikeCount -eq 0) {
        Write-Host "  (none)"
    }
}
