# MCBE UDP concurrent latency test using runspaces (HttpClient)
param(
    [string]$Node = "本地链式-sg-gcp-本地",
    [string]$Address = "mco.cubecraft.net:19132",
    [string]$BaseUrl = "http://127.0.0.1:8081",
    [int]$Batches = 10,
    [int]$Concurrency = 5,
    [int]$DelayMs = 500
)

$bodyJson = @{ name = $Node; address = $Address } | ConvertTo-Json -Compress
$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyJson)
$url = "$BaseUrl/api/proxy-outbounds/test-mcbe"

$results = @()
$failCount = 0
$latencies = @()
$httpTimes = @()

Write-Host "=== MCBE UDP Concurrent latency test ==="
Write-Host "Node: $Node  Address: $Address"
Write-Host "Batches: $Batches x $Concurrency = $($Batches * $Concurrency) total, delay=${DelayMs}ms"
Write-Host ""
Write-Host ("{0,5} {1,4} {2,12} {3,8} {4,8} {5,6} {6,8}" -f "Batch", "Idx", "StartTime", "LatMs", "HttpMs", "OK", "Server")
Write-Host ("{0,5} {1,4} {2,12} {3,8} {4,8} {5,6} {6,8}" -f "-----", "---", "---------", "-----", "------", "--", "------")

for ($batch = 1; $batch -le $Batches; $batch++) {
    $runspaces = @()
    for ($i = 1; $i -le $Concurrency; $i++) {
        $ps = [PowerShell]::Create()
        [void]$ps.AddScript({
            param($Url, $BodyBytes, $BatchNum, $Idx)
            $reqStart = Get-Date
            try {
                $client = [System.Net.Http.HttpClient]::new()
                $client.Timeout = [TimeSpan]::FromSeconds(15)
                $content = [System.Net.Http.ByteArrayContent]::new($BodyBytes)
                $content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new("application/json")
                $response = $client.PostAsync($Url, $content).Result
                $json = $response.Content.ReadAsStringAsync().Result
                $resp = $json | ConvertFrom-Json
                $reqEnd = Get-Date
                $httpMs = [int]($reqEnd - $reqStart).TotalMilliseconds
                $client.Dispose()
                return [PSCustomObject]@{
                    Batch = $BatchNum; Idx = $Idx; StartTime = $reqStart.ToString("HH:mm:ss.fff")
                    LatMs = if ($resp.data.latency_ms) { [int]$resp.data.latency_ms } else { -1 }
                    HttpMs = $httpMs; OK = [bool]$resp.data.success
                    Server = if ($resp.data.server_name) { $resp.data.server_name.Substring(0, [Math]::Min(8, $resp.data.server_name.Length)) } else { "" }
                }
            } catch {
                $reqEnd = Get-Date
                $httpMs = [int]($reqEnd - $reqStart).TotalMilliseconds
                return [PSCustomObject]@{
                    Batch = $BatchNum; Idx = $Idx; StartTime = $reqStart.ToString("HH:mm:ss.fff")
                    LatMs = -1; HttpMs = $httpMs; OK = $false; Server = ""; Error = $_.Exception.Message
                }
            }
        }).AddArgument($url).AddArgument($bodyBytes).AddArgument($batch).AddArgument($i)
        $handle = $ps.BeginInvoke()
        $runspaces += [PSCustomObject]@{ PS = $ps; Handle = $handle }
    }
    foreach ($r in $runspaces) {
        $result = $r.PS.EndInvoke($r.Handle)
        $r.PS.Dispose()
        foreach ($obj in $result) {
            $marker = ""
            if ($obj.HttpMs -gt 500) { $marker = " <<< HIGH" }
            if (-not $obj.OK) { $marker = " <<< FAIL" }
            Write-Host ("{0,5} {1,4} {2,12} {3,8} {4,8} {5,6} {6,8}{7}" -f $obj.Batch, $obj.Idx, $obj.StartTime, $obj.LatMs, $obj.HttpMs, $obj.OK, $obj.Server, $marker)
            $results += $obj
            if ($obj.OK) { $latencies += $obj.LatMs } else { $failCount++ }
            $httpTimes += $obj.HttpMs
        }
    }
    if ($batch -lt $Batches -and $DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
}

Write-Host ""
Write-Host "=== Summary ==="
$totalReq = $Batches * $Concurrency
Write-Host "Total: $totalReq  OK: $($totalReq - $failCount)  Fail: $failCount"
if ($latencies.Count -gt 0) {
    $avg = ($latencies | Measure-Object -Average).Average
    $sorted = $latencies | Sort-Object
    Write-Host "MCBE lat: min=$(($latencies|Measure-Object -Min).Minimum) avg=$([math]::Round($avg,1)) max=$(($latencies|Measure-Object -Max).Maximum) p50=$($sorted[[int]($sorted.Count*0.5)]) p90=$($sorted[[int]($sorted.Count*0.9)])"
}
if ($httpTimes.Count -gt 0) {
    $hAvg = ($httpTimes | Measure-Object -Average).Average
    $hSorted = $httpTimes | Sort-Object
    Write-Host "HTTP rt: min=$(($httpTimes|Measure-Object -Min).Minimum) avg=$([math]::Round($hAvg,1)) max=$(($httpTimes|Measure-Object -Max).Maximum) p50=$($hSorted[[int]($hSorted.Count*0.5)]) p90=$($hSorted[[int]($hSorted.Count*0.9)])"
}
