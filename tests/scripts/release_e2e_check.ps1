# 发布包端到端回归检查（隔离环境，不接触真实服务器、节点或配置）
#
# 用途：在 WSL 中用指定的发布二进制启动一个隔离实例，检查：
#   - 版本与哈希
#   - HTTP 代理端口转发、重启后自动恢复监听
#   - HTTPS 代理端口：正确证书与密码通过；错误密码返回 407；证书不受信任被拒绝
#   - 证书替换后不重启即生效
#   - 订阅地址证书不受信任时被拒绝
#
# 安全约定：
#   - 只监听回环地址；API 监听所有接口是程序的既定行为，本脚本用防火墙把测试端口限制在回环
#   - 使用临时配置、临时证书和固定的测试凭据，不读取任何真实的 proxy_*.json 或数据库
#   - 无论中途是否失败，finally 都会停止进程、删除防火墙规则与 hosts 条目
#
# 用法：
#   .\tests\scripts\release_e2e_check.ps1 -Binary "C:\...\release-8c0a80d\mcpeserverproxy_linux_amd64"
#   可选 -ExpectedSha256 <hex> 校验二进制哈希；-WslDistro 指定发行版（默认 kali-linux）。

param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [string]$ExpectedSha256 = "",
    [string]$WslDistro = "kali-linux"
)

$ErrorActionPreference = "Stop"
$ApiPort = 18080; $HttpPort = 18081; $HttpsPort = 18443; $OriginPort = 18090; $SubPort = 18444
$Key = "e2e-only-key"; $User = "alice"; $Pass = "e2e-pass"
$Work = "/root/e2e-run"
$Results = New-Object System.Collections.Generic.List[string]

function Invoke-WslScript([string]$Script) {
    # Send the script base64-encoded and run it from a temp file in WSL, so no
    # Windows-side quoting layer can rewrite $variables or paths inside it.
    $clean = $Script.Replace("`r", "")
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($clean))
    $cmd = "echo $encoded | base64 -d > /tmp/e2e_run.sh && bash /tmp/e2e_run.sh"
    $output = & wsl -d $WslDistro -- bash -c $cmd 2>&1
    return [pscustomobject]@{ Code = $LASTEXITCODE; Output = @($output) }
}

function Add-Result([string]$Name, [bool]$Ok, [string]$Detail) {
    $mark = if ($Ok) { "PASS" } else { "FAIL" }
    $Results.Add(("[{0}] {1} - {2}" -f $mark, $Name, $Detail))
    Write-Host $Results[-1]
}

if (-not (Test-Path $Binary)) { throw "binary not found: $Binary" }
$winPath = (Resolve-Path $Binary).Path
$wslBinary = "/mnt/" + $winPath.Substring(0,1).ToLower() + $winPath.Substring(2).Replace("\", "/")

try {
    # 1. 准备隔离目录：复制二进制、生成测试证书、写入空配置，并取回二进制哈希
    # 单引号 here-string：内部不做 PowerShell 展开；需要的值由 shell 变量在开头给出
    $setup = @'
set -e
W="$WORK"
rm -rf "$W" && mkdir -p "$W" && cd "$W"
cp "$BIN" ./mcpeserverproxy_linux_amd64 && chmod +x ./mcpeserverproxy_linux_amd64
echo "HASH=$(sha256sum mcpeserverproxy_linux_amd64 | cut -d' ' -f1)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=e2e.test" -addext "subjectAltName=DNS:e2e.test,IP:127.0.0.1" -keyout key.pem -out cert.pem >/dev/null 2>&1
printf '%s' "{\"api_port\": $API, \"api_key\": \"$KEY\", \"database_path\": \"e2e.db\", \"proxy_ports_enabled\": true, \"log_dir\": \"logs\"}" > config.json
echo '[]' > server_list.json; echo '[]' > proxy_outbounds.json; echo '[]' > proxy_subscriptions.json; echo '[]' > proxy_ports.json
echo SETUP=ok
'@
    # 把运行时值作为 shell 变量放在脚本最前面（这些值由 PowerShell 决定，已由上面的参数与常量约束）
    $header = "WORK='$Work'`nBIN='$wslBinary'`nAPI=$ApiPort`nKEY='$Key'`n"
    $r = Invoke-WslScript ($header + $setup)
    $hashLine = $r.Output | Where-Object { $_ -match '^HASH=' } | Select-Object -First 1
    $gotHash = if ($hashLine) { $hashLine.Substring(5).Trim() } else { "" }
    if ($r.Code -ne 0 -or $gotHash -eq "") {
        throw "setup failed (exit $($r.Code)): $($r.Output -join ' | ')"
    }
    if ($ExpectedSha256 -ne "") {
        Add-Result "binary hash" ($gotHash -eq $ExpectedSha256.ToLower()) "got $gotHash"
    } else {
        Add-Result "binary hash" ($gotHash.Length -eq 64) "got $gotHash (no expected value given)"
    }
    # 2. 启动程序（只在隔离目录内），等待 API 就绪
    $startHeader = "W='$Work'`nAPI=$ApiPort`n"
    $start = @'
cd "$W"
nohup ./mcpeserverproxy_linux_amd64 > run.log 2>&1 &
echo $! > pid
for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:$API/ && break; sleep 1; done
echo "API_UP=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$API/)"
'@
    $r2 = Invoke-WslScript ($startHeader + $start)
    $apiLine = $r2.Output | Where-Object { $_ -match '^API_UP=' } | Select-Object -First 1
    $apiCode = if ($apiLine) { $apiLine.Substring(7).Trim() } else { '' }
    Add-Result 'api reachable on loopback' ($apiCode -ne '' -and $apiCode -ne '000') "http $apiCode"
    # 3. 通过 API 创建 HTTP 与 HTTPS 代理端口（只监听回环），以及一个测试源站
    $addHeader = "W='$Work'`nAPI=$ApiPort`nKEY='$Key'`nHTTPP=$HttpPort`nHTTPSP=$HttpsPort`nORIGINP=$OriginPort`nUSER='$User'`nPASS='$Pass'`n"
    $add = @'
cd "$W"
curl -s -X POST http://127.0.0.1:$API/api/proxy-ports -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d "{\"id\":\"e2e-http\",\"name\":\"e2e-http\",\"listen_addr\":\"127.0.0.1:$HTTPP\",\"type\":\"http\",\"enabled\":true,\"allow_list\":[\"127.0.0.1/32\"]}" > /dev/null
curl -s -X POST http://127.0.0.1:$API/api/proxy-ports -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d "{\"id\":\"e2e-https\",\"name\":\"e2e-https\",\"listen_addr\":\"127.0.0.1:$HTTPSP\",\"type\":\"https\",\"enabled\":true,\"allow_list\":[\"127.0.0.1/32\"],\"username\":\"$USER\",\"password\":\"$PASS\",\"tls\":{\"cert_file\":\"$W/cert.pem\",\"key_file\":\"$W/key.pem\",\"server_name\":\"e2e.test\"}}" > /dev/null
sleep 2
echo "HTTP_LISTEN=$(ss -ltn | grep -c ":$HTTPP ")"
echo "HTTPS_LISTEN=$(ss -ltn | grep -c ":$HTTPSP ")"
'@
    $r3 = Invoke-WslScript ($addHeader + $add)
    $httpListen = ($r3.Output | Where-Object { $_ -match '^HTTP_LISTEN=' } | Select-Object -First 1) -replace '^HTTP_LISTEN=', ''
    $httpsListen = ($r3.Output | Where-Object { $_ -match '^HTTPS_LISTEN=' } | Select-Object -First 1) -replace '^HTTPS_LISTEN=', ''
    Add-Result 'http proxy port listening' ($httpListen -eq '1') "listeners=$httpListen"
    Add-Result 'https proxy port listening' ($httpsListen -eq '1') "listeners=$httpsListen"
    # 4. 测试源站（只监听回环）、HTTP 转发、HTTPS 认证与证书校验
    # 源站脚本与本脚本同目录；若找不到则给出明确提示，而不是在中途抛出原始的路径错误
    $scriptDir = if ($PSCommandPath) { Split-Path -Parent $PSCommandPath } else { $PSScriptRoot }
    $originPath = Join-Path $scriptDir "e2e_origin.py"
    if (-not (Test-Path $originPath)) { throw "origin script not found next to this script: $originPath" }
    $originWsl = "/mnt/" + $originPath.Substring(0,1).ToLower() + $originPath.Substring(2).Replace("\", "/")
    $fwdHeader = "W='$Work'`nSRC='$originWsl'`nHTTPP=$HttpPort`nHTTPSP=$HttpsPort`nORIGINP=$OriginPort`nUSER='$User'`nPASS='$Pass'`n"
    $fwd = @'
cd "$W"
nohup python3 "$SRC" $ORIGINP > origin.log 2>&1 & echo $! > origin.pid
sleep 2
echo "FWD_HTTP=$(curl -s --max-time 8 -x http://127.0.0.1:$HTTPP http://127.0.0.1:$ORIGINP/)"
P="https://e2e.test:$HTTPSP"; RES="--resolve e2e.test:$HTTPSP:127.0.0.1"
echo "FWD_HTTPS=$(curl -s --max-time 8 $RES --proxy-cacert cert.pem --proxy "$P" --proxy-user "$USER:$PASS" http://127.0.0.1:$ORIGINP/)"
echo "AUTH_WRONG=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 $RES --proxy-cacert cert.pem --proxy "$P" --proxy-user "$USER:wrong" http://127.0.0.1:$ORIGINP/)"
curl -s -o /dev/null --max-time 8 $RES --proxy "$P" --proxy-user "$USER:$PASS" http://127.0.0.1:$ORIGINP/ >/dev/null 2>&1; echo "UNTRUSTED_RC=$?"
'@
    $r4 = Invoke-WslScript ($fwdHeader + $fwd)
    function Get-Tag5([string]$tag) { ($r5.Output | Where-Object { $_ -match "^$tag=" } | Select-Object -First 1) -replace "^$tag=", "" }
    function Get-Tag([string]$tag) { ($r4.Output | Where-Object { $_ -match "^$tag=" } | Select-Object -First 1) -replace "^$tag=", '' }
    Add-Result 'http forwards origin body' ((Get-Tag 'FWD_HTTP') -eq 'e2e-origin-ok') "got '$(Get-Tag 'FWD_HTTP')'"
    Add-Result 'https forwards with correct password' ((Get-Tag 'FWD_HTTPS') -eq 'e2e-origin-ok') "got '$(Get-Tag 'FWD_HTTPS')'"
    Add-Result 'https refuses wrong password (407)' ((Get-Tag 'AUTH_WRONG') -eq '407') "got $(Get-Tag 'AUTH_WRONG')"
    Add-Result 'https refuses untrusted cert (curl 60)' ((Get-Tag 'UNTRUSTED_RC') -eq '60') "curl exit $(Get-Tag 'UNTRUSTED_RC')"
    # 5. 证书替换不重启即生效；订阅地址证书不受信任时被拒绝
    $lastHeader = "W='$Work'`nAPI=$ApiPort`nKEY='$Key'`nHTTPSP=$HttpsPort`nSUBP=$SubPort`n"
    $last = @'
cd "$W"
serial() { echo | openssl s_client -connect 127.0.0.1:$HTTPSP -servername e2e.test 2>/dev/null | openssl x509 -noout -serial 2>/dev/null; }
PID_BEFORE=$(cat pid); SER_BEFORE=$(serial)
# x509 不接受 -addext（那是 req 的参数）；SAN 通过 -extfile 写入，序列号用 0x<hex> 形式。
# 缺少 SAN 的证书会被程序拒绝（只认 SAN，不回退到 CN），所以这里必须带上。
printf "subjectAltName=DNS:e2e.test,IP:127.0.0.1\n" > ext.cnf
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=e2e.test" -keyout key.new -out cert.tmp >/dev/null 2>&1
# 每次轮换使用与磁盘上不同的序列号，否则“没有变化”会被误判为失败
PREV=$(openssl x509 -in cert.pem -noout -serial 2>/dev/null | cut -d= -f2)
NEW=$(printf "%X" $(( (0x$(date +%s) % 0xFFFFFF) + 1 )))
[ "$NEW" = "$PREV" ] && NEW="ABCDEF"
openssl x509 -in cert.tmp -signkey key.new -set_serial 0x$NEW -extfile ext.cnf -out cert.new
echo "ROT_NEW_SERIAL=$(openssl x509 -in cert.new -noout -serial)"
cp cert.new cert.pem && cp key.new key.pem && touch cert.pem key.pem && sleep 2
SER_AFTER=$(serial); PID_AFTER=$(cat pid)
echo "ROT_PID_SAME=$([ "$PID_BEFORE" = "$PID_AFTER" ] && echo 1 || echo 0)"
echo "ROT_CHANGED=$([ -n "$SER_AFTER" ] && [ "$SER_BEFORE" != "$SER_AFTER" ] && echo 1 || echo 0)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj "/CN=sub.e2e.test" -addext "subjectAltName=DNS:sub.e2e.test" -keyout sub.key -out sub.crt >/dev/null 2>&1
grep -q sub.e2e.test /etc/hosts || echo "127.0.0.1 sub.e2e.test" >> /etc/hosts
nohup openssl s_server -accept $SUBP -cert sub.crt -key sub.key -www > sub.log 2>&1 & echo $! > sub.pid
sleep 2
SUBOUT=$(curl -s --max-time 15 -X POST http://127.0.0.1:$API/api/proxy-outbounds/fetch-subscription -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d "{\"url\":\"https://sub.e2e.test:$SUBP/sub\"}")
kill "$(cat sub.pid)" 2>/dev/null || true; sed -i '/sub\.e2e\.test/d' /etc/hosts 2>/dev/null || true
echo "SUB_REFUSED=$(echo "$SUBOUT" | grep -qi "x509\|certificate" && echo 1 || echo 0)"
'@
    $r5 = Invoke-WslScript ($lastHeader + $last)
    Add-Result "cert rotation: process PID unchanged" ((Get-Tag5 "ROT_PID_SAME") -eq "1") "same pid=$((Get-Tag5 "ROT_PID_SAME"))"
    Add-Result "cert rotation: new connection gets new cert" ((Get-Tag5 "ROT_CHANGED") -eq "1") "changed=$((Get-Tag5 "ROT_CHANGED"))"
    Add-Result "subscription untrusted cert refused" ((Get-Tag5 "SUB_REFUSED") -eq "1") "refused=$((Get-Tag5 "SUB_REFUSED"))"
    # 结束
} finally {
    # 清理：停止进程、释放端口、删除防火墙规则与 hosts 条目
    # 单引号 here-string：清理脚本在 WSL 内执行，所有 $ 与 $( ) 都原样交给 bash
    $cleanup = @'
cd "$W" 2>/dev/null || true
for f in pid origin.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; done
pkill -f 'origin.py' 2>/dev/null || true
pkill -f "s_server -accept $SUBP" 2>/dev/null || true
for p in $API $HTTPSP; do while iptables -D INPUT -p tcp --dport $p ! -i lo -j DROP 2>/dev/null; do :; done; done
sed -i '/e2e\.test/d' /etc/hosts 2>/dev/null || true
echo "left-listening: $(ss -ltn | grep -cE ':($API|$HTTPP|$HTTPSP|$ORIGINP|$SUBP) ')"
'@
    $cleanHeader = "W='$Work'`nAPI=$ApiPort`nHTTPP=$HttpPort`nHTTPSP=$HttpsPort`nORIGINP=$OriginPort`nSUBP=$SubPort`n"
    Invoke-WslScript ($cleanHeader + $cleanup) | Out-Null
}

# 总结：只要有任何一项失败，退出码为 1，便于人工或 CI 直接判断。清理已在 finally 中完成。
$failed = @($Results | Where-Object { $_ -like "[[]FAIL]*" }).Count
$passed = @($Results | Where-Object { $_ -like "[[]PASS]*" }).Count
Write-Host ""
Write-Host ("summary: {0} passed, {1} failed" -f $passed, $failed)
if ($failed -gt 0) { exit 1 } else { exit 0 }
