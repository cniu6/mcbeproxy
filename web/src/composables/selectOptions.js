// 页面下拉选项的唯一来源：同一个选项只在这里定义一次，各页面直接引用，避免标签与取值各自漂移。

// 负载均衡策略（显式取值）。端口用户、分流规则等「继承上级」场景直接使用本列表，
// 清空即代表继承，因此这里不放空值选项。
export const loadBalanceOptions = [
  { label: '最低延迟', value: 'least-latency' },
  { label: '轮询', value: 'round-robin' },
  { label: '随机', value: 'random' },
  { label: '最少连接', value: 'least-connections' }
]

// 负载均衡的延迟类型（端口与分流规则的默认为 TCP）
export const loadBalanceSortOptions = [
  { label: 'TCP延迟', value: 'tcp' },
  { label: 'HTTP延迟', value: 'http' },
  { label: 'UDP延迟', value: 'udp' }
]

// 服务器级负载均衡：'' 为默认项，沿用 Servers 页原有的选项顺序
export const serverLoadBalanceOptions = [
  { label: '最低延迟 (默认)', value: '' },
  ...loadBalanceOptions
]

// 服务器级延迟类型：默认 UDP（MCBE 默认），与 Servers 页 formLoadBalanceSort || 'udp' 一致
export const serverLoadBalanceSortOptions = [
  { label: 'UDP延迟 (MCBE默认)', value: 'udp' },
  { label: 'TCP延迟', value: 'tcp' },
  { label: 'HTTP延迟', value: 'http' }
]

// 全量测速模式；'' 为关闭
export const autoPingFullScanModeOptions = [
  { label: '关闭', value: '' },
  { label: '每天定时', value: 'daily' },
  { label: '固定间隔', value: 'interval' }
]

// 节点协议筛选：与后端 config.ProxyOutbound 支持的协议类型保持一致
export const proxyProtocolOptions = [
  { label: 'Shadowsocks', value: 'shadowsocks' },
  { label: 'ShadowsocksR', value: 'shadowsocksr' },
  { label: 'VMess', value: 'vmess' },
  { label: 'Trojan', value: 'trojan' },
  { label: 'VLESS', value: 'vless' },
  { label: 'SOCKS5', value: 'socks5' },
  { label: 'HTTP', value: 'http' },
  { label: 'AnyTLS', value: 'anytls' },
  { label: 'Hysteria2', value: 'hysteria2' },
  { label: 'TUIC', value: 'tuic' },
  { label: 'WireGuard', value: 'wireguard' },
  { label: 'Naive', value: 'naive' },
  { label: 'Hysteria (v1)', value: 'hysteria' },
  { label: 'Snell', value: 'snell' },
  { label: 'Mieru', value: 'mieru' },
  { label: 'ShadowQUIC', value: 'shadowquic' },
  { label: 'Sudoku', value: 'sudoku' },
  { label: 'Masque', value: 'masque' },
  { label: 'TrustTunnel', value: 'trusttunnel' },
  { label: '代理链条', value: 'chain' }
]

// 代理端口入口类型（唯一来源）。行内全部展示，HTTPS/HY2/Mieru 转完整配置表单。
// 批量改类型与批量新增仍只使用 proxyPortQuickTypeValues，避免丢 TLS 或身份配置。
export const proxyPortTypeOptions = [
  { label: 'HTTP', value: 'http' },
  { label: 'HTTPS · TLS 代理', value: 'https' },
  { label: 'SOCKS5', value: 'socks5' },
  { label: 'SOCKS4', value: 'socks4' },
  { label: '混合', value: 'mixed' },
  { label: 'HY2 · UDP 主力', value: 'hysteria2' },
  { label: 'Mieru · TCP 兼容', value: 'mieru' }
]

// 安全入口（独立身份/证书自动生成/快捷导入链接），与 HTTPS 入口互不混用
export const proxyPortSecureTypes = ['hysteria2', 'mieru']

// 可直接快捷切换的四种类型；其他入口在行内选中后需要完整配置。批量仍限这四种。
export const proxyPortQuickTypeValues = ['http', 'socks5', 'socks4', 'mixed']

// 黑/白名单的到期时长
export const expiryOptions = [
  { label: '永久', value: 'permanent' },
  { label: '12 小时', value: '12h' },
  { label: '1 天', value: '1d' },
  { label: '5 天', value: '5d' },
  { label: '15 天', value: '15d' },
  { label: '30 天', value: '30d' },
  { label: '自定义', value: 'custom' }
]
