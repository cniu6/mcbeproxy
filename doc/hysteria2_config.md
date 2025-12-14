# Hysteria2 配置说明

本项目完整支持 Hysteria2 协议，包括端口跳跃 (Port Hopping) 和 TLS 配置。

## 配置字段

### 基础字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | ✅ | 节点名称，唯一标识 |
| `type` | string | ✅ | 必须为 `hysteria2` |
| `server` | string | ✅ | 服务器地址 |
| `port` | int | ✅ | 服务器端口 (1-65535) |
| `enabled` | bool | ✅ | 是否启用 |
| `password` | string | ✅ | 认证密码 |

### TLS 配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `tls` | bool | `true` | Hysteria2 强制使用 TLS |
| `sni` | string | `server` | TLS SNI，默认使用服务器地址 |
| `insecure` | bool | `false` | 跳过证书验证 |
| `cert_fingerprint` | string | - | 服务器证书 SHA256 指纹 (用于证书固定) |

### 端口跳跃 (Port Hopping)

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `port_hopping` | string | - | 端口范围，格式: `起始端口-结束端口` (如 `20000-55000`) |
| `hop_interval` | int | `10` | 端口跳跃间隔 (秒) |

### 混淆 (Obfuscation)

| 字段 | 类型 | 说明 |
|------|------|------|
| `obfs` | string | 混淆类型，目前仅支持 `salamander` |
| `obfs_password` | string | 混淆密码 |

### 带宽配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `up_mbps` | int | `100` | 上传带宽限制 (Mbps) |
| `down_mbps` | int | `100` | 下载带宽限制 (Mbps) |

### 高级配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `disable_mtu` | bool | `false` | 禁用 Path MTU Discovery |

## 配置示例

### 基础配置

```json
{
  "name": "hy2-basic",
  "type": "hysteria2",
  "server": "example.com",
  "port": 443,
  "enabled": true,
  "password": "your-password",
  "sni": "example.com",
  "insecure": false
}
```

### 带端口跳跃的配置

```json
{
  "name": "hy2-port-hopping",
  "type": "hysteria2",
  "server": "example.com",
  "port": 443,
  "enabled": true,
  "password": "your-password",
  "sni": "example.com",
  "insecure": false,
  "port_hopping": "20000-55000",
  "hop_interval": 10
}
```

### 完整配置 (所有选项)

```json
{
  "name": "hy2-full",
  "type": "hysteria2",
  "server": "example.com",
  "port": 443,
  "enabled": true,
  "password": "your-password",
  "sni": "example.com",
  "insecure": false,
  "cert_fingerprint": "ba:88:45:17:a1:...",
  "port_hopping": "20000-55000",
  "hop_interval": 10,
  "obfs": "salamander",
  "obfs_password": "obfs-password",
  "up_mbps": 100,
  "down_mbps": 100,
  "disable_mtu": false
}
```

## 端口跳跃工作原理

端口跳跃是 Hysteria2 的一个重要特性，可以有效对抗基于端口的流量识别和封锁。

### 工作流程

1. 客户端首次连接时，从 `port_hopping` 范围内随机选择一个端口
2. 每隔 `hop_interval` 秒，客户端会切换到范围内的另一个随机端口
3. QUIC 协议的连接迁移特性确保切换端口时不会断开连接

### 服务端配置

服务端需要监听整个端口范围。以下是 Hysteria2 服务端配置示例：

```yaml
listen: :443

# 端口跳跃配置
portHopping:
  ports: 20000-55000

tls:
  cert: /path/to/cert.pem
  key: /path/to/key.pem

auth:
  type: password
  password: your-password
```

### 防火墙配置

确保服务器防火墙开放了端口范围：

```bash
# iptables
iptables -A INPUT -p udp --dport 20000:55000 -j ACCEPT

# ufw
ufw allow 20000:55000/udp

# firewalld
firewall-cmd --permanent --add-port=20000-55000/udp
firewall-cmd --reload
```

## 注意事项

1. **TLS 是强制的**: Hysteria2 基于 QUIC 协议，必须使用 TLS
2. **UDP 必须启用**: 确保服务端启用了 UDP 中继功能
3. **带宽设置**: 建议根据实际网络情况设置带宽限制，过高的设置可能导致拥塞
4. **证书验证**: 生产环境建议使用有效证书，或使用 `cert_fingerprint` 进行证书固定
