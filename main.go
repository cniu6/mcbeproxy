package main

import (
	"context"       // 用于代理的优雅关闭
	"crypto/rand"   // 用于生成安全的API密钥
	"crypto/subtle" // 用于常量时间比较，防止时序攻击
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"    // 用于URL解码路径参数
	"os"
	"strings"    // 用于处理Bearer token
	"sync"       // 用于并发控制，sync.Map和Mutex
	"sync/atomic" // 用于原子操作，如流量计数
	"time"

	"github.com/rs/cors" // 导入 CORS 库
)

// 常量定义
const (
	MaxUDPPacketSize   = 8192         // 增大UDP数据包大小，确保能处理Minecraft的大数据包
	UDPBufferMultiple  = 10           // UDP缓冲区倍数
	MinimalLogInterval = 5000         // 最小日志记录间隔(毫秒)
	StatsSaveInterval  = 30           // 流量统计保存间隔(秒)
	StatsFileName      = "stats.json" // 流量统计文件名
	GlobalConfigFile   = "config.json"// 全局配置文件
	ProxiesFileName    = "proxies.json" // 代理规则文件名，新增
)

// 全局配置
type GlobalConfig struct {
	Debug            bool   `json:"debug"`              // 是否启用调试日志
	APIPort          int    `json:"api_port"`           // API服务端口
	StatsSaveSeconds int    `json:"stats_save_seconds"` // 统计数据保存间隔(秒)
	InactiveTimeout  int    `json:"inactive_timeout"`   // 不活跃客户端超时时间(分钟)
	MaxPacketSize    int    `json:"max_packet_size"`    // 最大UDP数据包大小
	BufferMultiple   int    `json:"buffer_multiple"`    // 缓冲区大小倍数
	StatsFile        string `json:"stats_file"`         // 统计数据文件名
	APIKey           string `json:"api_key"`            // API 密钥
	ProxiesFile      string `json:"proxies_file"`       // 代理规则文件名
}

// Config 保存代理配置信息
type Config struct {
	ListenAddr string `json:"listen_addr"` // 本地监听地址
	TargetAddr string `json:"target_addr"` // 目标服务器地址
	Protocol   string `json:"protocol"`    // 协议类型 "udp", "tcp", 或 "both"
}

// 客户端连接信息
type ClientInfo struct {
	IP            string       // 客户端IP地址
	Port          int          // 客户端端口
	ConnTime      time.Time    // 连接时间
	LastSeen      time.Time    // 最后活动时间
	LastLogged    time.Time    // 最后记录日志时间
	Conn          *net.UDPConn // 连接到目标服务器的UDP连接 (仅用于UDP)
	PacketCount   int64        // 处理的数据包数量
	BytesSent     int64        // 发送的字节数
	BytesReceived int64        // 接收的字节数
}

// 流量统计信息
type TrafficStats struct {
	IP            string `json:"ip"`             // 客户端IP地址
	BytesSent     int64 `json:"bytes_sent"`     // 发送的字节数
	BytesReceived int64 `json:"bytes_received"` // 接收的字节数
	PacketCount   int64 `json:"packet_count"`   // 数据包数量
	ConnTime      int64 `json:"conn_time"`      //连接时间（秒级时间戳）
	LastSeen      int64 `json:"last_seen"`      //最后活动时间（秒级时间戳）
	IsOnline      bool  `json:"is_online"`      //是否在线
}

// 服务器统计信息
type ServerStats struct {
	OnlineCount    int            `json:"online_count"`    // 在线玩家数
	TotalTraffic   int64          `json:"total_traffic"`   // 总流量(字节)
	TotalPackets   int64          `json:"total_packets"`   // 总数据包数
	StartTime      int64          `json:"start_time"`      // 服务启动时间（秒级时间戳）
	LastUpdated    int64          `json:"last_updated"`    // 最后更新时间（秒级时间戳）
	ClientsTraffic []TrafficStats `json:"clients_traffic"` // 客户端流量统计
}

// ProxyInstance 结构体用于管理一个正在运行的代理实例
type ProxyInstance struct {
	Config      Config
	Cancel      context.CancelFunc // 用于取消代理协程
	UDPListener *net.UDPConn       // UDP 监听器
	TCPListener net.Listener       // TCP 监听器
}

// 全局变量
var (
	clientInfoMap      sync.Map     // 客户端连接信息映射
	serverStartTime    time.Time    // 服务启动时间
	totalBytesSent     int64        // 总发送字节数
	totalBytesReceived int64        // 总接收字节数
	totalPackets       int64        // 总数据包数
	statsLock          sync.RWMutex // 统计数据锁
	currentStats       ServerStats  // 当前统计数据
	globalConfig       GlobalConfig // 全局配置

	// 用于动态代理管理
	activeProxies     map[string]*ProxyInstance // 存储所有正在运行的代理，键为 ListenAddr
	activeProxiesMux  sync.Mutex                // 保护 activeProxies 映射的并发访问
)

// generateAPIKey 生成一个安全的API密钥
func generateAPIKey() (string, error) {
	b := make([]byte, 32) // 32字节，Base64编码后大约44字符
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// 加载全局配置
func loadGlobalConfig() error {
	// 设置默认值
	globalConfig = GlobalConfig{
		Debug:            false,
		APIPort:          8080,
		StatsSaveSeconds: 30,
		InactiveTimeout:  5,
		MaxPacketSize:    8192,
		BufferMultiple:   10,
		StatsFile:        "stats.json",
		APIKey:           "",             // 初始为空，如果文件不存在或为空则生成
		ProxiesFile:      "proxies.json", // 默认代理规则文件
	}

	// 尝试从文件加载配置
	file, err := os.Open(GlobalConfigFile)
	if os.IsNotExist(err) {
		log.Printf("全局配置文件 %s 不存在，创建默认配置。", GlobalConfigFile)
		// 生成新的API密钥
		newKey, keyErr := generateAPIKey()
		if keyErr != nil {
			return fmt.Errorf("生成API密钥失败: %v", keyErr)
		}
		globalConfig.APIKey = newKey
		log.Printf("已生成新的API密钥: %s (请妥善保管此密钥)", globalConfig.APIKey)
		return saveGlobalConfig()
	} else if err != nil {
		return fmt.Errorf("打开全局配置文件失败: %v", err)
	}
	defer file.Close()

	// 解析配置
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&globalConfig); err != nil {
		return fmt.Errorf("解析全局配置文件失败: %v", err)
	}

	// 如果APIKey为空，则生成一个新的
	if globalConfig.APIKey == "" {
		newKey, keyErr := generateAPIKey()
		if keyErr != nil {
			return fmt.Errorf("生成API密钥失败: %v", keyErr)
		}
		globalConfig.APIKey = newKey
		log.Printf("全局配置文件中的API密钥为空，已生成新的密钥: %s (请妥善保管此密钥)", globalConfig.APIKey)
		return saveGlobalConfig() // 保存新的密钥到文件
	}

	return nil
}

// 保存全局配置
func saveGlobalConfig() error {
	file, err := os.Create(GlobalConfigFile)
	if err != nil {
		return fmt.Errorf("创建全局配置文件失败: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	return encoder.Encode(globalConfig)
}

// ====================================================================
// 代理规则持久化
// ====================================================================

// loadProxies 从 JSON 文件加载代理规则
func loadProxies() ([]Config, error) {
	var configs []Config
	file, err := os.Open(globalConfig.ProxiesFile)
	if os.IsNotExist(err) {
		log.Printf("代理规则文件 %s 不存在，将从空配置启动。", globalConfig.ProxiesFile)
		return configs, nil // 文件不存在不是错误，返回空配置
	}
	if err != nil {
		return nil, fmt.Errorf("打开代理规则文件失败: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&configs); err != nil {
		return nil, fmt.Errorf("解析代理规则文件失败: %v", err)
	}
	log.Printf("已加载 %d 条代理规则从 %s。", len(configs), globalConfig.ProxiesFile)
	return configs, nil
}

// saveProxies 将当前所有激活的代理规则保存到 JSON 文件
func saveProxies() error {
	activeProxiesMux.Lock()
	defer activeProxiesMux.Unlock()

	var configsToSave []Config
	for _, p := range activeProxies {
		configsToSave = append(configsToSave, p.Config)
	}

	file, err := os.Create(globalConfig.ProxiesFile)
	if err != nil {
		return fmt.Errorf("创建代理规则文件失败: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(configsToSave); err != nil {
		return fmt.Errorf("写入代理规则文件失败: %v", err)
	}
	if globalConfig.Debug {
		log.Printf("已保存 %d 条代理规则到 %s。", len(configsToSave), globalConfig.ProxiesFile)
	}
	return nil
}

// ====================================================================
// 代理服务核心逻辑
// ====================================================================

// 设置UDP连接的缓冲区大小
func setUDPSocketOptions(conn *net.UDPConn) error {
	if err := conn.SetReadBuffer(globalConfig.MaxPacketSize * globalConfig.BufferMultiple); err != nil {
		return fmt.Errorf("设置读取缓冲区失败: %v", err)
	}
	if err := conn.SetWriteBuffer(globalConfig.MaxPacketSize * globalConfig.BufferMultiple); err != nil {
		return fmt.Errorf("设置写入缓冲区失败: %v", err)
	}
	return nil
}

// 获取或创建客户端信息
func getOrCreateClientInfo(clientAddr *net.UDPAddr) *ClientInfo {
	clientKey := clientAddr.String()
	now := time.Now()

	val, exists := clientInfoMap.Load(clientKey)
	if exists {
		clientInfo := val.(*ClientInfo)
		clientInfo.LastSeen = now
		atomic.AddInt64(&clientInfo.PacketCount, 1) // 应该在收到每个包时都增加
		return clientInfo
	}

	clientInfo := &ClientInfo{
		IP:            clientAddr.IP.String(),
		Port:          clientAddr.Port,
		ConnTime:      now,
		LastSeen:      now,
		LastLogged:    now.Add(-1 * time.Hour), // 确保第一个包会被记录
		PacketCount:   1,
		BytesSent:     0,
		BytesReceived: 0,
	}

	log.Printf("新UDP客户端连接: %s (IP: %s, 端口: %d)", clientKey, clientInfo.IP, clientInfo.Port)
	clientInfoMap.Store(clientKey, clientInfo)
	updateStats() // 有新客户端连接时更新统计
	return clientInfo
}

// 启动UDP代理服务器
func startUDPProxy(ctx context.Context, config Config, listener *net.UDPConn) {
	log.Printf("UDP代理已启动: %s -> %s\n", config.ListenAddr, config.TargetAddr)

	clients := sync.Map{} // 存储客户端与目标服务器的UDP连接
	clientListener := listener // 保存原始监听器的引用，用于响应客户端

	buffer := make([]byte, globalConfig.MaxPacketSize)

	// 在循环外部预解析目标地址，避免每次发送都解析
	targetUDPAddr, err := net.ResolveUDPAddr("udp", config.TargetAddr)
	if err != nil {
		log.Printf("严重错误: 解析UDP目标地址 %s 失败: %v. 该代理无法正常工作。", config.TargetAddr, err)
		listener.Close() // 如果无法解析目标地址，这个代理就没有意义了，应该立即退出监听器
		// 注意：这里不会调用 ctx.Done()，因为这个错误发生在代理启动前，而非运行时
		return
	}

	for {
		select {
		case <-ctx.Done():
			log.Printf("UDP代理 %s 已停止.", config.ListenAddr)
			listener.Close() // 关闭监听器，停止接收主循环的新数据
			// 遍历并关闭所有客户端连接到目标服务器的UDP连接
			clients.Range(func(key, value interface{}) bool {
				if conn, ok := value.(*net.UDPConn); ok {
					conn.Close() // 关闭到目标的连接
				}
				clients.Delete(key) // 从map中删除
				return true
			})
			return
		default:
			// 设置读取超时，以便检查 context.Done()
			listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, clientAddr, err := listener.ReadFromUDP(buffer)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					continue // 超时，继续循环检查 context
				}
				// 避免打印"use of closed network connection"错误，因为这可能是正常关闭
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("UDP代理 %s 读取UDP数据出错: %v\n", config.ListenAddr, err)
				}
				continue
			}

			// 获取或创建客户端信息
			clientInfo := getOrCreateClientInfo(clientAddr) // 内部已增加packetCount

			// 统计流量 (收到的来自客户端的包)
			atomic.AddInt64(&clientInfo.BytesReceived, int64(n))
			atomic.AddInt64(&totalBytesReceived, int64(n))
			atomic.AddInt64(&totalPackets, 1)

			// 限制日志频率，避免日志处理影响性能
			now := time.Now()
			shouldLog := globalConfig.Debug &&
				now.Sub(clientInfo.LastLogged).Milliseconds() > MinimalLogInterval

			if shouldLog {
				log.Printf("[UDP]%s收到来自 %s 的请求，大小: %d 字节", config.ListenAddr, clientAddr.String(), n)
				clientInfo.LastLogged = now
			}

			// 查找或创建到目标服务器的连接
			targetConnVal, exists := clients.Load(clientAddr.String())
			var targetConn *net.UDPConn
			if !exists {
				// 创建新连接：将第二个参数 (laddr) 设置为 nil，让系统自动选择一个端口
				var dialErr error
				targetConn, dialErr = net.DialUDP("udp", nil, targetUDPAddr) // 直接连接到目标地址
				if dialErr != nil {
					log.Printf("连接目标服务器 %s 失败: %v\n", config.TargetAddr, dialErr)
					continue
				}

				// 设置目标连接的UDP套接字选项
				if err := setUDPSocketOptions(targetConn); err != nil {
					log.Printf("警告: 设置目标UDP连接选项失败: %v", err)
				}

				clientInfo.Conn = targetConn // 保存目标连接到 ClientInfo
				clients.Store(clientAddr.String(), targetConn)

				// 启动从目标到客户端的转发goroutine
				go func(ctx context.Context, clientAddr *net.UDPAddr, targetConn *net.UDPConn, clientInfo *ClientInfo) {
					respBuffer := make([]byte, globalConfig.MaxPacketSize)
					defer func() {
						log.Printf("关闭目标连接 %s (来自 %s)", targetConn.RemoteAddr().String(), clientInfo.IP)
						targetConn.Close()
						clients.Delete(clientAddr.String()) // 从映射中删除此客户端
						updateStats()
					}()

					for {
						select {
						case <-ctx.Done():
							return // 代理已停止
						default:
							targetConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
							n, err := targetConn.Read(respBuffer)
							if err != nil {
								if err, ok := err.(net.Error); ok && err.Timeout() {
									continue // 超时，继续循环检查 context
								}
								// 避免打印"use of closed network connection"错误
								if !strings.Contains(err.Error(), "use of closed network connection") {
									log.Printf("从目标读取失败 (%s): %v\n", config.TargetAddr, err)
								}
								return // 读取失败，退出协程
							}

							// 统计流量 (发送给客户端的包)
							atomic.AddInt64(&clientInfo.BytesSent, int64(n))
							atomic.AddInt64(&totalBytesSent, int64(n))

							// 限制日志频率
							now := time.Now()
							shouldLog := globalConfig.Debug && now.Sub(clientInfo.LastLogged).Milliseconds() > MinimalLogInterval
							if shouldLog {
								log.Printf("[UDP]%s向 %s 发送响应，大小: %d 字节", config.ListenAddr, clientAddr.String(), n)
								clientInfo.LastLogged = now
							}

							// 使用原始监听器发送响应，避免创建新连接
							_, err = clientListener.WriteToUDP(respBuffer[:n], clientAddr)
							if err != nil {
								log.Printf("向客户端写入失败 (%s): %v\n", clientAddr.String(), err)
								return // 写入失败，退出协程
							}

							// 只有从目标读取并成功写回客户端才更新 lastSeen 和 packetCount
							clientInfo.LastSeen = now
							atomic.AddInt64(&clientInfo.PacketCount, 1)
						}
					}
				}(ctx, clientAddr, targetConn, clientInfo)
			} else {
				targetConn = targetConnVal.(*net.UDPConn)
			}

			// 将数据转发到目标：使用 Write 方法，因为 targetConn 已经是"预连接"的
			_, err = targetConn.Write(buffer[:n])
			if err != nil {
				log.Printf("向目标写入失败 (%s -> %s): %v\n", clientAddr.String(), config.TargetAddr, err)
				// 如果写入失败，清理连接
				if clientInfo.Conn != nil {
					clientInfo.Conn.Close()
				}
				clients.Delete(clientAddr.String())
				updateStats()
				continue
			}
		}
	}
}

// 检查网络错误是否为超时错误
func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}

// 处理单个TCP连接
func handleTCPConnection(client net.Conn, targetAddr string) {
	clientAddr := client.RemoteAddr().String()
	log.Printf("新TCP连接: %s", clientAddr)

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("连接目标服务器失败 (%s -> %s): %v\n", clientAddr, targetAddr, err)
		client.Close()
		return
	}

	// 设置TCP连接选项，减少延迟
	if tcpConn, ok := target.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	if tcpConn, ok := client.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 -> 目标转发
	go func() {
		defer wg.Done()
		bytesCopied, err := io.Copy(target, client)
		if err != nil && err != io.EOF && !isTimeout(err) {
			log.Printf("TCP客户端->目标复制错误 (%s -> %s): %v\n", clientAddr, targetAddr, err)
		}
		if globalConfig.Debug && bytesCopied > 0 {
			log.Printf("从TCP客户端 %s 传输了 %d 字节到目标 %s\n", clientAddr, bytesCopied, targetAddr)
		}
		atomic.AddInt64(&totalBytesReceived, bytesCopied) // 统计接收到的字节数
		if tcpConn, ok := target.(*net.TCPConn); ok {
			tcpConn.CloseWrite() // 关闭目标连接的写入端
		}
	}()

	// 目标 -> 客户端转发
	go func() {
		defer wg.Done()
		bytesCopied, err := io.Copy(client, target)
		if err != nil && err != io.EOF && !isTimeout(err) {
			log.Printf("TCP目标->客户端复制错误 (%s -> %s): %v\n", targetAddr, clientAddr, err)
		}
		if globalConfig.Debug && bytesCopied > 0 {
			log.Printf("从TCP目标 %s 传输了 %d 字节到客户端 %s\n", bytesCopied, targetAddr, clientAddr)
		}
		atomic.AddInt64(&totalBytesSent, bytesCopied) // 统计发送的字节数
		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.CloseWrite() // 关闭客户端连接的写入端
		}
	}()

	// 等待双向复制完成，然后关闭连接
	wg.Wait()
	log.Printf("关闭TCP连接: %s -> %s\n", clientAddr, targetAddr)
	client.Close()
	target.Close()
}

// 启动TCP代理服务器
func startTCPProxy(ctx context.Context, config Config, listener net.Listener) {
	log.Printf("TCP代理已启动: %s -> %s\n", config.ListenAddr, config.TargetAddr)

	go func() { // 独立协程接受连接
		defer func() {
			log.Printf("TCP代理 %s 已停止.", config.ListenAddr)
			listener.Close() // 停止接受新连接
		}()
		for {
			// 设置 Accept 的超时时间，以便在阻塞等待新连接时也能响应 context.Done()
			if tcpListener, ok := listener.(*net.TCPListener); ok {
				tcpListener.SetDeadline(time.Now().Add(100 * time.Millisecond))
			}

			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done(): // 检查上下文是否已关闭
					return // 如果是因上下文取消而发生的错误，则正常退出
				default:
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue // 超时不是错误，继续循环
					}
					// 避免打印"use of closed network connection"错误
					if !strings.Contains(err.Error(), "use of closed network connection") {
						log.Printf("接受TCP连接失败 (%s): %v\n", config.ListenAddr, err)
					}
					// 短暂等待，避免CPU空转
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}

			// 为每个连接启动一个处理goroutine
			go handleTCPConnection(conn, config.TargetAddr)
		}
	}()
	<-ctx.Done() // 等待上下文取消信号
}

// ====================================================================
// 统计与清理
// ====================================================================

// 启动客户端清理goroutine
func startClientCleanup() {
	go func() {
		for {
			// 每分钟清理一次不活跃的客户端
			time.Sleep(1 * time.Minute)

			// 当前时间
			now := time.Now()

			// 超时时间：配置的分钟数没有活动
			timeout := time.Duration(globalConfig.InactiveTimeout) * time.Minute

			// 遍历所有客户端信息
			clientInfoMap.Range(func(key, value interface{}) bool {
				clientInfo := value.(*ClientInfo)

				// 如果客户端超过指定时间没有活动，则关闭连接并删除
				if now.Sub(clientInfo.LastSeen) > timeout {
					if globalConfig.Debug {
						log.Printf("清理不活跃客户端: %s (IP: %s, 端口: %d, 连接时长: %v)",
							key.(string), clientInfo.IP, clientInfo.Port,
							now.Sub(clientInfo.ConnTime))
					}

					// 关闭连接（仅适用于UDP连接，TCP连接在handleTCPConnection中已关闭）
					if clientInfo.Conn != nil {
						clientInfo.Conn.Close()
					}

					// 从映射中删除
					clientInfoMap.Delete(key)

					// 更新统计信息
					updateStats()
				}

				return true
			})
		}
	}()
}

// 更新服务器统计信息
func updateStats() {
	statsLock.Lock()
	defer statsLock.Unlock()

	// 当前时间戳（秒）
	nowTs := time.Now().Unix()

	// 更新当前统计数据
	currentStats.TotalTraffic = atomic.LoadInt64(&totalBytesSent) + atomic.LoadInt64(&totalBytesReceived)
	currentStats.TotalPackets = atomic.LoadInt64(&totalPackets)
	currentStats.LastUpdated = nowTs

	// 重置在线计数，稍后会重新计算
	currentStats.OnlineCount = 0

	// 使用map临时存储按IP地址合并的数据
	ipStats := make(map[string]*TrafficStats)

	// 首先将已有的离线客户端添加到map中
	// 这确保了即使客户端离线，其历史流量数据也得以保留
	for _, stats := range currentStats.ClientsTraffic {
		if !stats.IsOnline { // 只保留离线客户端的历史数据
			ipStats[stats.IP] = &TrafficStats{
				IP: stats.IP,
				BytesSent:     stats.BytesSent,
				BytesReceived: stats.BytesReceived,
				PacketCount:   stats.PacketCount,
				ConnTime:      stats.ConnTime,
				LastSeen:      stats.LastSeen,
				IsOnline:      false,
			}
		}
	}

	// 遍历所有在线客户端，按IP地址合并统计信息
	clientInfoMap.Range(func(key, value interface{}) bool {
		clientInfo := value.(*ClientInfo)

		// 使用IP作为唯一标识，合并相同IP的连接
		ipKey := clientInfo.IP

		// 客户端连接时间和最后活动时间转为时间戳（秒）
		connTimeTs := clientInfo.ConnTime.Unix()
		lastSeenTs := clientInfo.LastSeen.Unix()

		// 获取当前流量数据
		bytesSent := atomic.LoadInt64(&clientInfo.BytesSent)
		bytesReceived := atomic.LoadInt64(&clientInfo.BytesReceived)
		packetCount := atomic.LoadInt64(&clientInfo.PacketCount)

		// 如果这个IP已经有记录，则合并数据
		if existingStat, found := ipStats[ipKey]; found {
			// 对于在线记录，直接累加当前流量
			existingStat.BytesSent += bytesSent
			existingStat.BytesReceived += bytesReceived
			existingStat.PacketCount += packetCount
			existingStat.IsOnline = true // 更新为在线状态

			// 保留最新的最后活动时间
			if lastSeenTs > existingStat.LastSeen {
				existingStat.LastSeen = lastSeenTs
			}

			// 保留最早的连接时间
			if connTimeTs < existingStat.ConnTime {
				existingStat.ConnTime = connTimeTs
			}

		} else {
			// 如果没有历史记录，创建新记录
			ipStats[ipKey] = &TrafficStats{
				IP:            ipKey,
				BytesSent:     bytesSent,
				BytesReceived: bytesReceived,
				PacketCount:   packetCount,
				ConnTime:      connTimeTs,
				LastSeen:      lastSeenTs,
				IsOnline:      true,
			}
		}

		return true
	})

	// 将合并后的统计转换为切片，更新全局统计
	currentStats.ClientsTraffic = []TrafficStats{}
	for _, stat := range ipStats {
		if stat.IsOnline {
			currentStats.OnlineCount++
		}
		currentStats.ClientsTraffic = append(currentStats.ClientsTraffic, *stat)
	}
}

// 保存统计数据到JSON文件
func saveStatsToFile() error {
	statsLock.RLock()
	defer statsLock.RUnlock()

	file, err := os.Create(globalConfig.StatsFile)
	if err != nil {
		return fmt.Errorf("创建统计文件失败: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	return encoder.Encode(currentStats)
}

// 启动统计数据定期保存
func startStatsSaver() {
	go func() {
		for {
			// 每隔指定时间保存一次统计数据
			time.Sleep(time.Duration(globalConfig.StatsSaveSeconds) * time.Second)

			// 更新统计数据
			updateStats()

			// 保存到文件
			if err := saveStatsToFile(); err != nil {
				log.Printf("保存统计数据失败: %v", err)
			} else if globalConfig.Debug {
				log.Printf("已保存统计数据到 %s", globalConfig.StatsFile)
			}
		}
	}()
}

// 加载统计数据
func loadStatsFromFile() error {
	file, err := os.Open(globalConfig.StatsFile)
	if os.IsNotExist(err) {
		// 文件不存在，使用默认值
		log.Printf("统计文件 %s 不存在，将从零开始统计。", globalConfig.StatsFile)
		return nil
	}
	if err != nil {
		return fmt.Errorf("打开统计文件失败: %v", err)
	}
	defer file.Close()

	statsLock.Lock()
	defer statsLock.Unlock()

	// 创建临时变量存储从文件加载的统计数据
	var loadedStats ServerStats
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&loadedStats); err != nil {
		return fmt.Errorf("解析统计文件失败: %v", err)
	}

	// 将总流量和总数据包数从文件加载到内存
	// 注意：TCP流量是双向的，UDP流量也是双向统计，这里直接累加
	// 为了不因为重启而导致流量翻倍，将历史总流量折半分配给发送和接收
	// 实际运行时会精确统计
	atomic.StoreInt64(&totalBytesSent, loadedStats.TotalTraffic/2)
	atomic.StoreInt64(&totalBytesReceived, loadedStats.TotalTraffic/2)
	atomic.StoreInt64(&totalPackets, loadedStats.TotalPackets)

	// 保留服务器启动时间，但更新最后更新时间
	currentStats = loadedStats

	// 将所有客户端标记为离线
	for i := range currentStats.ClientsTraffic {
		currentStats.ClientsTraffic[i].IsOnline = false
	}
	// 重置在线玩家数量 (因为所有客户端都被标记为离线了)
	currentStats.OnlineCount = 0

	log.Printf("已加载统计数据: 总流量 %d 字节, 总数据包 %d 个", loadedStats.TotalTraffic, loadedStats.TotalPackets)
	return nil
}

// ====================================================================
// API 认证中间件
// ====================================================================

// authMiddleware 是一个HTTP中间件，用于验证API密钥
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OPTIONS 请求通常是 CORS 预检请求，不需要认证
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := r.Header.Get("Authorization")
		if apiKey == "" {
			http.Error(w, "Unauthorized:缺失Authorization头", http.StatusUnauthorized)
			return
		}

		// 预期格式: Bearer YOUR_API_KEY
		tokenParts := strings.SplitN(apiKey, " ", 2)
		if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
			http.Error(w, "Unauthorized: 无效Authorization头格式", http.StatusUnauthorized)
			return
		}

		providedKey := tokenParts[1]
		expectedKey := globalConfig.APIKey // 从全局配置中获取预期密钥

		// 使用 crypto/subtle.ConstantTimeCompare 进行常量时间比较，防止时序攻击
		if 1 != subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedKey)) {
			// 为了防止攻击者通过错误类型区分，返回通用错误信息
			http.Error(w, "Unauthorized: 无效API Key", http.StatusUnauthorized)
			return
		}

		// 认证成功，继续处理请求
		next.ServeHTTP(w, r)
	})
}

// ====================================================================
// API 相关处理函数
// ====================================================================

// 处理API请求 - 获取统计数据
func handleAPIStats(w http.ResponseWriter, r *http.Request) {
	statsLock.RLock()
	defer statsLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(currentStats)
}

// 处理API请求 - 获取在线玩家
func handleAPIPlayers(w http.ResponseWriter, r *http.Request) {
	statsLock.RLock() // 虽然 clientInfoMap 是 sync.Map，但为了与 updateStats 保持一致，也用 statsLock
	defer statsLock.RUnlock()

	type Player struct {
		IP       string `json:"ip"`
		LastSeen int64  `json:"last_seen"` // 最后活动时间（秒级时间戳）
	}

	// 使用map临时存储按IP地址合并的玩家数据
	ipPlayers := make(map[string]Player)

	// 遍历所有客户端，按IP地址合并
	clientInfoMap.Range(func(key, value interface{}) bool {
		clientInfo := value.(*ClientInfo)
		ipKey := clientInfo.IP

		// 转换为秒级时间戳
		lastSeenTs := clientInfo.LastSeen.Unix()

		// 如果这个IP已经有记录，则更新最后活动时间
		if existingPlayer, found := ipPlayers[ipKey]; found {
			// 保留最新的最后活动时间
			if lastSeenTs > existingPlayer.LastSeen {
				existingPlayer.LastSeen = lastSeenTs
				ipPlayers[ipKey] = existingPlayer
			}
		} else {
			// 创建新的玩家记录
			ipPlayers[ipKey] = Player{
				IP:       clientInfo.IP,
				LastSeen: lastSeenTs,
			}
		}

		return true
	})

	// 将合并后的玩家数据转换为切片
	var players []Player
	for _, player := range ipPlayers {
		players = append(players, player)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":   len(players),
		"players": players,
	})
}

// 处理API请求 - 清空统计数据
func handleAPIClearStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许POST请求", http.StatusMethodNotAllowed)
		return
	}

	statsLock.Lock()
	defer statsLock.Unlock()

	// 重置所有计数器
	atomic.StoreInt64(&totalBytesSent, 0)
	atomic.StoreInt64(&totalBytesReceived, 0)
	atomic.StoreInt64(&totalPackets, 0)

	// 保留在线用户，但清空他们的流量统计
	var onlineTraffic []TrafficStats
	for _, stat := range currentStats.ClientsTraffic {
		if stat.IsOnline {
			stat.BytesSent = 0
			stat.BytesReceived = 0
			stat.PacketCount = 0
			onlineTraffic = append(onlineTraffic, stat)
		}
	}

	// 更新当前统计
	currentStats.TotalTraffic = 0
	currentStats.TotalPackets = 0
	currentStats.LastUpdated = time.Now().Unix()
	currentStats.ClientsTraffic = onlineTraffic

	// 保存到文件
	if err := saveStatsToFile(); err != nil {
		log.Printf("保存重置的统计数据失败: %v", err)
		http.Error(w, fmt.Sprintf("保存重置的统计数据失败: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "统计数据已清空",
	})
}

// handleListProxies 处理 GET /api/proxies 请求，列出所有代理
func handleListProxies(w http.ResponseWriter, r *http.Request) {
	activeProxiesMux.Lock()
	defer activeProxiesMux.Unlock()

	var configs []Config
	for _, p := range activeProxies {
		configs = append(configs, p.Config)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(configs)
}

// startProxyForConfig 是一个辅助函数，用于根据 Config 启动一个代理实例
func startProxyForConfig(config Config) error {
	activeProxiesMux.Lock()
	defer activeProxiesMux.Unlock()

	if _, exists := activeProxies[config.ListenAddr]; exists {
		return fmt.Errorf("代理已存在于 %s，无法重复启动", config.ListenAddr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	proxyInstance := &ProxyInstance{
		Config: config,
		Cancel: cancel,
	}

	var hasListener bool // 标记是否成功启动了至少一个监听器
	if config.Protocol == "udp" || config.Protocol == "both" {
		listenUDPAddr, resolveErr := net.ResolveUDPAddr("udp", config.ListenAddr)
		if resolveErr != nil {
			cancel() // 即使还没启动监听，也要取消上下文
			return fmt.Errorf("解析UDP监听地址失败 (%s): %v", config.ListenAddr, resolveErr)
		}
		listener, listenErr := net.ListenUDP("udp", listenUDPAddr)
		if listenErr != nil {
			cancel() // 即使还没启动监听，也要取消上下文
			return fmt.Errorf("启动UDP监听失败 (%s): %v", config.ListenAddr, listenErr)
		}
		if err := setUDPSocketOptions(listener); err != nil {
			log.Printf("警告: 设置UDP套接字选项失败: %v", err)
		}
		proxyInstance.UDPListener = listener
		go startUDPProxy(ctx, config, listener)
		hasListener = true
	}

	if config.Protocol == "tcp" || config.Protocol == "both" {
		listener, listenErr := net.Listen("tcp", config.ListenAddr)
		if listenErr != nil {
			if proxyInstance.UDPListener != nil { // 如果UDP监听已启动，关闭它
				proxyInstance.UDPListener.Close()
			}
			cancel() // 即使TCP监听失败，也要取消上下文，确保所有协程和资源被释放
			return fmt.Errorf("启动TCP监听失败 (%s): %v", config.ListenAddr, listenErr)
		}
		proxyInstance.TCPListener = listener
		go startTCPProxy(ctx, config, listener)
		hasListener = true
	}

	// 如果没有成功启动任何监听器，则返回错误
	if !hasListener {
		cancel() // 确保上下文被取消
		return fmt.Errorf("未能为 %s 启动任何代理监听器 (协议: %s)", config.ListenAddr, config.Protocol)
	}

	activeProxies[config.ListenAddr] = proxyInstance
	log.Printf("已启动代理: %s (协议: %s) -> %s", config.ListenAddr, config.Protocol, config.TargetAddr)
	return nil
}


// handleAddProxy 处理 POST /api/proxies 请求，添加新代理
func handleAddProxy(w http.ResponseWriter, r *http.Request) {
	var config Config
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, fmt.Sprintf("无效的请求体: %v", err), http.StatusBadRequest)
		return
	}

	if config.ListenAddr == "" || config.TargetAddr == "" || config.Protocol == "" {
		http.Error(w, "ListenAddr, TargetAddr, Protocol 字段不能为空", http.StatusBadRequest)
		return
	}
	if config.Protocol != "udp" && config.Protocol != "tcp" && config.Protocol != "both" {
		http.Error(w, "Protocol 必须是 'udp', 'tcp' 或 'both'", http.StatusBadRequest)
		return
	}

	// 尝试启动代理
	err := startProxyForConfig(config)
	if err != nil {
		if strings.Contains(err.Error(), "代理已存在") { // 特殊处理已存在的情况
			http.Error(w, err.Error(), http.StatusConflict) // 409 Conflict
		} else if strings.Contains(err.Error(), "解析") || strings.Contains(err.Error(), "监听") {
			http.Error(w, err.Error(), http.StatusBadRequest) // 400 Bad Request (端口占用也归于此)
		} else {
			http.Error(w, fmt.Sprintf("启动代理失败: %v", err), http.StatusInternalServerError) // 500 Internal Server Error
		}
		return
	}

	// 启动成功后，持久化规则
	if err := saveProxies(); err != nil {
		log.Printf("警告: 保存代理规则失败: %v", err)
		// 即使保存失败，代理已经启动，也发送成功响应
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("代理 %s 已添加并启动", config.ListenAddr),
	})
}

// handleProxies 是一个统一的处理函数，根据请求方法分派给不同的子处理函数
func handleProxies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleListProxies(w, r)
	case http.MethodPost:
		handleAddProxy(w, r)
	default:
		// 对于其他不支持的方法，返回 405 Method Not Allowed
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}


func handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "只允许DELETE请求", http.StatusMethodNotAllowed)
		return
	}

	// r.URL.Path 包含完整的路径，例如 "/api/proxies/0.0.0.0%3A19132"
	// 需要移除前缀 "/api/proxies/" 来获取编码后的监听地址
	listenAddrEncoded := r.URL.Path[len("/api/proxies/"):]
	listenAddr, err := url.PathUnescape(listenAddrEncoded)
	if err != nil {
		http.Error(w, fmt.Sprintf("解码监听地址失败: %v", err), http.StatusBadRequest)
		return
	}

	activeProxiesMux.Lock()
	proxyInstance, exists := activeProxies[listenAddr]
	if !exists {
		activeProxiesMux.Unlock() // 未找到时也要解锁
		http.Error(w, fmt.Sprintf("代理 %s 不存在", listenAddr), http.StatusNotFound)
		return
	}
	delete(activeProxies, listenAddr) // 从内存中删除
	activeProxiesMux.Unlock()         // 解锁，以便 saveProxies 可以获取锁

	// 调用取消函数，停止代理协程
	proxyInstance.Cancel()
	// 明确关闭监听器，确保 goroutine 退出
	// 即使 context.Done() 会触发关闭，这里显式关闭可以立即释放端口
	if proxyInstance.UDPListener != nil {
		proxyInstance.UDPListener.Close()
	}
	if proxyInstance.TCPListener != nil {
		proxyInstance.TCPListener.Close()
	}

	log.Printf("通过API删除代理: %s", listenAddr)

	// 从文件持久化中删除
	if err := saveProxies(); err != nil {
		log.Printf("警告: 删除代理规则后保存失败: %v", err)
		// 即使保存失败，代理已经停止，也发送成功响应
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("代理 %s 已删除", listenAddr),
	})
}

// 启动API服务器
func startAPIServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stats", handleAPIStats)
	mux.HandleFunc("/api/players", handleAPIPlayers)
	mux.HandleFunc("/api/clear-stats", handleAPIClearStats)
	mux.HandleFunc("/api/proxies", handleProxies) // 统一处理 /api/proxies 的 GET/POST 请求
	mux.HandleFunc("/api/proxies/", handleDeleteProxy) // DELETE for delete (requires exact path matching)

	// 配置 CORS 中间件
	c := cors.New(cors.Options{
		// 允许所有来源，生产环境应限制为你的前端域名 (例如: []string{"http://localhost:8000", "https://your-frontend.com"})
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"}, // 允许Authorization头和Content-Type
		AllowCredentials: true,                                       // 如果需要发送cookies或HTTP认证，需要设置为true
		Debug:            globalConfig.Debug,                         // CORS 调试信息
	})

	// 将认证中间件应用于所有API路由
	// 顺序很重要：先认证，再 CORS。我们先用authMiddleware包装mux，然后用cors包装 authMux
	authMux := authMiddleware(mux)         // mux现在被authMiddleware保护
	handler := c.Handler(authMux) // cors再包装authMux，处理预检请求和添加CORS头

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", globalConfig.APIPort),
		Handler: handler, // 使用包装后的 handler
	}

	log.Printf("API服务已启动: http://localhost:%d", globalConfig.APIPort)
	log.Printf("- 获取统计数据: http://localhost:%d/api/stats", globalConfig.APIPort)
	log.Printf("- 获取在线玩家: http://localhost:%d/api/players", globalConfig.APIPort)
	log.Printf("- 清空统计数据: POST http://localhost:%d/api/clear-stats", globalConfig.APIPort)
	log.Printf("- 列出所有代理: GET http://localhost:%d/api/proxies", globalConfig.APIPort)
	log.Printf("- 添加新代理: POST http://localhost:%d/api/proxies", globalConfig.APIPort)
	log.Printf("- 删除代理: DELETE http://localhost:%d/api/proxies/{listen_addr_encoded}", globalConfig.APIPort)
	log.Printf("--------------------------------------------------")
	log.Printf("警告: APIKey: %s", globalConfig.APIKey) // 打印API密钥
	log.Printf("--------------------------------------------------")
	log.Printf("请务必使用 HTTPS/SSL/TLS 保护你的生产环境API！")
	log.Printf("AllowedOrigins: 请根据你的前端部署地址修改 Cors Options 中的 AllowedOrigins 设置！")


	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("API服务启动失败: %v", err)
		}
	}()
}


func main() {
	// 设置日志格式
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// 初始化 activeProxies map
	activeProxies = make(map[string]*ProxyInstance)

	// 加载全局配置
	// 如果config.json不存在或APIKey为空，将生成新的APIKey并保存
	if err := loadGlobalConfig(); err != nil {
		log.Fatalf("加载全局配置失败: %v", err) // 如果基本配置都无法加载，则致命错误
	} else {
		log.Printf("已加载全局配置: Debug=%v, APIPort=%d, StatsSaveInterval=%d秒, InactiveTimeout=%d分钟, ProxiesFile=%s",
			globalConfig.Debug, globalConfig.APIPort, globalConfig.StatsSaveSeconds, globalConfig.InactiveTimeout, globalConfig.ProxiesFile)
	}

	// 记录服务启动时间
	serverStartTime = time.Now()
	currentStats.StartTime = time.Now().Unix()

	// 加载统计数据 - 必须在设置serverStartTime之后调用
	if err := loadStatsFromFile(); err != nil {
		log.Printf("加载统计数据失败: %v，将从零开始统计。", err)
	}

	// 新增：加载并启动持久化代理规则
	initialProxies, err := loadProxies()
	if err != nil {
		log.Fatalf("加载代理规则失败: %v", err)
	}

	var anyProxyFailed bool
	for _, config := range initialProxies {
		// 每次尝试启动一个代理，如果失败则记录日志但不阻止其他代理启动
		if err := startProxyForConfig(config); err != nil {
			log.Printf("启动持久化代理 %s 失败: %v", config.ListenAddr, err)
			anyProxyFailed = true
		}
	}
	if anyProxyFailed {
		log.Printf("部分持久化代理启动失败，请检查端口占用或配置错误。")
		// 即使有代理启动失败，也尝试保存当前实际启动的代理列表
		// 这可以清理配置文件中不再能正常启动的条目
		if err := saveProxies(); err != nil {
			log.Printf("警告: 启动后保存实际代理列表失败: %v", err)
		}
	} else {
		log.Printf("已成功启动所有 %d 条持久化代理规则。", len(initialProxies))
	}

	// 启动后台Goroutine
	startClientCleanup()
	startStatsSaver()
	startAPIServer()

	log.Printf("Minecraft BE 代理服务已启动，等待API指令添加转发规则...")
	select {} // 阻塞主goroutine，直到程序退出
}