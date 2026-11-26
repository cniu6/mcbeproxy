package proxy

import "time"

// ConnectionIOError 只保留一次IO失败的摘要，不保存数据包、认证信息或持续事件列表。
type ConnectionIOError struct {
	At        time.Time `json:"at"`
	Operation string    `json:"operation"`
	Error     string    `json:"error"`
	Timeout   bool      `json:"timeout"`
	Repeat    uint64    `json:"repeat"`
}

// PacketBufferDiagnostic 是本传输连接生命周期内的接收队列快照。
// HY2 的底层连接可能被多个玩家共用，不能把这里的总丢包数当成某个玩家丢包。
type PacketBufferDiagnostic struct {
	QueuePackets     int       `json:"queue_packets"`
	QueueBytes       int       `json:"queue_bytes"`
	PacketLimit      int       `json:"packet_limit"`
	ByteLimit        int       `json:"byte_limit"`
	PeakPackets      int       `json:"peak_packets"`
	PeakBytes        int       `json:"peak_bytes"`
	ReceivedPackets  int64     `json:"received_packets"`
	ReceivedBytes    int64     `json:"received_bytes"`
	LastReceivedAt   time.Time `json:"last_received_at,omitzero"`
	DeliveredPackets int64     `json:"delivered_packets"`
	DeliveredBytes   int64     `json:"delivered_bytes"`
	DroppedPackets   int64     `json:"dropped_packets"`
	DroppedBytes     int64     `json:"dropped_bytes"`
	LastDropAt       time.Time `json:"last_drop_at,omitempty"`
	LastDropReason   string    `json:"last_drop_reason,omitempty"`
}

// ConnectionDiagnostic 的地址都是实际连接端点，不包含用户名、密码或订阅URL。
// 跳数字段只标识诊断所属的实际出站跳；0/空表示本机没有对应证据，不代表健康。
type ConnectionDiagnostic struct {
	ID                     string                  `json:"id"`
	Layer                  string                  `json:"layer"`
	CreatedAt              time.Time               `json:"created_at,omitempty"`
	HopIndex               int                     `json:"hop_index,omitempty"`
	HopName                string                  `json:"hop_name,omitempty"`
	HopProtocol            string                  `json:"hop_protocol,omitempty"`
	Proxy                  string                  `json:"proxy,omitempty"`
	Destination            string                  `json:"destination,omitempty"`
	ControlLocal           string                  `json:"control_local,omitempty"`
	ControlRemote          string                  `json:"control_remote,omitempty"`
	UDPLocal               string                  `json:"udp_local,omitempty"`
	Relay                  string                  `json:"relay,omitempty"`
	AssociationGeneration  uint64                  `json:"association_generation,omitempty"`
	ControlErrorGeneration uint64                  `json:"control_error_generation,omitempty"`
	LastError              ConnectionIOError       `json:"last_error"`
	ControlError           *ConnectionIOError      `json:"control_error,omitempty"`
	LatestIOError          *ConnectionIOError      `json:"latest_io_error,omitempty"`
	RemoteClosed           bool                    `json:"remote_closed"`
	Reconnecting           bool                    `json:"reconnecting"`
	LocallyClosed          bool                    `json:"locally_closed"`
	CauseScope             string                  `json:"cause_scope"`
	PacketBuffer           *PacketBufferDiagnostic `json:"packet_buffer,omitempty"`
}

// RouteDiagnosticHop 是一次连接实际绑定的出站跳序。Observed=false 只表示
// 本机没有该跳的运行时证据（不透明协议/未捕获），不能当成该跳健康或故障。
type RouteDiagnosticHop struct {
	Index    int    `json:"index"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Observed bool   `json:"observed"`
}

// routeHopIdentity 在创建出站时冻结，之后不随重载或新建连接改变。
type routeHopIdentity struct {
	index    int
	name     string
	protocol string
}

func (h routeHopIdentity) apply(d *ConnectionDiagnostic) {
	if d == nil || h.index <= 0 {
		return
	}
	d.HopIndex, d.HopName, d.HopProtocol = h.index, h.name, h.protocol
}

func (h routeHopIdentity) routeHop() RouteDiagnosticHop {
	return RouteDiagnosticHop{Index: h.index, Name: h.name, Protocol: h.protocol}
}
