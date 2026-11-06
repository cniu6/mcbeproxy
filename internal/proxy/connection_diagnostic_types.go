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
	DeliveredPackets int64     `json:"delivered_packets"`
	DeliveredBytes   int64     `json:"delivered_bytes"`
	DroppedPackets   int64     `json:"dropped_packets"`
	DroppedBytes     int64     `json:"dropped_bytes"`
	LastDropAt       time.Time `json:"last_drop_at,omitempty"`
	LastDropReason   string    `json:"last_drop_reason,omitempty"`
}

// ConnectionDiagnostic 的地址都是实际连接端点，不包含用户名、密码或订阅URL。
type ConnectionDiagnostic struct {
	ID            string                  `json:"id"`
	Layer         string                  `json:"layer"`
	CreatedAt     time.Time               `json:"created_at,omitempty"`
	Proxy         string                  `json:"proxy,omitempty"`
	Destination   string                  `json:"destination,omitempty"`
	ControlLocal  string                  `json:"control_local,omitempty"`
	ControlRemote string                  `json:"control_remote,omitempty"`
	UDPLocal      string                  `json:"udp_local,omitempty"`
	Relay         string                  `json:"relay,omitempty"`
	LastError     ConnectionIOError       `json:"last_error"`
	ControlError  *ConnectionIOError      `json:"control_error,omitempty"`
	LatestIOError *ConnectionIOError      `json:"latest_io_error,omitempty"`
	RemoteClosed  bool                    `json:"remote_closed"`
	Reconnecting  bool                    `json:"reconnecting"`
	LocallyClosed bool                    `json:"locally_closed"`
	CauseScope    string                  `json:"cause_scope"`
	PacketBuffer  *PacketBufferDiagnostic `json:"packet_buffer,omitempty"`
}
