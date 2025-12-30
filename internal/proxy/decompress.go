// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"

	"github.com/golang/snappy"
)

// MaxDecompressedPacketBytes 限制解压后的最大数据量，避免解压炸弹。
const MaxDecompressedPacketBytes = 4 * 1024 * 1024

func decompressFlateLimited(data []byte) ([]byte, error) {
	buf := bytes.NewReader(data)
	reader := flate.NewReader(buf)
	defer reader.Close()

	if err := reader.(flate.Resetter).Reset(buf, nil); err != nil {
		return nil, err
	}

	var result bytes.Buffer
	limited := io.LimitReader(reader, MaxDecompressedPacketBytes+1)
	n, err := result.ReadFrom(limited)
	if err != nil {
		return nil, err
	}
	if n > MaxDecompressedPacketBytes {
		return nil, fmt.Errorf("解压数据过大")
	}
	return result.Bytes(), nil
}

func decompressSnappyLimited(data []byte) ([]byte, error) {
	decodedLen, err := snappy.DecodedLen(data)
	if err != nil {
		return nil, err
	}
	if decodedLen > MaxDecompressedPacketBytes {
		return nil, fmt.Errorf("解压数据过大")
	}
	return snappy.Decode(nil, data)
}
