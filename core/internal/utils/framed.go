package utils

import (
	"crypto/rand"
	"io"
	"sync"

	"github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/quic-go/quicvarint"
)

const (
	// MaxFramedPaddingLength is the maximum allowed padding length inside a framed message.
	// This is set to the same value as MaxPaddingLength in protocol/proxy.go (4096)
	// to prevent DoS attacks via maliciously large varint padding claims.
	// See also: UDPMessage handling and ReadTCPRequest/ReadTCPResponse which use the same limit.
	MaxFramedPaddingLength = 4096
)

var framedBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// FramedReadWriter wraps an io.ReadWriter with Hysteria payload padding framing.
// Frame format: [DataLen (varint)][PaddingLen (varint)][Padding][Data]
//
// Padding strategy (analogous to UDPMessage in proxy.go):
// - Target total frame size ~1150 bytes (safe for most networks, same as UDP datagrams).
// - Random padding length up to 255 bytes when beneficial.
// - Actual padding bytes filled with crypto/rand for proper noise (not pool garbage).
type FramedReadWriter struct {
	RW     io.ReadWriter
	reader io.ByteReader
	left   []byte
}

func (f *FramedReadWriter) Read(b []byte) (int, error) {
	// 1. Return leftover data if any
	if len(f.left) > 0 {
		n := copy(b, f.left)
		f.left = f.left[n:]
		return n, nil
	}

	// 2. Read new frame
	if f.reader == nil {
		f.reader = quicvarint.NewReader(f.RW)
	}

	// Read DataLen
	dataLen, err := quicvarint.Read(f.reader)
	if err != nil {
		return 0, err
	}

	// Read PaddingLen
	padLen, err := quicvarint.Read(f.reader)
	if err != nil {
		return 0, err
	}

	// Check against max (analogous to MaxPaddingLength in protocol/proxy.go)
	// Prevents DoS via huge claimed padding (varint can encode very large values).
	if padLen > MaxFramedPaddingLength {
		return 0, errors.ProtocolError{Message: "invalid padding length"}
	}

	// Skip Padding
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, f.RW, int64(padLen)); err != nil {
			return 0, err
		}
	}

	// Read Data
	if dataLen == 0 {
		return 0, nil
	}

	if int(dataLen) <= len(b) {
		return io.ReadFull(f.RW, b[:dataLen])
	}

	// Data is larger than buffer b, read all of it and store leftover
	tempBuf := make([]byte, dataLen)
	if _, err := io.ReadFull(f.RW, tempBuf); err != nil {
		return 0, err
	}
	n := copy(b, tempBuf)
	f.left = tempBuf[n:]
	return n, nil
}

func (f *FramedReadWriter) Write(b []byte) (int, error) {
	dataLen := uint64(len(b))

	// Padding strategy analogous to UDP datagrams (targetLimit=1150, max 255)
	const targetFrameSize = 1150
	const maxFramedPadding = 255

	padLen := uint64(0)
	if int(dataLen) < targetFrameSize {
		maxPadding := targetFrameSize - int(dataLen) - 5 // conservative for varint overhead
		if maxPadding > maxFramedPadding {
			maxPadding = maxFramedPadding
		}
		if maxPadding > 0 {
			var rb [1]byte
			if _, err := rand.Read(rb[:]); err != nil {
				return 0, err
			}
			if maxPadding >= 255 {
				// 255 means full 0-255 range. rb[0] is already 0-255.
				// uint8(255+1) would be 0 → %0 panic. Use directly.
				padLen = uint64(rb[0])
			} else {
				padLen = uint64(rb[0] % uint8(maxPadding+1))
			}
		}
	}

	// Write Header
	h := quicvarint.Append(nil, dataLen)
	h = quicvarint.Append(h, padLen)
	if _, err := f.RW.Write(h); err != nil {
		return 0, err
	}

	// Write Padding using crypto/rand for real random noise
	if padLen > 0 {
		pad := make([]byte, padLen)
		if _, err := rand.Read(pad); err != nil {
			return 0, err
		}
		if _, err := f.RW.Write(pad); err != nil {
			return 0, err
		}
	}

	// Write Data
	return f.RW.Write(b)
}
