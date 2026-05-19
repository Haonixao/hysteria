package utils

import (
	"io"
	"math/rand/v2"
	"sync"

	"github.com/apernet/quic-go/quicvarint"
)

var framedBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// FramedReadWriter wraps an io.ReadWriter with Hysteria payload padding framing.
// Frame format: [DataLen (varint)][PaddingLen (varint)][Padding][Data]
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
	
	// Random padding length (0-32)
	padLen := uint64(rand.IntN(33))
	
	// Write Header
	h := quicvarint.Append(nil, dataLen)
	h = quicvarint.Append(h, padLen)
	if _, err := f.RW.Write(h); err != nil {
		return 0, err
	}
	
	// Write Padding (reuse existing buffer content as "noise")
	if padLen > 0 {
		bufp := framedBufPool.Get().(*[]byte)
		buf := *bufp
		defer framedBufPool.Put(bufp)
		
		if _, err := f.RW.Write(buf[:padLen]); err != nil {
			return 0, err
		}
	}
	
	// Write Data
	return f.RW.Write(b)
}
