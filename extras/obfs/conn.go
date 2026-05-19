package obfs

import (
	"net"
	"sync"
	"syscall"
	"time"
)

const udpBufferSize = 2048

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, udpBufferSize)
	},
}

// Obfuscator is the interface that wraps the Obfuscate and Deobfuscate methods.
type Obfuscator interface {
	Obfuscate(in, out []byte) int
	Deobfuscate(in, out []byte) int
}

var _ net.PacketConn = (*obfsPacketConn)(nil)

type obfsPacketConn struct {
	Conn net.PacketConn
	Obfs Obfuscator
}

// udpLikePacketConn is the subset of *net.UDPConn methods that quic-go relies
// on for UDP-specific optimizations.
type udpLikePacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

type obfsPacketConnUDP struct {
	*obfsPacketConn
	UDPConn udpLikePacketConn
}

// WrapPacketConn enables obfuscation on a net.PacketConn.
func WrapPacketConn(conn net.PacketConn, obfs Obfuscator) net.PacketConn {
	opc := &obfsPacketConn{
		Conn: conn,
		Obfs: obfs,
	}
	if udpConn, ok := conn.(udpLikePacketConn); ok {
		return &obfsPacketConnUDP{
			obfsPacketConn: opc,
			UDPConn:        udpConn,
		}
	}
	return opc
}

func (c *obfsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	for {
		n, addr, err = c.Conn.ReadFrom(buf)
		if n <= 0 {
			return n, addr, err
		}
		n = c.Obfs.Deobfuscate(buf[:n], p)
		if n > 0 || err != nil {
			return n, addr, err
		}
	}
}

func (c *obfsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	nn := c.Obfs.Obfuscate(p, buf)
	if nn <= 0 {
		return 0, nil
	}
	_, err = c.Conn.WriteTo(buf[:nn], addr)
	if err == nil {
		n = len(p)
	}
	return n, err
}

func (c *obfsPacketConn) Close() error {
	return c.Conn.Close()
}

func (c *obfsPacketConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *obfsPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *obfsPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *obfsPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (c *obfsPacketConnUDP) SetReadBuffer(bytes int) error {
	return c.UDPConn.SetReadBuffer(bytes)
}

func (c *obfsPacketConnUDP) SetWriteBuffer(bytes int) error {
	return c.UDPConn.SetWriteBuffer(bytes)
}

func (c *obfsPacketConnUDP) SyscallConn() (syscall.RawConn, error) {
	return c.UDPConn.SyscallConn()
}
