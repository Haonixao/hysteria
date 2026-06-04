package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/apernet/hysteria/core/v2/errors"

	"github.com/apernet/quic-go/quicvarint"
)

const (
	FrameTypeTCPRequest = 0x401

	// Max length values are for preventing DoS attacks

	MaxAddressLength = 2048
	MaxMessageLength = 2048
	MaxPaddingLength = 4096

	MaxDatagramFrameSize = 1200
	MaxUDPSize           = 4096

	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

// TCPRequest format:
// 0x401 (QUIC varint)
// Address length (QUIC varint)
// Address (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func ReadTCPRequest(r io.Reader) (string, error) {
	bReader := quicvarint.NewReader(r)
	addrLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if addrLen == 0 || addrLen > MaxAddressLength {
		return "", errors.ProtocolError{Message: "invalid address length"}
	}
	addrBuf := make([]byte, addrLen)
	_, err = io.ReadFull(r, addrBuf)
	if err != nil {
		return "", err
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if paddingLen > MaxPaddingLength {
		return "", errors.ProtocolError{Message: "invalid padding length"}
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r, int64(paddingLen))
		if err != nil {
			return "", err
		}
	}
	return string(addrBuf), nil
}

func WriteTCPRequest(w io.Writer, addr string) error {
	padding := tcpRequestPadding.String()
	paddingLen := len(padding)
	addrLen := len(addr)
	sz := int(quicvarint.Len(FrameTypeTCPRequest)) +
		int(quicvarint.Len(uint64(addrLen))) + addrLen +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buf := make([]byte, sz)
	i := varintPut(buf, FrameTypeTCPRequest)
	i += varintPut(buf[i:], uint64(addrLen))
	i += copy(buf[i:], addr)
	i += varintPut(buf[i:], uint64(paddingLen))
	copy(buf[i:], padding)
	_, err := w.Write(buf)
	return err
}

// TCPResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (QUIC varint)
// Message (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func ReadTCPResponse(r io.Reader) (bool, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, "", err
	}
	bReader := quicvarint.NewReader(r)
	msgLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if msgLen > MaxMessageLength {
		return false, "", errors.ProtocolError{Message: "invalid message length"}
	}
	var msgBuf []byte
	// No message is fine
	if msgLen > 0 {
		msgBuf = make([]byte, msgLen)
		_, err = io.ReadFull(r, msgBuf)
		if err != nil {
			return false, "", err
		}
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if paddingLen > MaxPaddingLength {
		return false, "", errors.ProtocolError{Message: "invalid padding length"}
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r, int64(paddingLen))
		if err != nil {
			return false, "", err
		}
	}
	return status[0] == 0, string(msgBuf), nil
}

func WriteTCPResponse(w io.Writer, ok bool, msg string) error {
	padding := tcpResponsePadding.String()
	paddingLen := len(padding)
	msgLen := len(msg)
	sz := 1 + int(quicvarint.Len(uint64(msgLen))) + msgLen +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buf := make([]byte, sz)
	if ok {
		buf[0] = 0
	} else {
		buf[0] = 1
	}
	i := varintPut(buf[1:], uint64(msgLen))
	i += copy(buf[1+i:], msg)
	i += varintPut(buf[1+i:], uint64(paddingLen))
	copy(buf[1+i:], padding)
	_, err := w.Write(buf)
	return err
}

// UDPMessage format:
// Session ID (uint32 BE)
// Packet ID (uint16 BE)
// Fragment ID (uint8)
// Fragment count (uint8)
// Address length (QUIC varint)
// Address (bytes)
// Padding length (QUIC varint)
// Padding (random bytes)
// Data...

type UDPMessage struct {
	SessionID uint32 // 4
	PacketID  uint16 // 2
	FragID    uint8  // 1
	FragCount uint8  // 1
	Addr      string // varint + bytes
	Data      []byte
}

func (m *UDPMessage) HeaderSize() int {
	lAddr := len(m.Addr)
	// 4 (SessionID) + 2 (PacketID) + 1 (FragID) + 1 (FragCount) + varint(lAddr) + lAddr + 1 (min PadLen byte)
	return 8 + int(quicvarint.Len(uint64(lAddr))) + lAddr + 1
}

func (m *UDPMessage) Size() int {
	return m.HeaderSize() + len(m.Data)
}

func (m *UDPMessage) Serialize(buf []byte) int {
	hSize := m.HeaderSize()
	dataLen := len(m.Data)

	// Целевой лимит для пакета с паддингом. 
	// 1150 байт - безопасное значение, проходящее через большинство сетей.
	// Padding strategy: используем crypto/rand для длины и для байт паддинга
	// (аналогично FramedReadWriter и требованиям в docs/protocols/hysteria.md).
	const targetLimit = 1150

	padLen := uint64(0)
	if hSize+dataLen < targetLimit {
		maxPadding := targetLimit - (hSize + dataLen)
		if maxPadding > 255 {
			maxPadding = 255
		}
		if maxPadding > 0 {
			var rb [1]byte
			if _, err := rand.Read(rb[:]); err == nil {
				if maxPadding >= 255 {
					// 255 means we want full 0-255 range. rb[0] is already 0-255,
					// uint8(255+1) would underflow to 0 → %0 panic. Use value directly.
					padLen = uint64(rb[0])
				} else {
					padLen = uint64(rb[0] % uint8(maxPadding+1))
				}
			}
			// on rand failure: keep padLen=0 (safe, no padding)
		}
	}

	// Итоговый размер
	padVarintSize := int(quicvarint.Len(padLen))
	// (hSize - 1) - это размер заголовка БЕЗ учета байта PadLen
	totalSize := (hSize - 1) + padVarintSize + int(padLen) + dataLen

	if totalSize > len(buf) {
		return -1
	}

	binary.BigEndian.PutUint32(buf, m.SessionID)
	binary.BigEndian.PutUint16(buf[4:], m.PacketID)
	buf[6] = m.FragID
	buf[7] = m.FragCount
	i := 8 + varintPut(buf[8:], uint64(len(m.Addr)))
	i += copy(buf[i:], m.Addr)

	// Записываем PaddingLen
	i += varintPut(buf[i:], padLen)

	// Заполняем область Padding реальными случайными байтами через crypto/rand.
	// Раньше здесь было просто "i += int(padLen)" — в буфер попадали нули (от make)
	// или остатки от предыдущих пакетов при переиспользовании SendBuf/msgBuf.
	// Теперь padding — настоящий шум, как заявлено в документации Umbrella.
	if padLen > 0 {
		if _, err := rand.Read(buf[i : i+int(padLen)]); err != nil {
			// crypto/rand failure is extremely rare. Do not fail the send.
			// Padding area will contain zeros or stale data, but packet is still sent.
		}
	}
	i += int(padLen)

	// Записываем Data
	i += copy(buf[i:], m.Data)

	return i
}

func ParseUDPMessage(msg []byte) (*UDPMessage, error) {
	m := &UDPMessage{}
	buf := bytes.NewReader(msg)
	if err := binary.Read(buf, binary.BigEndian, &m.SessionID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &m.PacketID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &m.FragID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &m.FragCount); err != nil {
		return nil, err
	}
	lAddr, err := quicvarint.Read(buf)
	if err != nil {
		return nil, err
	}
	if lAddr > uint64(len(msg)) { // Базовая проверка на безумные значения
		return nil, errors.ProtocolError{Message: "invalid address length"}
	}

	addrBuf := make([]byte, lAddr)
	if _, err := io.ReadFull(buf, addrBuf); err != nil {
		return nil, err
	}
	m.Addr = string(addrBuf)

	// Пытаемся прочитать PaddingLen. 
	// Если данных больше нет, значит это старый формат или пакет без данных и паддинга.
	if buf.Len() == 0 {
		m.Data = []byte{}
		return m, nil
	}

	padLen, err := quicvarint.Read(buf)
	if err != nil {
		// Если не удалось прочитать varint, но байты были, возможно это старый формат 
		// где сразу шли данные. Но в нашем новом протоколе это ошибка.
		// Для обратной совместимости можно было бы вернуть оставшееся как Data,
		// но мы контролируем обе стороны.
		return nil, err
	}

	// Пропускаем Padding
	if padLen > 0 {
		if uint64(buf.Len()) < padLen {
			return nil, errors.ProtocolError{Message: "padding length exceeds buffer"}
		}
		if _, err := io.CopyN(io.Discard, buf, int64(padLen)); err != nil {
			return nil, err
		}
	}

	// Всё остальное - это Data
	remaining := buf.Len()
	if remaining > 0 {
		m.Data = make([]byte, remaining)
		if _, err := io.ReadFull(buf, m.Data); err != nil {
			return nil, err
		}
	} else {
		m.Data = []byte{}
	}

	return m, nil
}

// varintPut is like quicvarint.Append, but instead of appending to a slice,
// it writes to a fixed-size buffer. Returns the number of bytes written.
func varintPut(b []byte, i uint64) int {
	if i <= maxVarInt1 {
		b[0] = uint8(i)
		return 1
	}
	if i <= maxVarInt2 {
		b[0] = uint8(i>>8) | 0x40
		b[1] = uint8(i)
		return 2
	}
	if i <= maxVarInt4 {
		b[0] = uint8(i>>24) | 0x80
		b[1] = uint8(i >> 16)
		b[2] = uint8(i >> 8)
		b[3] = uint8(i)
		return 4
	}
	if i <= maxVarInt8 {
		b[0] = uint8(i>>56) | 0xc0
		b[1] = uint8(i >> 48)
		b[2] = uint8(i >> 40)
		b[3] = uint8(i >> 32)
		b[4] = uint8(i >> 24)
		b[5] = uint8(i >> 16)
		b[6] = uint8(i >> 8)
		b[7] = uint8(i)
		return 8
	}
	panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
}
