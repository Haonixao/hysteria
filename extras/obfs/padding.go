package obfs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// PaddingObfuscator добавляет случайный паддинг в конец каждого пакета.
// Формат пакета: [Payload][Random Padding][2 bytes: Padding Length (BigEndian)]
type PaddingObfuscator struct {
	MaxPadding int
}

func NewPaddingObfuscator(maxPadding int) (*PaddingObfuscator, error) {
	if maxPadding <= 0 {
		return nil, fmt.Errorf("max padding must be positive")
	}
	if maxPadding > 1024 {
		return nil, fmt.Errorf("max padding too large (max 1024)")
	}
	return &PaddingObfuscator{
		MaxPadding: maxPadding,
	}, nil
}

func (o *PaddingObfuscator) Obfuscate(in, out []byte) int {
	// Генерируем случайную длину паддинга [0, MaxPadding]
	var b [2]byte
	_, _ = rand.Read(b[:])
	padLen := int(binary.BigEndian.Uint16(b[:])) % (o.MaxPadding + 1)

	totalLen := len(in) + padLen + 2
	if len(out) < totalLen {
		return 0
	}

	// 1. Копируем полезную нагрузку
	copy(out, in)

	// 2. Генерируем случайный паддинг
	if padLen > 0 {
		_, _ = rand.Read(out[len(in) : len(in)+padLen])
	}

	// 3. Записываем длину паддинга в последние 2 байта
	binary.BigEndian.PutUint16(out[totalLen-2:], uint16(padLen))

	return totalLen
}

func (o *PaddingObfuscator) Deobfuscate(in, out []byte) int {
	if len(in) < 2 {
		return 0
	}

	// Читаем длину паддинга из последних 2 байт
	padLen := int(binary.BigEndian.Uint16(in[len(in)-2:]))
	
	payloadLen := len(in) - 2 - padLen
	if payloadLen < 0 || len(out) < payloadLen {
		return 0
	}

	// Копируем только полезную нагрузку
	copy(out, in[:payloadLen])
	return payloadLen
}
