package internal

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

type Opcode byte

// WebSocket OpCodes
const (
	OpContinuation Opcode = 0x0
	OpText         Opcode = 0x1
	OpBinary       Opcode = 0x2
	OpClose        Opcode = 0x8
	OpPing         Opcode = 0x9
	OpPong         Opcode = 0xA
)

const (
	PayloadLen16BitCode byte   = 126
	PayloadLen64BitCode byte   = 127
	minimalHeaderSize   int    = 2
	firsHeaderByte      byte   = 0
	secondHeaderByte    byte   = 1
	maskFIN             byte   = 0b10000000
	maskRSV1            byte   = 0b01000000
	maskRSV2            byte   = 0b00100000
	maskRSV3            byte   = 0b00010000
	maskOPCODE          byte   = 0b00001111
	maskPayloadMasked   byte   = maskFIN
	payloadLen125OrLess uint64 = 125
	uint16byteSize      int    = 2
	uint64ByteSize      int    = 8
	maskKeySize         int    = 4
)

// Frame represents a WebSocket protocol frame as defined in RFC 6455
type Frame struct {
	Fin           bool
	Rsv1          bool
	Rsv2          bool
	Rsv3          bool
	OpCode        Opcode
	Masked        bool
	PayloadLength uint64
	MaskingKey    [4]byte
	PayloadData   []byte
}

// NewFrame creates a new WebSocket frame with the specified parameters
func NewFrame(fin bool, opcode Opcode, payload []byte, mask bool) (*Frame, error) {
	frame := &Frame{
		Fin:           fin,
		OpCode:        opcode,
		PayloadLength: uint64(len(payload)),
		PayloadData:   payload,
		Masked:        mask,
	}

	if mask {
		n, err := rand.Read(frame.MaskingKey[:])
		if err != nil {
			return nil, err
		}
		if n != len(frame.MaskingKey) {
			return nil, errors.New("masking key too short")
		}
		frame.MaskPayload()
	}

	return frame, nil
}

// NewServerFrame creates a frame that's suitable for server-to-client communication (unmasked)
func NewServerFrame(fin bool, opcode Opcode, payload []byte) (*Frame, error) {
	// Server-to-client frames MUST NOT be masked per RFC 6455
	return NewFrame(fin, opcode, payload, false)
}

// NewClientFrame creates a frame that's suitable for client-to-server communication (masked)
func NewClientFrame(fin bool, opcode Opcode, payload []byte) (*Frame, error) {
	// Client-to-server frames MUST be masked per RFC 6455
	return NewFrame(fin, opcode, payload, true)
}

// MaskPayload applies masking to the payload data
func (f *Frame) MaskPayload() {
	if !f.Masked || len(f.PayloadData) == 0 {
		return
	}

	for i := 0; i < len(f.PayloadData); i++ {
		f.PayloadData[i] ^= f.MaskingKey[i%4]
	}
}

// UnmaskPayload removes masking from the payload data
func (f *Frame) UnmaskPayload() {
	f.MaskPayload()
}

// EncodeFrame serializes a frame to its wire format
func (f *Frame) EncodeFrame() []byte {
	headerSize := minimalHeaderSize

	if f.PayloadLength <= payloadLen125OrLess {
	} else if f.PayloadLength <= math.MaxUint16 {
		headerSize += uint16byteSize
	} else {
		headerSize += uint64ByteSize
	}

	if f.Masked {
		headerSize += maskKeySize
	}

	buf := make([]byte, headerSize+len(f.PayloadData))

	buf[firsHeaderByte] = byte(f.OpCode) & maskOPCODE
	if f.Fin {
		buf[firsHeaderByte] |= maskFIN
	}
	if f.Rsv1 {
		buf[firsHeaderByte] |= maskRSV1
	}
	if f.Rsv2 {
		buf[firsHeaderByte] |= maskRSV2
	}
	if f.Rsv3 {
		buf[firsHeaderByte] |= maskRSV3
	}

	if f.Masked {
		buf[secondHeaderByte] |= maskPayloadMasked
	}

	if f.PayloadLength <= payloadLen125OrLess {
		buf[secondHeaderByte] |= byte(f.PayloadLength)
	} else if f.PayloadLength <= math.MaxUint16 {
		buf[secondHeaderByte] |= PayloadLen16BitCode
		binary.BigEndian.PutUint16(buf[2:4], uint16(f.PayloadLength))
	} else {
		buf[secondHeaderByte] |= PayloadLen64BitCode
		binary.BigEndian.PutUint64(buf[2:10], f.PayloadLength)
	}

	if f.Masked {
		maskPos := 2
		if f.PayloadLength <= payloadLen125OrLess {
			maskPos = 2
		} else if f.PayloadLength <= math.MaxUint16 {
			maskPos = 4
		} else {
			maskPos = 10
		}

		copy(buf[maskPos:maskPos+4], f.MaskingKey[:])
	}
	payloadPos := headerSize
	copy(buf[payloadPos:], f.PayloadData)

	return buf
}

// DecodeFrame deserializes a frame from its wire format
func DecodeFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, minimalHeaderSize)

	if n, err := r.Read(header); err != nil || n != minimalHeaderSize {
		switch err {
		case nil:
			return nil, fmt.Errorf("invalid header size %v expected %v", n, minimalHeaderSize)
		default:
			return nil, err
		}
	}

	frame := &Frame{}

	frame.Fin = (header[firsHeaderByte] & maskFIN) != 0
	frame.Rsv1 = (header[firsHeaderByte] & maskRSV1) != 0
	frame.Rsv2 = (header[firsHeaderByte] & maskRSV2) != 0
	frame.Rsv3 = (header[firsHeaderByte] & maskRSV3) != 0
	frame.OpCode = Opcode(header[firsHeaderByte] & maskOPCODE)

	frame.Masked = (header[secondHeaderByte] & maskPayloadMasked) != 0
	payloadLenIndicator := header[secondHeaderByte] & 0b01111111

	switch {
	case payloadLenIndicator <= byte(payloadLen125OrLess):
		frame.PayloadLength = uint64(payloadLenIndicator)
	case payloadLenIndicator == PayloadLen16BitCode:
		extendedLen := make([]byte, uint16byteSize)
		if _, err := io.ReadFull(r, extendedLen); err != nil {
			return nil, err
		}
		frame.PayloadLength = uint64(binary.BigEndian.Uint16(extendedLen))
	case payloadLenIndicator == PayloadLen64BitCode:
		extendedLen := make([]byte, uint64ByteSize)
		if _, err := io.ReadFull(r, extendedLen); err != nil {
			return nil, err
		}
		frame.PayloadLength = binary.BigEndian.Uint64(extendedLen)
		if frame.PayloadLength&(1<<63) != 0 {
			return nil, errors.New("most significant bit of 64-bit length must be 0")
		}
	}

	if frame.Masked {
		maskingKey := make([]byte, maskKeySize)
		if _, err := io.ReadFull(r, maskingKey); err != nil {
			return nil, err
		}
		copy(frame.MaskingKey[:], maskingKey)
	}

	if frame.PayloadLength > 0 {
		frame.PayloadData = make([]byte, frame.PayloadLength)
		if _, err := io.ReadFull(r, frame.PayloadData); err != nil {
			return nil, err
		}

		if frame.Masked {
			frame.UnmaskPayload()
		}
	}

	return frame, nil
}

// IsControl returns true if the frame is a control frame
func (f *Frame) IsControl() bool {
	return f.OpCode >= 0x8
}

// IsData returns true if the frame is a data frame (text or binary)
func (f *Frame) IsData() bool {
	return f.OpCode == OpText || f.OpCode == OpBinary || f.OpCode == OpContinuation
}
