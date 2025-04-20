package frames

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

// NewCloseFrame creates a new close control frame with the specified status code and reason
func NewCloseFrame(code WebSocketStatusCode, reason string, isServer bool) (*Frame, error) {
	if !utf8.ValidString(reason) {
		return nil, errors.New("close frame reason must be valid UTF-8")
	}

	const uint16ByteLen int = 2

	payloadLen := uint16ByteLen

	if reason != "" {
		payloadLen += len(reason)
	}

	payload := make([]byte, payloadLen)
	binary.BigEndian.PutUint16(payload, uint16(code))

	if reason != "" {
		if !utf8.ValidString(reason) {
			return nil, errors.New("invalid UTF-8 in close reason")
		}
		copy(payload[uint16ByteLen:], []byte(reason))
	}

	if isServer {
		return NewServerFrame(true, OpClose, payload)
	} else {
		return NewClientFrame(true, OpClose, payload)
	}
}

// NewPingFrame creates a new ping control frame with the specified application data
func NewPingFrame(applicationData string, isClient bool) (*Frame, error) {
	if !utf8.ValidString(applicationData) {
		return nil, errors.New("ping frame application data must be valid UTF-8")
	}

	if len(applicationData) > int(PayloadLen125OrLess) {
		return nil, errors.New("ping frame payload cannot exceed 125 bytes")
	}
	payload := []byte(applicationData)

	if isClient {
		return NewClientFrame(true, OpPing, payload)
	} else {
		return NewServerFrame(true, OpPing, payload)
	}
}

// CreatePongFrame creates a new pong frame in response to a ping frame
func (f *Frame) CreatePongFrame(isClient bool) (*Frame, error) {
	if f == nil {
		return nil, errors.New("ping frame is nil")
	}

	if f.OpCode != OpPing {
		return nil, errors.New("not a ping frame")
	}

	if isClient {
		return NewClientFrame(true, OpPong, f.PayloadData)
	} else {
		return NewServerFrame(true, OpPong, f.PayloadData)
	}
}

// ReadCloseFrame reads the status code and reason from a close frame
func (f *Frame) ReadCloseFrame() (WebSocketStatusCode, string, error) {
	const uint16ByteLen int = 2

	if f.OpCode != OpClose {
		return 0, "", errors.New("not a close frame")
	}

	if len(f.PayloadData) == 0 {
		return NoStatusCode1005, "", nil
	}

	if len(f.PayloadData) < uint16ByteLen {
		return 0, "", errors.New("invalid close frame: payload too small")
	}

	code := WebSocketStatusCode(binary.BigEndian.Uint16(f.PayloadData[:uint16ByteLen]))

	reason := ""
	if len(f.PayloadData) > uint16ByteLen {
		reasonBytes := f.PayloadData[uint16ByteLen:]
		if !utf8.Valid(reasonBytes) {
			return code, "", errors.New("close frame contains invalid UTF-8 in reason")
		}

		reason = string(reasonBytes)
	}

	return code, reason, nil
}

// ReadPingFrame reads the application data from a ping frame
func (f *Frame) ReadPingFrame() (string, error) {
	if f.OpCode != OpPing {
		return "", errors.New("not a ping frame")
	}

	if len(f.PayloadData) == 0 {
		return "", nil
	}

	if !utf8.Valid(f.PayloadData) {
		return "", errors.New("ping frame contains invalid UTF-8 in application data")
	}

	if len(f.PayloadData) > int(PayloadLen125OrLess) {
		return "", errors.New("ping frame payload exceeds maximum allowed length of 125 bytes")
	}

	return string(f.PayloadData), nil
}

// ReadPongFrame reads the application data from a pong frame
func (f *Frame) ReadPongFrame() (string, error) {
	if f == nil {
		return "", errors.New("pong frame is nil")
	}

	if f.OpCode != OpPong {
		return "", errors.New("not a pong frame")
	}

	if len(f.PayloadData) == 0 {
		return "", nil
	}

	if !utf8.Valid(f.PayloadData) {
		return "", errors.New("pong frame contains invalid UTF-8 in application data")
	}

	if len(f.PayloadData) > int(PayloadLen125OrLess) {
		return "", errors.New("pong frame payload exceeds maximum allowed length of 125 bytes")
	}

	return string(f.PayloadData), nil
}
