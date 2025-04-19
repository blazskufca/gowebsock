package internal

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// Opcode is a 4 bit value which indicates the type of the frame.
type Opcode byte

// WebSocket OpCodes
const (
	// OpContinuation indicates that frame is a part of continuation frame in a fragmented message.
	OpContinuation Opcode = 0x0
	// OpText indicates that the Frame.PayloadData is a UTF-8 text data.
	OpText Opcode = 0x1
	// OpBinary indicates that the Frame.PayloadData is a binary payload.
	OpBinary Opcode = 0x2
	// OpClose indicates that the frame is a Close control frame.
	OpClose Opcode = 0x8
	// OpPing indicates that the frame is a Ping control frame.
	OpPing Opcode = 0x9
	// OpPong indicates that the frame in Pong control frame.
	OpPong Opcode = 0xA
)

const (
	// PayloadLen16BitCode indicates that the real payload length are the next 2 bytes
	PayloadLen16BitCode byte = 126
	// PayloadLen64BitCode indicates that the real payload length are the next 8 bytes
	PayloadLen64BitCode byte = 127
	// minimalHeaderSize is the minimal size for a valid websocket frame, which is 2 bytes. Frame might be bigger.
	minimalHeaderSize int = 2
	// firsHeaderByte is a index into a first byte of the websocket Frame.
	firsHeaderByte byte = 0
	// secondHeaderByte is a index into a second byte of the websocket Frame.
	secondHeaderByte byte = 1
	// maskFIN is a mask for operating with Frame.Fin bit.
	maskFIN byte = 0b10000000
	// maskRSV1 is a mask for operating with Frame.Rsv1.
	maskRSV1 byte = 0b01000000
	// maskRSV2 is a mask for operating with Frame.Rsv2.
	maskRSV2 byte = 0b00100000
	// maskRSV3 is a mask for operating with Frame.Rsv3.
	maskRSV3 byte = 0b00010000
	// maskOPCODE is a mask for operating with Frame.OpCode.
	maskOPCODE byte = 0b00001111
	// maskPayloadMasked is a mask for operating with Frame.Masked.
	maskPayloadMasked byte = maskFIN
	// payloadLen125OrLess is a constant which compares Frame.PayloadData length.
	payloadLen125OrLess uint64 = 125
	// uint16byteSize is a size of uint16 in bytes. 2 bytes or 16 bits.
	uint16byteSize int = 2
	// uint64ByteSize is a size of uint64 in bytes. 8 bytes or 64 bits.
	uint64ByteSize int = 8
	// maskKeySize is a size of a masking keys. 4 bytes.
	maskKeySize int = 4
)

// WebSocketStatusCode is a status code in a Close control frame.
type WebSocketStatusCode uint16

const (
	// NormalClosure indicates a normal closure meaning the purpose for which the connection was established has been fulfilled.
	NormalClosure WebSocketStatusCode = 1000
	// GoingAway indicates the endpoint is going away, such as server going down or browser having navigated away from a page
	GoingAway WebSocketStatusCode = 1001
	// ProtocolError indicates the endpoint is terminating connection due to protocol error
	ProtocolError WebSocketStatusCode = 1002
	// GotUnacceptableData indicates the endpoint is shutting down a connection because it got a type of data it can not accept
	// such as a TEXT endpoint getting binary data
	GotUnacceptableData WebSocketStatusCode = 1003
	// Reserved1004 is a reserved status code for further use
	Reserved1004 WebSocketStatusCode = 1004
	// NoStatusCode1005 is a reserved value and MUST NOT be set as a status code in a control frame by an endpoint.
	// It is designated for use in applications expecting a status code to indicate that the  connection was closed
	//abnormally, e.g., without sending or receiving a Close control frame.
	NoStatusCode1005 WebSocketStatusCode = 1005
	// NoStatusCode1006 is a reserved value and MUST NOT be set as a status code in a  Close control frame by an endpoint.
	//It is designated for use in applications expecting a status code to indicate that the connection was closed
	//abnormally, e.g., without sending or receiving a Close control frame.
	NoStatusCode1006 WebSocketStatusCode = 1006
	// GotInconsistentData indicates that endpoint is shutting down the connection because it got data which is not
	// consistent with the expected encoding, i.e. such as non UTF-8 data within a text message
	GotInconsistentData WebSocketStatusCode = 1007
	// ViolatesPolicy indicates that the endpoint is shutting down the connection because an endpoint got a message which
	// violates it's policy. This is a generic status code that can be returned when there is no other more suitable status code
	ViolatesPolicy WebSocketStatusCode = 1008
	// MessageTooBig indicates that the endpoint got a message which is too big for it to process
	MessageTooBig WebSocketStatusCode = 1009
	// FailedToNegotiateExtensions indicates that an endpoint (client) is terminating the connection because it has
	// expected the server to negotiate one or more extension, but the server didn't return them in the response message
	// of the WebSocket handshake.  The list of extensions that are needed SHOULD appear in the /reason/ part of the Close
	// frame. This WebSocketStatusCode is not used by the Server because it can and should fail the handshake instead.
	FailedToNegotiateExtensions WebSocketStatusCode = 1010
	// UnexpectedServerCondition indicates that a server is terminating the connection because it encountered an
	// unexpected condition that prevented it from fulfilling the request.
	UnexpectedServerCondition WebSocketStatusCode = 1011
	// Reserved1015 is a reserved value and MUST NOT be set as a status code in a Close control frame by an endpoint.
	// It is designated for use in applications expecting a status code to indicate that the connection was closed due
	// to a failure to perform a TLS handshake (e.g., the server certificate can't be verified).
	Reserved1015 WebSocketStatusCode = 1015
)

// Frame represents a WebSocket protocol frame as defined in RFC 6455
type Frame struct {
	Fin           bool    // Fin indicates that frame is Finish frame, last Frame in a message.
	Rsv1          bool    // Rsv1 is the first Websocket extension bit.
	Rsv2          bool    // Rsv2 is the second Websocket extension bit.
	Rsv3          bool    // Rsv3 is the third Websocket extension bit.
	OpCode        Opcode  // OpCode is Opcode 4 bit value which indicates the type of the Frame.
	Masked        bool    // Masked indicates the the Frame.PayloadData is masked with a Frame.MaskingKey.
	PayloadLength uint64  // PayloadLength is a variable (7 / 7+16 if PayloadLen16BitCode / 7+64 if PayloadLen64BitCode)
	MaskingKey    [4]byte // MaskingKey is a 4 byte value which Frame.PayloadData is masked if Frame.Masked bit is set.
	PayloadData   []byte  // PayloadData is a variable length byte slice. Websocket supports this to be OpText or OpBinary.
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
	return NewFrame(fin, opcode, payload, false)
}

// NewClientFrame creates a frame that's suitable for client-to-server communication (masked)
func NewClientFrame(fin bool, opcode Opcode, payload []byte) (*Frame, error) {
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

// MarshalBinary serializes a frame to its wire format. It fulfils encoding.BinaryMarshaler interface.
func (f *Frame) MarshalBinary() ([]byte, error) {
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

	return buf, nil
}

// DecodeFrame deserializes a frame from its wire format
func DecodeFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, minimalHeaderSize)

	if n, err := io.ReadFull(r, header); err != nil || n != minimalHeaderSize {
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
