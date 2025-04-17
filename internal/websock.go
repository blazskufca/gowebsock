package internal

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	websocketGUID                  string = `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`
	switchingProtocolsResponseLine string = "HTTP/1.1 101 Switching Protocols\r\n"
)

type WebSocket struct {
	Conn   net.Conn
	buff   *bufio.ReadWriter
	header http.Header
	status WebSocketStatusCode
}

func NewWebSocketWithUpgrade(w http.ResponseWriter, r *http.Request) (*WebSocket, error) {
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	if err := rc.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	conn, buf, err := rc.Hijack()
	if err != nil {
		return nil, err
	}
	ws := &WebSocket{
		Conn:   conn,
		buff:   buf,
		header: r.Header,
	}
	return ws, ws.Handshake(r)
}

func (ws *WebSocket) Handshake(r *http.Request) error {
	upgrade := strings.ToLower(strings.TrimSpace(r.Header.Get("Upgrade")))
	connection := strings.ToLower(strings.TrimSpace(r.Header.Get("Connection")))
	wsKey := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	wsVersion := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Version"))

	upgradeOK := upgrade == "websocket"
	connectionOK := strings.Contains(connection, "upgrade")
	keyOK := wsKey != ""
	versionOK := wsVersion == "13"

	if !(upgradeOK && connectionOK && keyOK && versionOK) {
		return errors.New("not a WebSocket UpgradeRequest")
	}

	var wsk string

	if wsk = strings.TrimSpace(ws.header.Get("Sec-WebSocket-Key")); wsk == "" {
		return errors.New("no Sec-WebSocket-Key")
	}

	extensions := ws.header.Get("Sec-WebSocket-Extensions")
	if extensions != "" {
		fmt.Printf("Client requested extensions: %s, but none are supported\n", extensions)
	}

	sha1Hash := sha1.New()
	sha1Hash.Write([]byte(wsk))
	sha1Hash.Write([]byte(websocketGUID))
	_, err := ws.buff.WriteString(switchingProtocolsResponseLine)
	if err != nil {
		return err
	}
	respHeader := http.Header{
		"Sec-WebSocket-Accept":  []string{base64.StdEncoding.EncodeToString(sha1Hash.Sum(nil))},
		"Upgrade":               []string{"websocket"},
		"Connection":            []string{"Upgrade"},
		"Sec-WebSocket-Version": []string{"13"},
		"Server":                []string{"GoWebSock"},
	}
	err = respHeader.Write(ws.buff)
	if err != nil {
		return err
	}
	_, err = ws.buff.WriteString("\r\n")
	if err != nil {
		return err
	}
	return ws.buff.Flush()
}

// WriteFramesFragmented encodes and writes a sequence of frames to a writer
func (ws *WebSocket) WriteFrames(frames []*Frame) error {
	for _, frame := range frames {
		encoded := frame.EncodeFrame()
		if _, err := ws.buff.Write(encoded); err != nil {
			return err
		}
	}
	err := ws.buff.Flush()
	if err != nil {
		return err
	}
	return nil
}

// WriteTextMessage is a convenience method to send a text message
func (ws *WebSocket) WriteTextMessage(message string) error {
	frame, err := TextFrame(message, true)
	if err != nil {
		return err
	}
	return ws.WriteFrames([]*Frame{frame})
}

// WriteBinaryMessage is a convenience method to send a binary message
func (ws *WebSocket) WriteBinaryMessage(data []byte) error {
	frame, err := BinaryFrame(data, true)
	if err != nil {
		return err
	}
	return ws.WriteFrames([]*Frame{frame})
}

// WriteFragmentedMessage breaks a large message into multiple frames
func (ws *WebSocket) WriteFragmentedMessage(data []byte, maxFrameSize int, opcode Opcode) error {
	frames, err := FragmentedFrames(data, maxFrameSize, opcode, true)
	if err != nil {
		return err
	}
	return ws.WriteFrames(frames)
}

// WriteCloseMessage sends a close frame with the specified status code and reason
func (ws *WebSocket) WriteCloseMessage(code WebSocketStatusCode, reason string) error {
	frame, err := NewCloseFrame(code, reason, true)
	if err != nil {
		return err
	}
	return ws.WriteFrames([]*Frame{frame})
}

// WritePingMessage sends a ping frame with the specified application data
func (ws *WebSocket) WritePingMessage(applicationData string) error {
	frame, err := NewPingFrame(applicationData, false)
	if err != nil {
		return err
	}
	return ws.WriteFrames([]*Frame{frame})
}

// WritePongMessage sends a pong frame in response to a ping
func (ws *WebSocket) WritePongMessage(pingFrame *Frame) error {
	if pingFrame == nil {
		return errors.New("ping frame is nil")
	}
	pongFrame, err := NewServerFrame(true, OpPong, pingFrame.PayloadData)
	if err != nil {
		return err
	}

	return ws.WriteFrames([]*Frame{pongFrame})
}

// ReadFrame reads a single WebSocket frame from the connection
func (ws *WebSocket) ReadFrame() (*Frame, error) {
	return DecodeFrame(ws.buff)
}

// ValidateClientFrame validates that a frame from a client follows the WebSocket protocol
func (ws *WebSocket) ValidateClientFrame(fr *Frame) error {
	if fr == nil {
		return errors.New("frame is nil")
	}

	if !fr.Masked {
		ws.status = ProtocolError
		return errors.New("protocol error: unmasked client frame")
	}

	if fr.IsControl() && (fr.PayloadLength > payloadLen125OrLess || !fr.Fin) {
		ws.status = ProtocolError
		return errors.New("protocol error: all control frames MUST have a payload length of 125 bytes or less and MUST NOT be fragmented")
	}

	if fr.OpCode > OpPong || (fr.OpCode > OpBinary && fr.OpCode < OpClose) {
		ws.status = ProtocolError
		log.Printf("Detected invalid opcode: %x", fr.OpCode)
		return fmt.Errorf("protocol error: opcode %x is reserved or invalid", fr.OpCode)
	}

	if fr.Rsv1 || fr.Rsv2 || fr.Rsv3 {
		ws.status = ProtocolError
		return errors.New("protocol error: RSV bits must be 0")
	}

	if fr.OpCode == OpClose {
		if fr.PayloadLength >= 2 {
			code := binary.BigEndian.Uint16(fr.PayloadData[:2])
			if code < 1000 || (code >= 1004 && code <= 1006) || (code >= 1012 && code <= 2999) {
				ws.status = ProtocolError
				return fmt.Errorf("protocol error: invalid close code %d", code)
			}
			if fr.PayloadLength > 2 && !utf8.Valid(fr.PayloadData[2:]) {
				ws.status = GotInconsistentData
				return errors.New("invalid UTF-8 in close reason")
			}
		} else if fr.PayloadLength == 1 {
			ws.status = ProtocolError
			return errors.New("protocol error: close payload length must be 0 or at least 2")
		}
	}

	return nil
}

// Close closes the WebSocket connection gracefully
func (ws *WebSocket) Close() error {
	// Send close frame with the current status
	closeFrame, _ := NewCloseFrame(ws.status, "", true)
	_ = ws.WriteFrames([]*Frame{closeFrame})

	return ws.Conn.Close()
}

// CloseWithCode closes the WebSocket connection with a specific status code and reason
func (ws *WebSocket) CloseWithCode(statusCode WebSocketStatusCode, reason string) error {
	ws.status = statusCode
	closeFrame, _ := NewCloseFrame(statusCode, reason, true)
	_ = ws.WriteFrames([]*Frame{closeFrame})

	return ws.Conn.Close()
}

// Read implements io.Reader for direct reading
func (ws *WebSocket) Read(p []byte) (int, error) {
	return ws.Conn.Read(p)
}

// Write implements io.Writer for direct writing
func (ws *WebSocket) Write(p []byte) (int, error) {
	n, err := ws.buff.Write(p)
	if err != nil {
		return n, err
	}
	err = ws.buff.Flush()
	return n, err
}

// ReadMessage is a high-level method that reads a message from the connection
// It handles control frames internally and returns application data frames
func (ws *WebSocket) ReadMessage() (messageType Opcode, data []byte, err error) {
	var payload []byte
	var firstOpCode Opcode
	var inFragmentedMessage bool

	for {
		frame, err := ws.ReadFrame()
		if err != nil {
			return 0, nil, err
		}
		if err := ws.ValidateClientFrame(frame); err != nil {
			return 0, nil, err
		}

		if frame.IsControl() {
			switch frame.OpCode {
			case OpClose:
				code, reason, _ := frame.ReadCloseFrame()
				if code == 0 {
					code = NormalClosure
				}
				closeErr := ws.WriteCloseMessage(code, reason)
				if closeErr != nil {
					return 0, nil, closeErr
				}
				return OpClose, nil, nil
			case OpPing:
				pongErr := ws.WritePongMessage(frame)
				if pongErr != nil {
					return 0, nil, pongErr
				}
				continue
			case OpPong:
				continue
			}
		}

		if frame.OpCode == OpContinuation {
			if !inFragmentedMessage {
				return 0, nil, fmt.Errorf("protocol error: continuation frame without preceding data frame")
			}
			payload = append(payload, frame.PayloadData...)
		} else {
			if inFragmentedMessage {
				return 0, nil, fmt.Errorf("protocol error: new data frame received while in fragmented message")
			}
			if frame.OpCode != OpText && frame.OpCode != OpBinary {
				return 0, nil, fmt.Errorf("protocol error: invalid data frame opcode %v", frame.OpCode)
			}
			firstOpCode = frame.OpCode
			payload = frame.PayloadData
			inFragmentedMessage = !frame.Fin
		}

		if frame.Fin {
			if firstOpCode == 0 {
				return 0, nil, fmt.Errorf("protocol error: no initial data frame for continuation")
			}
			if firstOpCode == OpText && !utf8.Valid(payload) {
				return 0, nil, fmt.Errorf("protocol error: invalid UTF-8 in complete text message")
			}
			return firstOpCode, payload, nil
		}
	}
}

// ReadTextMessage reads a complete text message (possibly across multiple frames)
// It returns an error if the message contains invalid UTF-8
func (ws *WebSocket) ReadTextMessage() (string, error) {
	messageType, data, err := ws.ReadMessage()
	if err != nil {
		return "", err
	}

	if messageType != OpText {
		return "", errors.New("received a non-text message")
	}

	if !utf8.Valid(data) {
		return "", errors.New("received text message contains invalid UTF-8")
	}

	return string(data), nil
}

// ReadBinaryMessage reads a complete binary message (possibly across multiple frames)
func (ws *WebSocket) ReadBinaryMessage() ([]byte, error) {
	messageType, data, err := ws.ReadMessage()
	if err != nil {
		return nil, err
	}

	if messageType != OpBinary {
		return nil, errors.New("received a non-binary message")
	}

	return data, nil
}
