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
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}
	if err := rc.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	conn, buf, err := rc.Hijack()
	if err != nil {
		return nil, err
	}
	if err = conn.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}
	if err = conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ws := &WebSocket{
		Conn:   conn,
		buff:   buf,
		header: r.Header,
		status: NormalClosure,
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

	extensions := ws.header.Get("Sec-WebSocket-Extensions")
	if extensions != "" {
		log.Printf("Client requested extensions: %s, but none are supported", extensions)
	}

	sha1Hash := sha1.New()
	sha1Hash.Write([]byte(wsKey))
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

// WriteFrames encodes and writes a sequence of frames
func (ws *WebSocket) WriteFrames(frames []*Frame) error {
	for _, frame := range frames {
		encoded, err := frame.MarshalBinary()
		if err != nil {
			return err
		}
		if _, err := ws.buff.Write(encoded); err != nil {
			return err
		}
	}
	return ws.buff.Flush()
}

// WriteTextMessage sends a text message
func (ws *WebSocket) WriteTextMessage(message string) error {
	frame, err := TextFrame(message, true)
	if err != nil {
		return err
	}
	return ws.WriteFrames([]*Frame{frame})
}

// WriteBinaryMessage sends a binary message
func (ws *WebSocket) WriteBinaryMessage(data []byte) error {
	frame, err := BinaryFrame(data, true)
	if err != nil {
		return err
	}
	return ws.WriteFrames([]*Frame{frame})
}

// WriteFragmentedMessage sends a fragmented message
func (ws *WebSocket) WriteFragmentedMessage(data []byte, maxFrameSize int, opcode Opcode) error {
	frames, err := FragmentedFrames(data, maxFrameSize, opcode, true)
	if err != nil {
		return err
	}
	return ws.WriteFrames(frames)
}

// WriteCloseMessage sends a close frame
func (ws *WebSocket) WriteCloseMessage(code WebSocketStatusCode, reason string) error {
	frame, err := NewCloseFrame(code, reason, true)
	if err != nil {
		return err
	}
	return ws.WriteFrames([]*Frame{frame})
}

// WritePingMessage sends a ping frame
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

// ReadFrame reads a single WebSocket frame
func (ws *WebSocket) ReadFrame() (*Frame, error) {
	return DecodeFrame(ws.buff)
}

// ValidateClientFrame validates a client frame per RFC 6455
func (ws *WebSocket) ValidateClientFrame(fr *Frame) error {
	if fr == nil {
		ws.status = ProtocolError
		return errors.New("frame is nil")
	}

	if !fr.Masked {
		ws.status = ProtocolError
		return errors.New("protocol error: unmasked client frame")
	}

	if fr.IsControl() && (fr.PayloadLength > payloadLen125OrLess || !fr.Fin) {
		ws.status = ProtocolError
		return errors.New("protocol error: control frames must have payload length <= 125 bytes and must not be fragmented")
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
				return errors.New("protocol error: invalid UTF-8 in close reason")
			}
		} else if fr.PayloadLength == 1 {
			ws.status = ProtocolError
			return errors.New("protocol error: close payload length must be 0 or at least 2")
		}
	}

	return nil
}

// Close closes the connection gracefully
func (ws *WebSocket) Close() error {
	err := ws.WriteCloseMessage(ws.status, "")
	if err != nil {
		_ = ws.Conn.Close()
		return err
	}
	return ws.Conn.Close()
}

// CloseWithCode closes the connection with a specific status code and reason
func (ws *WebSocket) CloseWithCode(statusCode WebSocketStatusCode, reason string) error {
	ws.status = statusCode
	err := ws.WriteCloseMessage(statusCode, reason)
	if err != nil {
		ws.Conn.Close()
		return err
	}
	return ws.Conn.Close()
}

// Read implements io.Reader
func (ws *WebSocket) Read(p []byte) (int, error) {
	return ws.Conn.Read(p)
}

// Write implements io.Writer
func (ws *WebSocket) Write(p []byte) (int, error) {
	n, err := ws.buff.Write(p)
	if err != nil {
		return n, err
	}
	err = ws.buff.Flush()
	return n, err
}

// ReadMessage reads a complete message, handling control frames and errors
func (ws *WebSocket) ReadMessage() (messageType Opcode, data []byte, err error) {
	defer ws.buff.Flush()
	var payload []byte
	var firstOpCode Opcode
	var inFragmentedMessage bool

	for {
		frame, err := ws.ReadFrame()
		if err != nil {
			ws.status = ProtocolError
			closeErr := ws.WriteCloseMessage(ProtocolError, "error reading frame")
			if closeErr != nil {
				_ = ws.Conn.Close()
				return 0, nil, closeErr
			}
			_ = ws.Conn.Close()
			return 0, nil, err
		}

		if err := ws.ValidateClientFrame(frame); err != nil {
			closeErr := ws.WriteCloseMessage(ws.status, err.Error())
			if closeErr != nil {
				_ = ws.Conn.Close()
				return 0, nil, closeErr
			}
			_ = ws.Conn.Close()
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
					_ = ws.Conn.Close()
					return 0, nil, closeErr
				}
				_ = ws.Conn.Close()
				return OpClose, nil, nil
			case OpPing:
				pongErr := ws.WritePongMessage(frame)
				if pongErr != nil {
					ws.status = ProtocolError
					closeErr := ws.WriteCloseMessage(ProtocolError, "error sending pong")
					if closeErr != nil {
						_ = ws.Conn.Close()
						return 0, nil, closeErr
					}
					_ = ws.Conn.Close()
					return 0, nil, pongErr
				}
				continue
			case OpPong:
				continue
			}
		}

		if frame.OpCode == OpContinuation {
			if !inFragmentedMessage {
				ws.status = ProtocolError
				closeErr := ws.WriteCloseMessage(ProtocolError, "continuation frame without preceding data frame")
				if closeErr != nil {
					_ = ws.Conn.Close()
					return 0, nil, closeErr
				}
				_ = ws.Conn.Close()
				return 0, nil, fmt.Errorf("protocol error: continuation frame without preceding data frame")
			}
			payload = append(payload, frame.PayloadData...)
		} else {
			if inFragmentedMessage {
				ws.status = ProtocolError
				closeErr := ws.WriteCloseMessage(ProtocolError, "new data frame received while in fragmented message")
				if closeErr != nil {
					_ = ws.Conn.Close()
					return 0, nil, closeErr
				}
				_ = ws.Conn.Close()
				return 0, nil, fmt.Errorf("protocol error: new data frame received while in fragmented message")
			}
			if frame.OpCode != OpText && frame.OpCode != OpBinary {
				ws.status = ProtocolError
				closeErr := ws.WriteCloseMessage(ProtocolError, fmt.Sprintf("invalid data frame opcode %v", frame.OpCode))
				if closeErr != nil {
					_ = ws.Conn.Close()
					return 0, nil, closeErr
				}
				_ = ws.Conn.Close()
				return 0, nil, fmt.Errorf("protocol error: invalid data frame opcode %v", frame.OpCode)
			}
			firstOpCode = frame.OpCode
			payload = frame.PayloadData
			inFragmentedMessage = !frame.Fin
		}

		if frame.Fin {
			if firstOpCode == 0 {
				ws.status = ProtocolError
				closeErr := ws.WriteCloseMessage(ProtocolError, "no initial data frame for continuation")
				if closeErr != nil {
					_ = ws.Conn.Close()
					return 0, nil, closeErr
				}
				_ = ws.Conn.Close()
				return 0, nil, fmt.Errorf("protocol error: no initial data frame for continuation")
			}
			if firstOpCode == OpText && !utf8.Valid(payload) {
				ws.status = GotInconsistentData
				closeErr := ws.WriteCloseMessage(GotInconsistentData, "invalid UTF-8 in text message")
				if closeErr != nil {
					_ = ws.Conn.Close()
					return 0, nil, closeErr
				}
				_ = ws.Conn.Close()
				return 0, nil, fmt.Errorf("protocol error: invalid UTF-8 in complete text message")
			}
			return firstOpCode, payload, nil
		}
	}
}

// ReadTextMessage reads a complete text message
func (ws *WebSocket) ReadTextMessage() (string, error) {
	messageType, data, err := ws.ReadMessage()
	if err != nil {
		return "", err
	}
	if messageType != OpText {
		return "", errors.New("received a non-text message")
	}
	return string(data), nil
}

// ReadBinaryMessage reads a complete binary message
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
