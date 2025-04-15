package internal

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

const (
	websocketGUID                  string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	switchingProtocolsResponseLine string = "HTTP/1.1 101 Switching Protocols\r\n"
)

type WebSocket struct {
	Conn   net.Conn
	buff   *bufio.ReadWriter
	header http.Header
	status uint16
}

func NewWebSocketWithUpgrade(w http.ResponseWriter, r *http.Request) (*WebSocket, error) {
	rc := http.NewResponseController(w)
	conn, buf, err := rc.Hijack()
	if err != nil {
		return nil, err
	}
	ws := &WebSocket{
		Conn:   conn,
		buff:   buf,
		header: r.Header,
	}
	return ws, ws.Handshake(w, r)
}

func (ws *WebSocket) Handshake(w http.ResponseWriter, r *http.Request) error {
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
