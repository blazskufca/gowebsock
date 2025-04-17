package main

import (
	"fmt"
	"github.com/blazskufca/gowebsock/internal"
	"log"
	"net/http"
)

// WebSocketHandler handles WebSocket connections and implements echo functionality
func WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request headers:", r.Header)

	ws, err := internal.NewWebSocketWithUpgrade(w, r)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return
	}

	for {
		t, frame, err := ws.ReadMessage()
		if err != nil {
			_ = ws.WriteCloseMessage(internal.ProtocolError, err.Error())
			return
		}

		switch t {
		case internal.OpText:
			log.Println("Received op text")
			err = ws.WriteTextMessage(string(frame))
			if err != nil {
				_ = ws.WriteCloseMessage(internal.ProtocolError, err.Error())
				return
			}
		case internal.OpBinary:
			log.Println("Received op binary")
			fmt.Println(frame)
			err = ws.WriteBinaryMessage(frame)
			if err != nil {
				_ = ws.WriteCloseMessage(internal.ProtocolError, err.Error())
				return
			}
		case internal.OpClose:
			_ = ws.CloseWithCode(internal.NormalClosure, "Connection closed")
			log.Println("Received op close")
			return
		}

	}

}

func main() {
	http.HandleFunc("/echo", WebSocketHandler)
	port := 8080
	fmt.Printf("WebSocket Echo Server started on port %d\n", port)
	fmt.Printf("WebSocket endpoint: ws://localhost:%d/echo\n", port)

	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
