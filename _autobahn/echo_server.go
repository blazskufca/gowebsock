package main

import (
	"fmt"
	"github.com/blazskufca/gowebsock/frames"
	"github.com/blazskufca/gowebsock/websock"
	"log"
	"net/http"
)

// WebSocketHandler handles WebSocket connections and implements echo functionality
func WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request headers:", r.Header)

	ws, err := websock.NewWebSocketWithUpgrade(w, r)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return
	}

	for {
		t, frame, re := ws.ReadMessage()
		if re != nil {
			log.Printf("WebSocket read failed: %v", re)
			return
		}

		switch t {
		case frames.OpText:
			log.Println("Received op text")
			log.Println(frame)
			err = ws.WriteTextMessage(string(frame))
			if err != nil {
				log.Printf("WebSocket read failed: %v", err)
				return
			}
		case frames.OpBinary:
			log.Println("Received op binary")
			err = ws.WriteBinaryMessage(frame)
			if err != nil {
				log.Printf("WebSocket read failed: %v", err)
				return
			}
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
