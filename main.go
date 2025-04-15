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
		return
	}

	log.Printf("New WebSocket connection established")

	welcomeMsg := []byte("Welcome to the WebSocket Echo Server!")
	welcomeFrame, _ := internal.NewServerFrame(true, internal.OpText, welcomeMsg)
	welcomeData := welcomeFrame.EncodeFrame()
	_, err = ws.Conn.Write(welcomeData)
	if err != nil {
		log.Printf("Error sending welcome message: %v", err)
	} else {
		log.Println("Sent welcome message to client")
	}

	for {
		log.Println("Waiting for frame from client...")

		frame, err := internal.DecodeFrame(ws.Conn)
		if err != nil {
			log.Printf("Error reading frame: %v", err)
			break
		}

		log.Printf("Received frame - OpCode: %v, Length: %d, Masked: %v",
			frame.OpCode, frame.PayloadLength, frame.Masked)

		if frame.OpCode == internal.OpClose {
			log.Println("Received close frame, closing connection")
			closeFrame, _ := internal.NewServerFrame(true, internal.OpClose, frame.PayloadData)
			closeFrameData := closeFrame.EncodeFrame()
			_, _ = ws.Conn.Write(closeFrameData)
			break
		}

		if frame.OpCode == internal.OpPing {
			log.Println("Received ping frame, sending pong")
			pongFrame, _ := internal.NewServerFrame(true, internal.OpPong, frame.PayloadData)
			pongFrameData := pongFrame.EncodeFrame()
			_, err = ws.Conn.Write(pongFrameData)
			if err != nil {
				log.Printf("Error sending pong: %v", err)
				break
			}
			continue
		}

		if frame.IsData() {
			if frame.OpCode == internal.OpText {
				log.Printf("Echoing text data: %s", string(frame.PayloadData))
			} else {
				log.Printf("Echoing %d bytes of binary data", len(frame.PayloadData))
			}

			responseFrame, _ := internal.NewServerFrame(true, frame.OpCode, frame.PayloadData)
			responseFrameData := responseFrame.EncodeFrame()

			_, err = ws.Conn.Write(responseFrameData)
			if err != nil {
				log.Printf("Error echoing data: %v", err)
				break
			} else {
				log.Println("Successfully sent echo response")
			}
		}
	}

	_ = ws.Conn.Close()
	log.Println("WebSocket connection closed")
}

func main() {
	http.HandleFunc("/echo", WebSocketHandler)

	port := 8080
	fmt.Printf("WebSocket Echo Server started on port %d\n", port)
	fmt.Printf("Connect to ws://localhost:%d/echo\n", port)

	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
