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

	log.Printf("New WebSocket connection established")
	err = ws.WriteTextMessage("Welcome to the WebSocket echo server!")
	if err != nil {
		http.Error(w, "WebSocket write failed", http.StatusBadRequest)
	}
	log.Println("Sent welcome message to client")

	for {
		log.Println("Waiting for frame from client...")

		t, frame, err := ws.ReadMessage()
		if err != nil {
			log.Printf("Error reading message: %v", err)
		}
		log.Println("Received frame from client...")
		switch t {
		case internal.OpText:
			log.Println("Received op text")
			fmt.Println(string(frame))
			err = ws.WriteTextMessage(string(frame))
			if err != nil {
				log.Printf("Error writing text: %v", err)
				continue
			}
		case internal.OpBinary:
			log.Println("Received op binary")
			fmt.Println(frame)
			err = ws.WriteBinaryMessage(frame)
			if err != nil {
				log.Printf("Error writing text: %v", err)
				continue
			}
		case internal.OpClose:
			log.Println("Received op close")
			return
		}

	}
}

func main() {
	http.HandleFunc("/echo", WebSocketHandler)

	// Also serve a simple HTML page for easy testing
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(testClientHTML))
	})

	port := 8080
	fmt.Printf("WebSocket Echo Server started on port %d\n", port)
	fmt.Printf("For testing, visit http://localhost:%d\n", port)
	fmt.Printf("WebSocket endpoint: ws://localhost:%d/echo\n", port)

	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// Simple HTML page for testing the WebSocket server
const testClientHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>WebSocket Echo Test</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        #output { width: 100%; height: 300px; overflow-y: scroll; border: 1px solid #ccc; margin-bottom: 10px; padding: 10px; }
        #input { width: 80%; padding: 8px; }
        button { padding: 8px 15px; }
        .log { margin: 5px 0; }
        .received { color: blue; }
        .sent { color: green; }
        .system { color: gray; }
        .error { color: red; }
    </style>
</head>
<body>
    <h1>WebSocket Echo Test</h1>
    <div id="output"></div>
    <input id="input" type="text" placeholder="Type a message...">
    <button onclick="sendMessage()">Send</button>
    <button onclick="sendBinary()">Send Binary</button>
    <button onclick="sendPing()">Send Ping</button>
    <button onclick="closeConnection()">Close</button>

    <script>
        var ws;
        var connected = false;

        function init() {
            log("system", "Connecting to WebSocket server...");
            ws = new WebSocket("ws://" + window.location.hostname + ":8080/echo");
            
            ws.onopen = function(e) {
                log("system", "Connection established!");
                connected = true;
            };
            
            ws.onmessage = function(e) {
                log("received", "Received: " + e.data);
            };
            
            ws.onclose = function(e) {
                log("system", "Connection closed (code: " + e.code + ", reason: " + e.reason + ")");
                connected = false;
            };
            
            ws.onerror = function(e) {
                log("error", "Error: " + e.message);
            };
        }
        
        function sendMessage() {
            if (!connected) {
                log("error", "Not connected!");
                return;
            }
            var message = document.getElementById("input").value;
            ws.send(message);
            log("sent", "Sent: " + message);
            document.getElementById("input").value = "";
        }
        
        function sendBinary() {
            if (!connected) {
                log("error", "Not connected!");
                return;
            }
            // Create a simple binary message
            var buffer = new ArrayBuffer(4);
            var view = new Uint8Array(buffer);
            view[0] = 0xDE;
            view[1] = 0xAD;
            view[2] = 0xBE;
            view[3] = 0xEF;
            ws.send(buffer);
            log("sent", "Sent binary data: 0xDEADBEEF");
        }
        
        function sendPing() {
            if (!connected) {
                log("error", "Not connected!");
                return;
            }
            // Note: The WebSocket API doesn't directly expose ping/pong,
            // but this would trigger it in our server for testing
            log("system", "Browser WebSocket API doesn't support direct ping control");
        }
        
        function closeConnection() {
            if (!connected) {
                log("error", "Not connected!");
                return;
            }
            ws.close(1000, "Client closing connection");
            log("system", "Closing connection...");
        }
        
        function log(type, message) {
            var output = document.getElementById("output");
            var entry = document.createElement("div");
            entry.className = "log " + type;
            entry.textContent = message;
            output.appendChild(entry);
            output.scrollTop = output.scrollHeight;
        }
        
        window.onload = init;
    </script>
</body>
</html>
`
