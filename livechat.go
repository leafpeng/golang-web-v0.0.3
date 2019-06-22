package main

import (
	"bytes"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

const (

	// time allowed to write a message to the peer
	writeWait = 10 * time.Second
	// time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second
	// send pings to peer with this period. must be less than pongWait
	pingPeriod = (pongWait * 9) / 10
	// maximum message size allowed from peer
	maxMessageSize = 512
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {

		cookie, err := r.Cookie("session")
		if err != nil {
			return false
		}
		if _, ok := inMemorySessions[cookie.Value]; ok {
			return ok
		}
		return false

	},
}

// Client is a middleman between the websocket connection and the hub
type Client struct {
	hub *Hub

	conn *websocket.Conn

	send chan []byte
}

// Hub maintains the set of active clients and broadcasts message to the clients
type Hub struct {
	clients map[*Client]bool

	broadcast chan []byte

	register chan *Client

	unregister chan *Client
}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
	}
}

func (h *Hub) run() {

	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
		case message := <-h.broadcast:
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}

}

// serveWs handles websocket requests from the peer
func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {

	if !AlreadyLoggedIn(w, r) {
		http.Error(w, "Not Authorized.", http.StatusForbidden)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	client := &Client{
		hub:  hub,
		conn: conn,
		send: make(chan []byte, 256),
	}

	client.hub.register <- client
	// Allow collection of memory referenced by the caller by doing all work in new goroutines.
	go client.writePump()
	go client.readPump(r)

}

// readPump pumps messages from the websocket connection to the hub

// the application runs readPump in a per-connection goroutine. the application ensures that there is at most one reader on a connection by executing all reads from this goroutine
func (c *Client) readPump(r *http.Request) {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}
		// get []byte of username, then concat with webcoket message, all together send to the hub for broadcast.
		username := getUserName(r)
		messageReplace := bytes.Replace(message, newline, space, -1)
		concatMessage := append(username, messageReplace...)
		message = bytes.TrimSpace(concatMessage)
		c.hub.broadcast <- message
	}
}

// writePump pumps message from the hub to the websocket connection.

// A goroutine running writePump is started for connection. The application ensures that there is at most one writer to a connection by executing all writes from this goroutine.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)
			// Add queued chat messages to the current websocket message.
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write(newline)
				w.Write(<-c.send)
			}
			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
