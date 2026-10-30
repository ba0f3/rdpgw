package transport

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebSocketRejectsOversizedMessages(t *testing.T) {
	result := make(chan error, 1)
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		transport, err := NewWS(conn)
		if err != nil {
			result <- err
			return
		}
		_, _, err = transport.ReadPacket()
		result <- err
	}))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	// The server may close before the writer finishes; both outcomes are valid.
	_ = conn.WriteMessage(websocket.BinaryMessage, bytes.Repeat([]byte("a"), (1<<20)+1))
	select {
	case err := <-result:
		if err != websocket.ErrReadLimit {
			t.Fatalf("expected read limit, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("oversized input did not terminate")
	}
}
