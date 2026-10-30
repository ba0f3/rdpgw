package security

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/credentials"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/gorilla/websocket"
)

func wireBody(values ...interface{}) []byte {
	var body bytes.Buffer
	for _, value := range values {
		if err := binary.Write(&body, binary.LittleEndian, value); err != nil {
			panic(err)
		}
	}
	return body.Bytes()
}

func wireExchange(t *testing.T, conn *websocket.Conn, kind uint16, body []byte, want uint16) []byte {
	t.Helper()
	packet := wireBody(kind, uint16(0), uint32(8+len(body)), body)
	if err := conn.WriteMessage(websocket.BinaryMessage, packet); err != nil {
		t.Fatal(err)
	}
	_, reply, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) < 8 || binary.LittleEndian.Uint16(reply) != want || int(binary.LittleEndian.Uint32(reply[4:])) != len(reply) {
		t.Fatalf("unexpected wire response %x", reply)
	}
	return reply[8:]
}

func TestPersistentCredentialAcrossActualWebSocketHandshake(t *testing.T) {
	oldManager, oldLifetime, oldIP, oldEngine := CredentialManager, PAATokenLifetime, VerifyClientIP, access.Current()
	t.Cleanup(func() {
		CredentialManager = oldManager
		PAATokenLifetime = oldLifetime
		VerifyClientIP = oldIP
		access.Init(oldEngine)
	})
	PAATokenLifetime = 43200
	VerifyClientIP = false
	access.Init(access.NewEngine(access.Policy{Drive: true}, []access.Rule{{Groups: []string{"limited"}, Redirect: access.Overrides{Drive: boolPointer(false)}}}))
	var group atomic.Value
	group.Store("staff")
	resolver := func(ctx context.Context, subject string) (identity.Identity, error) {
		id := identity.NewUser()
		id.SetUserName("alice")
		id.SetAttribute(identity.AttrSubject, subject)
		id.SetGroups([]string{group.Load().(string)})
		id.SetAuthenticated(true)
		return id, nil
	}
	path := filepath.Join(t.TempDir(), "credentials.db")
	store, err := credentials.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	CredentialManager = &CredentialService{Store: store, Resolve: resolver}
	id := identity.NewUser()
	id.SetUserName("alice")
	id.SetAuthenticated(true)
	id.SetAuthTime(time.Now())
	id.SetAttribute(identity.AttrSubject, "alice-id")
	if err := CredentialManager.Login(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	token, err := GeneratePAAToken(context.WithValue(context.Background(), identity.CTXKey, id), "alice", "desktop:3389")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = credentials.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	CredentialManager = &CredentialService{Store: store, Resolve: resolver}
	var dials atomic.Int32
	peers := make(chan net.Conn, 1)
	gw := &protocol.Gateway{TokenAuth: true, WebSocketOnly: true, CheckPAACookie: CheckPAACookie, CheckHost: CheckSession(func(context.Context, string) (bool, error) { return true, nil }), DialHost: func(ctx context.Context, host string) (net.Conn, error) {
		dials.Add(1)
		a, b := net.Pipe()
		peers <- b
		return a, nil
	}}
	done := make(chan struct{}, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { done <- struct{}{} }()
		// Gorilla's test dialer sends GET; native RDG uses RDG_OUT_DATA.
		r.Method = protocol.MethodRDGOUT
		user := identity.NewUser()
		user.SetAttribute(identity.AttrRemoteAddr, r.RemoteAddr)
		user.SetAttribute(identity.AttrClientIp, "127.0.0.1")
		gw.HandleGatewayProtocol(w, identity.AddToRequestCtx(user, r))
	}))
	defer srv.Close()
	waitDone := func() {
		t.Helper()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("gateway handler did not exit")
		}
	}
	connect := func() *websocket.Conn {
		conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		wireExchange(t, conn, protocol.PKT_TYPE_HANDSHAKE_REQUEST, wireBody(uint8(0), uint8(0), uint16(0), uint16(protocol.HTTP_EXTENDED_AUTH_PAA)), protocol.PKT_TYPE_HANDSHAKE_RESPONSE)
		return conn
	}
	tunnelAuth := func(conn *websocket.Conn) uint32 {
		cookie := protocol.EncodeUTF16(token)
		reply := wireExchange(t, conn, protocol.PKT_TYPE_TUNNEL_CREATE, wireBody(uint32(0), uint16(protocol.HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE), uint16(0), uint16(len(cookie)), cookie), protocol.PKT_TYPE_TUNNEL_RESPONSE)
		if binary.LittleEndian.Uint32(reply[2:]) != 0 {
			t.Fatalf("valid persisted bearer rejected: %x", reply)
		}
		reply = wireExchange(t, conn, protocol.PKT_TYPE_TUNNEL_AUTH, wireBody(uint16(0)), protocol.PKT_TYPE_TUNNEL_AUTH_RESPONSE)
		return binary.LittleEndian.Uint32(reply[8:])
	}
	channel := wireBody(uint8(1), uint8(0), uint16(3389), uint16(3), uint16(len(protocol.EncodeUTF16("desktop"))), protocol.EncodeUTF16("desktop"))
	conn := connect()
	flags := tunnelAuth(conn)
	if flags&protocol.HTTP_TUNNEL_REDIR_DISABLE_DRIVE != 0 {
		t.Fatal("initial wire flags unexpectedly disable drive")
	}
	group.Store("limited")
	reply := wireExchange(t, conn, protocol.PKT_TYPE_CHANNEL_CREATE, channel, protocol.PKT_TYPE_CHANNEL_RESPONSE)
	if binary.LittleEndian.Uint32(reply) == 0 || dials.Load() != 0 {
		t.Fatal("changed policy reached destination with stale advertised flags")
	}
	conn.Close()
	waitDone()
	conn = connect()
	flags = tunnelAuth(conn)
	if flags&protocol.HTTP_TUNNEL_REDIR_DISABLE_DRIVE == 0 {
		t.Fatal("new handshake did not advertise tightened drive policy")
	}
	reply = wireExchange(t, conn, protocol.PKT_TYPE_CHANNEL_CREATE, channel, protocol.PKT_TYPE_CHANNEL_RESPONSE)
	if binary.LittleEndian.Uint32(reply) != 0 || dials.Load() != 1 {
		t.Fatal("legitimate connection did not reach approved destination")
	}
	conn.Close()
	(<-peers).Close()
	waitDone()
	record, err := store.Lookup(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(record.ID, record.Subject); err != nil {
		t.Fatal(err)
	}
	conn = connect()
	cookie := protocol.EncodeUTF16(token)
	reply = wireExchange(t, conn, protocol.PKT_TYPE_TUNNEL_CREATE, wireBody(uint32(0), uint16(protocol.HTTP_TUNNEL_PACKET_FIELD_PAA_COOKIE), uint16(0), uint16(len(cookie)), cookie), protocol.PKT_TYPE_TUNNEL_RESPONSE)
	if binary.LittleEndian.Uint32(reply[2:]) == 0 {
		t.Fatal("revoked credential passed actual PAA handshake")
	}
	conn.Close()
	waitDone()
}
