package protocol

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebSocketOnlyRejectsBothLegacyChannels(t *testing.T) {
	gw := &Gateway{WebSocketOnly: true}
	// These requests have no authenticated HTTP identity. Reject before
	// caching or hijacking either legacy channel.
	for _, method := range []string{MethodRDGOUT, MethodRDGIN} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/remoteDesktopGateway/", nil)
		gw.HandleGatewayProtocol(w, req)
		if w.Code != http.StatusUpgradeRequired || w.Header().Get("Upgrade") != "websocket" {
			t.Fatalf("%s: status=%d", method, w.Code)
		}
	}
}
