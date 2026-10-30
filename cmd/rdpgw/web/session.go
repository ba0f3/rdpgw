package web

import (
	"context"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	rdpGwSession     = "RDPGWSESSION"
	identityKey      = "RDPGWID"
	maxSessionLength = 8192
	// defaultSessionLifetime is the lifetime of a session in seconds when
	// the operator did not configure one.
	defaultSessionLifetime = 120
)

// MaxAge is the lifetime of the session in seconds. It is set from the
// configuration when the session store is initialized.
var MaxAge = defaultSessionLifetime

var sessionStore sessions.Store

type sessionRequestKey struct{}

// InitStore initializes the session store. The lifetime is the time the
// user has to download the .rdp file before the session expires. It is not
// the lifetime of the gateway credentials in the .rdp file, that one is
// controlled by security.paatokenlifetime.
func InitStore(sessionKey []byte, encryptionKey []byte, storeType string, maxLength int, lifetime int) {
	if len(sessionKey) < 32 {
		log.Fatal("Session key too small")
	}
	if len(encryptionKey) < 32 {
		log.Fatal("Session key too small")
	}

	if lifetime <= 0 {
		lifetime = defaultSessionLifetime
	}
	MaxAge = lifetime
	log.Printf("Setting session lifetime to %d seconds", MaxAge)

	if storeType == "file" {
		log.Println("Filesystem is used as session storage")
		fs := sessions.NewFilesystemStore(os.TempDir(), sessionKey, encryptionKey)

		// set max length
		if maxLength == 0 {
			maxLength = maxSessionLength
		}
		log.Printf("Setting maximum session storage to %d bytes", maxLength)
		fs.MaxLength(maxLength)
		fs.MaxAge(max(MaxAge, int(CacheExpiration.Seconds())))
		fs.Options.Secure = true
		fs.Options.HttpOnly = true
		fs.Options.SameSite = http.SameSiteLaxMode

		sessionStore = fs
	} else {
		log.Println("Cookies are used as session storage")
		cs := sessions.NewCookieStore(sessionKey, encryptionKey)
		cs.MaxAge(max(MaxAge, int(CacheExpiration.Seconds())))
		cs.Options.Secure = true
		cs.Options.HttpOnly = true
		cs.Options.SameSite = http.SameSiteLaxMode
		sessionStore = cs
	}
}

func GetSession(r *http.Request) (*sessions.Session, error) {
	if cached, ok := r.Context().Value(sessionRequestKey{}).(*sessions.Session); ok {
		return cached, nil
	}
	session, err := sessionStore.Get(r, rdpGwSession)
	if err != nil {
		// Invalid or expired cookies start a new anonymous session.
		session, err = sessionStore.New(&http.Request{Header: make(http.Header)}, rdpGwSession)
	}
	if err == nil {
		// Gorilla's registry retains a decoding error for the request. Keep
		// the recovered anonymous session so later state/PKCE writes use the
		// same session instead of creating another empty one on every call.
		*r = *r.WithContext(context.WithValue(r.Context(), sessionRequestKey{}, session))
	}
	return session, err
}

func GetSessionIdentity(r *http.Request) (identity.Identity, error) {
	s, err := GetSession(r)
	if err != nil {
		return nil, err
	}

	idData := s.Values[identityKey]
	if idData == nil {
		return nil, nil

	}
	id := identity.NewUser()
	data, ok := idData.([]byte)
	if !ok {
		return nil, nil
	}
	if err := id.Unmarshal(data); err != nil {
		return nil, nil
	}
	if id.Authenticated() && (id.AuthTime().IsZero() || time.Now().Add(time.Minute).Before(id.AuthTime()) ||
		!time.Now().Before(id.AuthTime().Add(time.Duration(MaxAge)*time.Second)) ||
		(!id.Expiry().IsZero() && !time.Now().Before(id.Expiry()))) {
		return nil, nil
	}
	return id, nil
}

func SaveSessionIdentity(r *http.Request, w http.ResponseWriter, id identity.Identity) error {
	session, err := GetSession(r)
	if err != nil {
		return err
	}
	session.Options.MaxAge = MaxAge
	session.Options.HttpOnly = true
	session.Options.Secure = true
	session.Options.SameSite = http.SameSiteLaxMode

	idData, err := id.Marshal()
	if err != nil {
		return err
	}
	session.Values[identityKey] = idData

	return sessionStore.Save(r, w, session)

}
