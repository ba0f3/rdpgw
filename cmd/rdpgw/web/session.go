package web

import (
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/gorilla/sessions"
	"log"
	"net/http"
	"os"
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

		sessionStore = fs
	} else {
		log.Println("Cookies are used as session storage")
		sessionStore = sessions.NewCookieStore(sessionKey, encryptionKey)
	}
}

func GetSession(r *http.Request) (*sessions.Session, error) {
	session, err := sessionStore.Get(r, rdpGwSession)
	if err != nil {
		return nil, err
	}
	return session, nil
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
	id.Unmarshal(idData.([]byte))
	return id, nil
}

func SaveSessionIdentity(r *http.Request, w http.ResponseWriter, id identity.Identity) error {
	session, err := GetSession(r)
	if err != nil {
		return err
	}
	session.Options.MaxAge = MaxAge

	idData, err := id.Marshal()
	if err != nil {
		return err
	}
	session.Values[identityKey] = idData

	return sessionStore.Save(r, w, session)

}
