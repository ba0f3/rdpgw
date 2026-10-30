package web

import (
	"log"
	"net/http"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

// deniedByPolicy reports whether the access policy refuses the user. A
// denied user cannot log in and cannot use the gateway.
func deniedByPolicy(id identity.Identity) bool {
	if id == nil {
		return false
	}

	return access.Current().Denied(id)
}

// refuseDeniedUser refuses the request when the access policy denies the
// user. It returns true when the request was refused.
func refuseDeniedUser(w http.ResponseWriter, id identity.Identity) bool {
	if !deniedByPolicy(id) {
		return false
	}

	name := ""
	if id != nil {
		name = id.UserName()
	}

	log.Printf("Refusing %s: the access policy denies this user", name)
	http.Error(w, "access denied: the access policy does not allow this user", http.StatusForbidden)

	return true
}
