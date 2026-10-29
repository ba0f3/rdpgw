package security

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
)

var (
	Hosts         []string
	HostSelection string
)

func CheckHost(ctx context.Context, host string) (bool, error) {
	s := getTunnel(ctx)

	// The access policy restricts the hosts a user may connect to. It is
	// applied before the host selection rules because it is the more
	// specific of the two.
	if s != nil && s.User != nil {
		if !access.Current().HostAllowed(s.User, host) {
			log.Printf("User %s is not allowed to connect to host %s", s.User.UserName(), host)
			return false, fmt.Errorf("host %s is not allowed for this user", host)
		}
	}

	switch HostSelection {
	case "any":
		return true, nil
	case "signed":
		// todo get from context?
		return false, errors.New("cannot verify host in 'signed' mode as token data is missing")
	case "roundrobin", "unsigned":
		if s == nil || s.User == nil {
			return false, errors.New("no valid session info or username found in context")
		}

		if s.User.UserName() == "" {
			return false, errors.New("no valid session info or username found in context")
		}

		log.Printf("Checking host for user %s", s.User.UserName())
		for _, h := range Hosts {
			h = strings.Replace(h, "{{ preferred_username }}", s.User.UserName(), 1)
			if h == host {
				return true, nil
			}
		}
		return false, fmt.Errorf("invalid host %s", host)
	}

	return false, errors.New("unrecognized host selection criteria")
}
