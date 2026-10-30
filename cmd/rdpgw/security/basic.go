package security

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

var (
	Hosts         []string
	HostSelection string
)

// groupRuleWarning makes sure that the operator is warned once when the
// group rules of the access policy do not apply to a session.
var groupRuleWarning sync.Once

// warnAboutGroupRules informs the operator that the rules of the access
// policy that select users by their group membership do not apply to a
// session whose group membership the gateway does not know.
func warnAboutGroupRules(id identity.Identity) {
	groupRuleWarning.Do(func() {
		if !access.Current().HasGroupRules() {
			return
		}

		user := "the user"
		if id != nil && id.UserName() != "" {
			user = id.UserName()
		}

		if id == nil || len(id.Groups()) == 0 {
			log.Printf("WARNING: group membership is unknown for %s; group allow rules cannot grant access and group deny rules fail closed", user)
		}
	})
}

func CheckHost(ctx context.Context, host string) (bool, error) {
	s := getTunnel(ctx)

	// A check without a session cannot decide anything, it refuses the
	// connection.
	if s == nil || s.User == nil {
		return false, errors.New("no valid session info found in context")
	}

	// The access policy restricts the hosts a user may connect to. It is
	// applied before the host selection rules because it is the more
	// specific of the two.
	warnAboutGroupRules(s.User)
	if !access.Current().HostAllowed(s.User, host) {
		log.Printf("User %s is not allowed to connect to host %s", s.User.UserName(), host)
		return false, fmt.Errorf("host %s is not allowed for this user", host)
	}

	switch HostSelection {
	case "any":
		return true, nil
	case "signed":
		// The host was verified when the .rdp file was handed out, the
		// gateway access token of the session pins it.
		if s.TargetServer == "" {
			return false, errors.New("cannot verify host in 'signed' mode as token data is missing")
		}
		if s.TargetServer != host {
			log.Printf("Host %s does not match the host %s of the session", host, s.TargetServer)
			return false, fmt.Errorf("invalid host %s", host)
		}
		return true, nil
	case "roundrobin", "unsigned":
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
