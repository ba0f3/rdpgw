package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// knownDefaultSecrets is the list of placeholder session/token-key values
// that appear in README.md and the dev compose files. Operators that
// copy-paste the examples into a real deployment would be running with
// widely-published keys, so the gateway refuses to start when one of these
// is set for any of the session-/token-binding fields.
var knownDefaultSecrets = []string{
	"thisisasessionkeyreplacethisjetzt",
	"thisisasessionkeyreplacethisjetz",
	"thisisasessionkeyreplacethisnunu!",
	"thisisasessionkeyreplacethisnunu",
	"thisisasessionencryptionkey12345",
}

func checkDefaultSecrets(c *Configuration) error {
	fields := []struct {
		name  string
		value string
	}{
		{"server.sessionkey", c.Server.SessionKey},
		{"server.sessionencryptionkey", c.Server.SessionEncryptionKey},
		{"security.paatokensigningkey", c.Security.PAATokenSigningKey},
		{"security.paatokenencryptionkey", c.Security.PAATokenEncryptionKey},
		{"security.usertokensigningkey", c.Security.UserTokenSigningKey},
		{"security.usertokenencryptionkey", c.Security.UserTokenEncryptionKey},
		{"security.querytokensigningkey", c.Security.QueryTokenSigningKey},
	}
	for _, f := range fields {
		if f.value == "" {
			continue
		}
		for _, def := range knownDefaultSecrets {
			if f.value == def {
				return fmt.Errorf("%s is set to a known placeholder value (%q); replace it with a unique secret before starting", f.name, def)
			}
		}
	}
	return nil
}

const (
	TlsDisable = "disable"
	TlsAuto    = "auto"

	HostSelectionSigned     = "signed"
	HostSelectionRoundRobin = "roundrobin"

	SessionStoreCookie = "cookie"
	SessionStoreFile   = "file"

	AuthenticationOpenId   = "openid"
	AuthenticationBasic    = "local"
	AuthenticationKerberos = "kerberos"
	AuthenticationHeader   = "header"

	// defaultTokenLifetime is the lifetime of the credentials the gateway
	// hands out in minutes, the defaultSessionLifetime is the lifetime of
	// the browser session in seconds.
	defaultTokenLifetime   = 5
	defaultSessionLifetime = 120

	// maxTokenLifetime and maxSessionLifetime are the values above which
	// the gateway warns the operator. They are not limits, an operator
	// that needs a longer lifetime gets one.
	maxTokenLifetime   = 24 * 60
	maxSessionLifetime = 60 * 60
)

type Configuration struct {
	Server   ServerConfig   `koanf:"server"`
	OpenId   OpenIDConfig   `koanf:"openid"`
	Kerberos KerberosConfig `koanf:"kerberos"`
	Header   HeaderConfig   `koanf:"header"`
	Caps     RDGCapsConfig  `koanf:"caps"`
	Access   AccessConfig   `koanf:"access"`
	Security SecurityConfig `koanf:"security"`
	Client   ClientConfig   `koanf:"client"`
}

type ServerConfig struct {
	GatewayAddress       string   `koanf:"gatewayaddress"`
	Port                 int      `koanf:"port"`
	BindAddress          string   `koanf:"bindaddress"`
	CertFile             string   `koanf:"certfile"`
	KeyFile              string   `koanf:"keyfile"`
	Hosts                []string `koanf:"hosts"`
	HostSelection        string   `koanf:"hostselection"`
	SessionKey           string   `koanf:"sessionkey"`
	SessionEncryptionKey string   `koanf:"sessionencryptionkey"`
	SessionStore         string   `koanf:"sessionstore"`
	MaxSessionLength     int      `koanf:"maxsessionlength"`
	SendBuf              int      `koanf:"sendbuf"`
	ReceiveBuf           int      `koanf:"receivebuf"`
	Tls                  string   `koanf:"tls"`
	Authentication       []string `koanf:"authentication"`
	AuthSocket           string   `koanf:"authsocket"`
	BasicAuthTimeout     int      `koanf:"basicauthtimeout"`
	// AllowedDestinationPorts gates the TCP ports `hostselection: any` may
	// forward to. Empty defaults to {3389}. Ignored for the curated host
	// modes (roundrobin, signed, unsigned).
	AllowedDestinationPorts []int `koanf:"alloweddestinationports"`
	// AllowPrivateDestinations, when true, lets `hostselection: any`
	// forward to loopback, RFC1918, link-local, and IPv6 ULA targets.
	// Default false.
	AllowPrivateDestinations bool `koanf:"allowprivatedestinations"`
	// TrustedProxies is the CIDR allow-list of upstream proxies whose
	// X-Forwarded-For header is honored when deriving the client IP.
	// Empty (the default) makes the gateway ignore X-Forwarded-For
	// entirely and use r.RemoteAddr.
	TrustedProxies []string `koanf:"trustedproxies"`
	// SessionLifetime is the lifetime of the browser session in seconds.
	// It is the time the user has to download an .rdp file before the
	// session expires. Note that this is not the lifetime of the gateway
	// credentials in the .rdp file, that is controlled by
	// security.paatokenlifetime.
	SessionLifetime int `koanf:"sessionlifetime"`
}

type KerberosConfig struct {
	Keytab   string `koanf:"keytab"`
	Krb5Conf string `koanf:"krb5conf"`
}

type OpenIDConfig struct {
	ProviderUrl  string `koanf:"providerurl"`
	ClientId     string `koanf:"clientid"`
	ClientSecret string `koanf:"clientsecret"`
	// Groups is the list of groups a user must be a member of to be
	// allowed to log in to the gateway. An empty list (the default) allows
	// every user the OpenID Connect provider authenticates.
	Groups []string `koanf:"groups"`
	// GroupsClaim is the name of the ID token claim that carries the group
	// membership of the user. It defaults to "groups".
	GroupsClaim string `koanf:"groupsclaim"`
	// Scopes are the scopes requested from the OpenID Connect provider.
	// It defaults to "openid profile email". Providers that only expose
	// group membership through a scope (Keycloak for example) need that
	// scope to be added here.
	Scopes []string `koanf:"scopes"`
}

type HeaderConfig struct {
	UserHeader        string `koanf:"userheader"`
	UserIdHeader      string `koanf:"useridheader"`
	EmailHeader       string `koanf:"emailheader"`
	DisplayNameHeader string `koanf:"displaynameheader"`
	// GroupsHeader is the header that carries the group membership of the
	// user. The value is a comma separated list of group names. It is used
	// by the access policy to apply per group restrictions.
	GroupsHeader string `koanf:"groupsheader"`
	// TrustedProxies is the CIDR allow-list of upstream proxies allowed to
	// stamp UserHeader (and friends). Empty disables header auth at runtime.
	TrustedProxies []string `koanf:"trustedproxies"`
}

// RDGCapsConfig is the global capability configuration. The redirect
// settings are the ceiling of the access policy: a rule in the access
// section can only narrow them, never widen them.
type RDGCapsConfig struct {
	SmartCardAuth   bool `koanf:"smartcardauth"`
	TokenAuth       bool `koanf:"tokenauth"`
	IdleTimeout     int  `koanf:"idletimeout"`
	RedirectAll     bool `koanf:"redirectall"`
	DisableRedirect bool `koanf:"disableredirect"`
	EnableClipboard bool `koanf:"enableclipboard"`
	EnablePrinter   bool `koanf:"enableprinter"`
	EnablePort      bool `koanf:"enableport"`
	EnablePnp       bool `koanf:"enablepnp"`
	EnableDrive     bool `koanf:"enabledrive"`
	// EnableSmartCard allows the smartcards of the client to be redirected
	// into the session. It is off by default.
	EnableSmartCard bool `koanf:"enablesmartcard"`
	// EnableWebAuthn allows WebAuthn credential prompts to be redirected to
	// the client. It is off by default.
	EnableWebAuthn bool `koanf:"enablewebauthn"`
	// EnableLocation allows the location information of the client to be
	// redirected into the session. It is off by default.
	EnableLocation bool `koanf:"enablelocation"`
	// EnableCamera allows the cameras of the client to be redirected into
	// the session. It is off by default, the device redirection of the
	// client does not imply it.
	EnableCamera bool `koanf:"enablecamera"`
	// EnableUsb allows the USB devices of the client to be redirected into
	// the session. It is off by default, the device redirection of the
	// client does not imply it.
	EnableUsb bool `koanf:"enableusb"`
}

// AccessConfig holds the per user and per group access rules.
type AccessConfig struct {
	// Rules are evaluated in order, the first rule that matches the user
	// applies. A rule can narrow the redirect policy and restrict the
	// hosts the user may connect to.
	Rules []AccessRule `koanf:"rules"`
}

// AccessRule restricts what a set of users or groups may do.
type AccessRule struct {
	// Name is an optional identifier for the rule, it is used in the log
	// messages of the gateway.
	Name string `koanf:"name"`
	// Users lists the user names the rule applies to.
	Users []string `koanf:"users"`
	// Groups lists the group names the rule applies to.
	Groups []string `koanf:"groups"`
	// Redirect narrows the redirect policy of the global capabilities for
	// the matching users. Settings that are not mentioned are inherited.
	Redirect *AccessRedirect `koanf:"redirect"`
	// Hosts restricts the matching users to the listed hosts. An empty list
	// does not restrict the hosts. The single entry "*" allows any host.
	Hosts []string `koanf:"hosts"`
	// Deny refuses the matching users access to the gateway.
	Deny bool `koanf:"deny"`
}

// AccessRedirect is a sparse redirect policy. A setting that is not present
// is inherited from the global capabilities.
type AccessRedirect struct {
	EnableClipboard *bool `koanf:"enableclipboard"`
	EnableDrive     *bool `koanf:"enabledrive"`
	EnablePrinter   *bool `koanf:"enableprinter"`
	EnablePort      *bool `koanf:"enableport"`
	EnablePnp       *bool `koanf:"enablepnp"`
	EnableSmartCard *bool `koanf:"enablesmartcard"`
	EnableWebAuthn  *bool `koanf:"enablewebauthn"`
	EnableLocation  *bool `koanf:"enablelocation"`
	EnableCamera    *bool `koanf:"enablecamera"`
	EnableUsb       *bool `koanf:"enableusb"`
}

type SecurityConfig struct {
	PAATokenEncryptionKey  string `koanf:"paatokenencryptionkey"`
	PAATokenSigningKey     string `koanf:"paatokensigningkey"`
	UserTokenEncryptionKey string `koanf:"usertokenencryptionkey"`
	UserTokenSigningKey    string `koanf:"usertokensigningkey"`
	QueryTokenSigningKey   string `koanf:"querytokensigningkey"`
	QueryTokenIssuer       string `koanf:"querytokenissuer"`
	VerifyClientIp         bool   `koanf:"verifyclientip"`
	EnableUserToken        bool   `koanf:"enableusertoken"`
	// PAATokenLifetime is the lifetime of the gateway credentials in
	// minutes. These are the credentials that are handed to the client in
	// the .rdp file, they determine how long a downloaded .rdp file stays
	// usable.
	PAATokenLifetime int `koanf:"paatokenlifetime"`
	// UserTokenLifetime is the lifetime of the user token in minutes.
	UserTokenLifetime int `koanf:"usertokenlifetime"`
	// QueryTokenLifetime is the lifetime of the host selection query token
	// in minutes.
	QueryTokenLifetime int `koanf:"querytokenlifetime"`
}

type ClientConfig struct {
	Defaults string `koanf:"defaults"`
	// kept for backwards compatibility
	UsernameTemplate string `koanf:"usernametemplate"`
	SplitUserDomain  bool   `koanf:"splituserdomain"`
	NoUsername       bool   `koanf:"nousername"`
	SigningCert      string `koanf:"signingcert"`
	SigningKey       string `koanf:"signingkey"`
	// RdpOverridableKeys is the operator allow-list of RDP setting keys that
	// the /connect endpoint may override from URL query parameters. Empty
	// disables URL-based overrides. Entries are normalized (lowercase, no
	// whitespace), so "use multimon" and "usemultimon" are equivalent.
	RdpOverridableKeys []string `koanf:"rdpoverridablekeys"`
}

func ToCamel(s string) string {
	s = strings.TrimSpace(s)
	n := strings.Builder{}
	n.Grow(len(s))
	var capNext bool = true
	for i, v := range []byte(s) {
		vIsCap := v >= 'A' && v <= 'Z'
		vIsLow := v >= 'a' && v <= 'z'
		if capNext {
			if vIsLow {
				v += 'A'
				v -= 'a'
			}
		} else if i == 0 {
			if vIsCap {
				v += 'a'
				v -= 'A'
			}
		}
		if vIsCap || vIsLow {
			n.WriteByte(v)
			capNext = false
		} else if vIsNum := v >= '0' && v <= '9'; vIsNum {
			n.WriteByte(v)
			capNext = true
		} else {
			capNext = v == '_' || v == ' ' || v == '-' || v == '.'
			if v == '.' {
				n.WriteByte(v)
			}
		}
	}
	return n.String()
}

var Conf Configuration

func Load(configFile string) Configuration {

	// start from a clean configuration, a reload must not keep the values
	// of a previous load.
	Conf = Configuration{}

	var k = koanf.New(".")

	k.Load(confmap.Provider(map[string]interface{}{
		"Server.Tls":                  "auto",
		"Server.Port":                 443,
		"Server.BindAddress":          "",
		"Server.SessionStore":         "cookie",
		"Server.SessionLifetime":      120,
		"Server.HostSelection":        "roundrobin",
		"Server.Authentication":       "openid",
		"Server.AuthSocket":           "/tmp/rdpgw-auth.sock",
		"Server.BasicAuthTimeout":     5,
		"Client.NetworkAutoDetect":    1,
		"Client.BandwidthAutoDetect":  1,
		"Security.VerifyClientIp":     true,
		"Security.PAATokenLifetime":   5,
		"Security.UserTokenLifetime":  5,
		"Security.QueryTokenLifetime": 5,
		"Caps.TokenAuth":              true,
	}, "."), nil)

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Printf("Config file %s not found, using defaults and environment", configFile)
	} else {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			log.Fatalf("Error loading config from file: %v", err)
		}
	}

	if err := k.Load(env.ProviderWithValue("RDPGW_", ".", func(s string, v string) (string, interface{}) {
		key := strings.Replace(strings.ToLower(strings.TrimPrefix(s, "RDPGW_")), "__", ".", -1)
		key = ToCamel(key)

		v = strings.Trim(v, " ")

		// handle lists
		if strings.Contains(v, " ") {
			return key, strings.Split(v, " ")
		}
		return key, v

	}), nil); err != nil {
		log.Fatalf("Error loading config from environment: %v", err)
	}

	koanfTag := koanf.UnmarshalConf{Tag: "koanf"}
	k.UnmarshalWithConf("Server", &Conf.Server, koanfTag)
	k.UnmarshalWithConf("OpenId", &Conf.OpenId, koanfTag)
	k.UnmarshalWithConf("Header", &Conf.Header, koanfTag)
	k.UnmarshalWithConf("Caps", &Conf.Caps, koanfTag)
	k.UnmarshalWithConf("Access", &Conf.Access, koanfTag)
	k.UnmarshalWithConf("Security", &Conf.Security, koanfTag)
	k.UnmarshalWithConf("Client", &Conf.Client, koanfTag)
	k.UnmarshalWithConf("Kerberos", &Conf.Kerberos, koanfTag)

	if err := checkDefaultSecrets(&Conf); err != nil {
		log.Fatalf("refusing to start: %s", err)
	}

	if len(Conf.Security.PAATokenEncryptionKey) != 32 {
		Conf.Security.PAATokenEncryptionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `security.paatokenencryptionkey` specified (empty or not 32 characters). Setting to random")
	}

	if len(Conf.Security.PAATokenSigningKey) != 32 {
		Conf.Security.PAATokenSigningKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `security.paatokensigningkey` specified (empty or not 32 characters). Setting to random")
	}

	if Conf.Security.EnableUserToken {
		if len(Conf.Security.UserTokenEncryptionKey) != 32 {
			Conf.Security.UserTokenEncryptionKey, _ = security.GenerateRandomString(32)
			log.Printf("No valid `security.usertokenencryptionkey` specified (empty or not 32 characters). Setting to random")
		}
	}

	if len(Conf.Server.SessionKey) != 32 {
		Conf.Server.SessionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `server.sessionkey` specified (empty or not 32 characters). Setting to random")
	}

	if len(Conf.Server.SessionEncryptionKey) != 32 {
		Conf.Server.SessionEncryptionKey, _ = security.GenerateRandomString(32)
		log.Printf("No valid `server.sessionencryptionkey` specified (empty or not 32 characters). Setting to random")
	}

	if Conf.Server.HostSelection == "signed" && len(Conf.Security.QueryTokenSigningKey) == 0 {
		log.Fatalf("host selection is set to `signed` but `querytokensigningkey` is not set")
	}

	if Conf.Server.BasicAuthEnabled() && Conf.Server.Tls == "disable" {
		log.Fatalf("basicauth=local and tls=disable are mutually exclusive")
	}

	if Conf.Server.NtlmEnabled() && Conf.Server.KerberosEnabled() {
		log.Fatalf("ntlm and kerberos authentication are not stackable")
	}

	if !Conf.Caps.TokenAuth && Conf.Server.OpenIDEnabled() {
		log.Fatalf("openid is configured but tokenauth disabled")
	}

	if Conf.Server.KerberosEnabled() && Conf.Kerberos.Keytab == "" {
		log.Fatalf("kerberos is configured but no keytab was specified")
	}

	if Conf.Server.HeaderEnabled() && Conf.Header.UserHeader == "" {
		log.Fatalf("header authentication is configured but no user header was specified")
	}

	if Conf.Server.SessionLifetime < 0 {
		log.Fatalf("server.sessionlifetime cannot be negative")
	}

	if Conf.Security.PAATokenLifetime < 0 {
		log.Fatalf("security.paatokenlifetime cannot be negative")
	}

	if Conf.Security.UserTokenLifetime < 0 {
		log.Fatalf("security.usertokenlifetime cannot be negative")
	}

	if Conf.Security.QueryTokenLifetime < 0 {
		log.Fatalf("security.querytokenlifetime cannot be negative")
	}

	// A lifetime of zero is the same as an unset lifetime, the default
	// applies. A token that expires on arrival is never what an operator
	// wants.
	if Conf.Server.SessionLifetime == 0 {
		Conf.Server.SessionLifetime = defaultSessionLifetime
	}

	if Conf.Security.PAATokenLifetime == 0 {
		Conf.Security.PAATokenLifetime = defaultTokenLifetime
	}

	if Conf.Security.UserTokenLifetime == 0 {
		Conf.Security.UserTokenLifetime = defaultTokenLifetime
	}

	if Conf.Security.QueryTokenLifetime == 0 {
		Conf.Security.QueryTokenLifetime = defaultTokenLifetime
	}

	// The lifetime of the gateway credentials widens the window in which a
	// stolen .rdp file can be used, the operator should know about it.
	if Conf.Security.PAATokenLifetime > maxTokenLifetime {
		log.Printf("WARNING: security.paatokenlifetime is %d minutes, a gateway access token stays usable for that long",
			Conf.Security.PAATokenLifetime)
	}

	if Conf.Security.UserTokenLifetime > maxTokenLifetime {
		log.Printf("WARNING: security.usertokenlifetime is %d minutes, a user token stays usable for that long",
			Conf.Security.UserTokenLifetime)
	}

	if Conf.Security.QueryTokenLifetime > maxTokenLifetime {
		log.Printf("WARNING: security.querytokenlifetime is %d minutes, a query token stays usable for that long",
			Conf.Security.QueryTokenLifetime)
	}

	if Conf.Server.SessionLifetime > maxSessionLifetime {
		log.Printf("WARNING: server.sessionlifetime is %d seconds, the group membership of a user stays valid for that long",
			Conf.Server.SessionLifetime)
	}

	if Conf.OpenId.GroupsClaim == "" {
		Conf.OpenId.GroupsClaim = "groups"
	}

	// every access rule must select at least one user or group, a rule
	// without a selector would match every user.
	for i, rule := range Conf.Access.Rules {
		if len(rule.Users) == 0 && len(rule.Groups) == 0 {
			log.Fatalf("access rule %d (%s) does not select any user or group", i, rule.Name)
		}
	}

	// prepend '//' if required for URL parsing
	if !strings.Contains(Conf.Server.GatewayAddress, "//") {
		Conf.Server.GatewayAddress = "//" + Conf.Server.GatewayAddress
	}

	return Conf
}

func (s *ServerConfig) OpenIDEnabled() bool {
	return s.matchAuth("openid")
}

func (s *ServerConfig) KerberosEnabled() bool {
	return s.matchAuth("kerberos")
}

func (s *ServerConfig) BasicAuthEnabled() bool {
	return s.matchAuth("local") || s.matchAuth("basic")
}

func (s *ServerConfig) NtlmEnabled() bool {
	return s.matchAuth("ntlm")
}

func (s *ServerConfig) HeaderEnabled() bool {
	return s.matchAuth("header")
}

func (s *ServerConfig) matchAuth(needle string) bool {
	for _, q := range s.Authentication {
		if q == needle {
			return true
		}
	}
	return false
}
