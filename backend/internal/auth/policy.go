package auth

import "strings"

var privilegedMFARoles = map[string]struct{}{"owner": {}, "administrator": {}, "security administrator": {}}

func MFARequired(roleNames []string, organizationRequiresMFA bool) bool {
	if organizationRequiresMFA {
		return true
	}
	for _, name := range roleNames {
		if _, ok := privilegedMFARoles[strings.ToLower(name)]; ok {
			return true
		}
	}
	return false
}

type SessionCookiePolicy struct {
	Name          string
	Secure        bool
	HTTPOnly      bool
	SameSite      string
	MaxAgeSeconds int
}

func CookiePolicy(production bool) SessionCookiePolicy {
	return SessionCookiePolicy{Name: "netscope_session", Secure: production, HTTPOnly: true, SameSite: "Lax", MaxAgeSeconds: 43200}
}
