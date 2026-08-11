package scopes

import (
	"context"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"net"
	"net/url"
	"strings"
	"time"
)

type Repository interface {
	GetForOrganization(context.Context, domain.ID, domain.ID) (domain.AuthorizedScope, error)
}

func Normalize(scope domain.AuthorizedScope) (string, error) {
	value := strings.TrimSpace(scope.Value)
	switch scope.Type {
	case domain.ScopeHostname:
		if value == "" {
			return "", net.InvalidAddrError("empty hostname")
		}
		return strings.ToLower(strings.TrimSuffix(value, ".")), nil
	case domain.ScopeIP:
		parsed := net.ParseIP(value)
		if parsed == nil {
			return "", net.InvalidAddrError("invalid IP")
		}
		return parsed.String(), nil
	case domain.ScopeCIDR:
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return "", err
		}
		return network.String(), nil
	case domain.ScopeURL:
		u, err := url.ParseRequestURI(value)
		if err != nil {
			return "", err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return "", net.InvalidAddrError("URL scheme must be http or https")
		}
		u.Fragment = ""
		return u.String(), nil
	default:
		return "", &url.Error{Op: "normalize", URL: value, Err: net.InvalidAddrError("unsupported scope type")}
	}
}
func Active(scope domain.AuthorizedScope, now time.Time) bool {
	return (scope.Status == domain.ScopeApproved || scope.Status == domain.ScopeVerified) && !now.Before(scope.ValidFrom) && now.Before(scope.ValidUntil)
}
