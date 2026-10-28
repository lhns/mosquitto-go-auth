package backends

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	jwtGo "github.com/golang-jwt/jwt/v5"
)

// CacheDeadline tells until when a cached result for username can be used.
// When the JWT backend is on and username is a compact JWT with an exp claim, the deadline is
// exp and capped is true. A JWT prefix is removed first. Only the payload is decoded
// (header, signature and algorithm are ignored), so a token of any algorithm gets the
// cap. The exp claim can only make the cache lifetime shorter and it never grants access.
// The skip options lift the cap only in local and files mode, where the plugin checks the
// token itself: for a login result when jwt_skip_user_expiration is true, for an ACL result
// when both skip options are true (a superuser check, which uses the user option, can also
// grant an ACL request). In remote and js mode the server or script decides about exp, so a
// token is always capped.
func (b *Backends) CacheDeadline(username string, acl bool) (deadline time.Time, capped bool) {
	if _, ok := b.backends[jwtBackend]; !ok {
		return time.Time{}, false
	}
	if (b.jwtMode == localMode || b.jwtMode == filesMode) && b.jwtSkipUserExp && (!acl || b.jwtSkipACLExp) {
		return time.Time{}, false
	}
	if b.checkPrefix {
		if i := strings.Index(username, "_"); i > 0 {
			if _, ok := b.prefixes[username[:i]]; ok {
				username = username[i+1:]
			}
		}
	}

	// Only the payload is decoded: a broken header, an unknown algorithm or a bad signature must
	// not lift the cap, because the remote server may still accept such a token. Anything that
	// is not a JWT has no claims, so no exp. A map keeps the key matching case-sensitive.
	parts := strings.Split(username, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	claims := jwtGo.MapClaims{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, false
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return time.Time{}, false // no exp, or an exp that is not a number
	}

	return exp.Time, true
}
