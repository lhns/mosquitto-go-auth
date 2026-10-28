package backends

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"time"
)

// maxExp is the largest exp that gives a cap (year 9999). A larger exp gives no cap.
const maxExp = 253402300799

// CacheDeadline tells until when a cached result for username can be used.
// When the JWT backend is on and username is a compact JWT with a numeric exp claim, the deadline
// is exp and capped is true. A JWT prefix is removed first. Only the payload is decoded: the
// header and the signature are not checked, so a token of any algorithm gets the cap. The exp
// claim can only make the cache lifetime shorter and it never grants access.
// The cap does not apply when the checks skip the expiration: for a login result when
// jwt_skip_user_expiration is true, for an ACL result when both skip options are true (a
// superuser check, which uses the user option, can also grant an ACL request).
func (b *Backends) CacheDeadline(username string, acl bool) (deadline time.Time, capped bool) {
	if _, ok := b.backends[jwtBackend]; !ok || b.jwtSkipUserExp && (!acl || b.jwtSkipACLExp) {
		return time.Time{}, false
	}
	if b.checkPrefix {
		if valid, _ := b.lookupPrefix(username); valid {
			username = username[strings.Index(username, "_")+1:]
		}
	}

	parts := strings.Split(username, ".")
	if len(parts) != 3 {
		return time.Time{}, false // not a compact JWT
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil || claims.Exp == "" {
		return time.Time{}, false // no exp, or an exp that is not a number
	}
	exp, err := claims.Exp.Float64()
	if err != nil || math.IsNaN(exp) || exp < 0 || exp > maxExp {
		return time.Time{}, false
	}
	sec, frac := math.Modf(exp)

	return time.Unix(int64(sec), int64(frac*1e9)), true
}
