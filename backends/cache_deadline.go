package backends

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"
)

// maxExp is 9999-12-31T23:59:59Z. A larger exp is treated as no exp.
const maxExp = 253402300799

// CacheDeadline tells until when a cached result for username can be used. It only makes the
// cache lifetime shorter, it never grants access.
// With the JWT backend on and a compact JWT (after removing a JWT prefix) with an exp claim,
// the deadline is exp rounded down to the second, like the JWT library does, and capped is true.
// Only the payload is decoded, so a token of any algorithm gets the cap. An exp that is not a
// non-negative number (a string, null, an object, a negative number) is capped at once, so the
// result is not cached: the remote server or script may read it differently. An exp beyond
// the year 9999 is no cap.
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
		if prefix, _, ok := b.splitPrefix(username); ok {
			username = username[len(prefix)+1:]
		}
	}

	// A broken header, an unknown algorithm or a bad signature must not lift the cap, because
	// the remote server may still accept such a token. Anything that is not a JWT has no claims,
	// so no exp. A map keeps the key matching case-sensitive.
	parts := strings.Split(username, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, false
	}
	rawExp, ok := claims["exp"]
	if !ok {
		return time.Time{}, false
	}

	// An exp that is present but unreadable (not a number, negative) caps at once, so the cache is
	// skipped and the backend decides: the remote server or script may read it differently.
	dec := json.NewDecoder(bytes.NewReader(rawExp))
	dec.UseNumber()
	var value interface{}
	_ = dec.Decode(&value) // rawExp is valid JSON, anything but a number leaves a non-number
	number, ok := value.(json.Number)
	if !ok {
		return time.Time{}, true
	}
	// Only a range error is possible for a valid JSON number, it gives +-Inf.
	seconds, _ := strconv.ParseFloat(number.String(), 64)
	if seconds < 0 {
		return time.Time{}, true
	}
	if seconds > maxExp {
		return time.Time{}, false // cannot pass within any cache TTL
	}

	return time.Unix(int64(math.Floor(seconds)), 0), true
}
