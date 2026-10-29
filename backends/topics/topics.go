package topics

import (
	"strings"

	log "github.com/sirupsen/logrus"
)

// Match tells if givenTopic matches savedTopic's pattern.
// A topic that starts with "$" is not matched by a pattern whose first level is "+" or "#"
// (MQTT section 4.7.2). A shared subscription filter "$share/<group>/..." keeps the plain matching.
func Match(savedTopic, givenTopic string) bool {
	if givenTopic == savedTopic {
		return true
	}
	if strings.HasPrefix(givenTopic, "$") && !strings.HasPrefix(givenTopic, "$share/") {
		if first, _, _ := strings.Cut(savedTopic, "/"); first == "+" || first == "#" {
			return false
		}
	}
	return match(strings.Split(savedTopic, "/"), strings.Split(givenTopic, "/"))
}

// MatchDeny tells if givenTopic matches savedTopic's pattern, for deny rules. It does not apply
// the "$" rule of Match: a deny rule that starts with "#" or "+" also denies "$" topics, like in
// 3.5.1, so that the rule cannot deny less than before.
func MatchDeny(savedTopic, givenTopic string) bool {
	return givenTopic == savedTopic || match(strings.Split(savedTopic, "/"), strings.Split(givenTopic, "/"))
}

func match(route []string, topic []string) bool {
	switch {
	case len(route) == 0:
		return len(topic) == 0
	case len(topic) == 0:
		return route[0] == "#"
	case route[0] == "#":
		return len(route) == 1 // '#' must be last in pattern
	case route[0] == "+", route[0] == topic[0]:
		return match(route[1:], topic[1:])
	}

	return false
}

// Outcome tells what Substitute did with a pattern.
type Outcome int

const (
	// Replaced: the pattern is usable.
	Replaced Outcome = iota
	// Skip: a used value is empty or has "/" or NUL. The value cannot widen a rule but it changes
	// the rule's meaning, so an allow rule does not apply. A deny rule is matched with the
	// literal result, as it would be without the check, so that it cannot fail open.
	Skip
	// Reject: a used value has "+" or "#". The value would widen a rule.
	// An allow rule does not apply, a deny rule denies the request.
	Reject
)

// Substitute replaces "%u" with username and "%c" with clientid in pattern, in one pass.
// A replaced value is not scanned again. If a value that pattern uses is empty or has "/" or NUL,
// the outcome is Skip and the result has the values inserted as they are. If one has "+" or "#",
// the result is ("", Reject). See Outcome. This extends the auth_plugin_deny_special_chars check of mosquitto.
func Substitute(pattern, username, clientid string) (string, Outcome) {
	orig := pattern
	if !strings.Contains(pattern, "%") {
		return pattern, Replaced
	}
	var b strings.Builder
	// A skipped value does not end the scan: a wildcard in a later value must still give Reject.
	skipped := false
	for {
		i := strings.IndexByte(pattern, '%')
		if i < 0 || i+1 >= len(pattern) {
			b.WriteString(pattern)
			if skipped {
				return b.String(), Skip
			}
			return b.String(), Replaced
		}
		var v, name string
		switch pattern[i+1] {
		case 'u':
			v, name = username, "username"
		case 'c':
			v, name = clientid, "clientid"
		default:
			b.WriteString(pattern[:i+1])
			pattern = pattern[i+1:]
			continue
		}
		// The value is not logged because it can be a token.
		if strings.ContainsAny(v, "+#") {
			log.Debugf("acl pattern %q: %s placeholder rejected, it has a wildcard", orig, name)
			return "", Reject
		}
		if v == "" || strings.ContainsAny(v, "/\x00") {
			log.Debugf("acl pattern %q: %s placeholder skipped, it is empty or has / or NUL", orig, name)
			skipped = true
		}
		b.WriteString(pattern[:i])
		b.WriteString(v)
		pattern = pattern[i+2:]
	}
}
