package topics

import (
	"strings"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

// Plugin-wide options (auth_opt_<name>). SetOptions sets them once at startup, before any check.
var (
	uncheckedPlaceholders atomic.Bool // deny_special_chars false
	legacyWildcard        atomic.Bool // acl_legacy_wildcard_match true
)

// SetOptions reads the options deny_special_chars (default true) and acl_legacy_wildcard_match
// (default false). It logs a warning for each option that turns a check off.
// Both options are temporary and a later release removes them.
func SetOptions(authOpts map[string]string) {
	uncheckedPlaceholders.Store(authOpts["deny_special_chars"] == "false")
	legacyWildcard.Store(authOpts["acl_legacy_wildcard_match"] == "true")

	if uncheckedPlaceholders.Load() {
		log.Warn("option deny_special_chars is false: the user name and client ID placeholders are replaced also when the value is empty or has + # / or NUL. This option is temporary and a later release removes it")
	}
	if legacyWildcard.Load() {
		log.Warn("option acl_legacy_wildcard_match is true: a rule that starts with + or # also matches a topic that starts with $. This option is temporary and a later release removes it")
	}
}

// Match tells if givenTopic matches savedTopic's pattern.
// A topic that starts with "$" is not matched by a pattern whose first level is "+" or "#"
// (MQTT section 4.7.2). A shared subscription filter "$share/<group>/..." keeps the plain matching.
func Match(savedTopic, givenTopic string) bool {
	if givenTopic == savedTopic {
		return true
	}
	if !legacyWildcard.Load() && strings.HasPrefix(givenTopic, "$") && !strings.HasPrefix(givenTopic, "$share/") {
		if first, _, _ := strings.Cut(savedTopic, "/"); first == "+" || first == "#" {
			return false
		}
	}
	return match(strings.Split(savedTopic, "/"), strings.Split(givenTopic, "/"))
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

// Substitute replaces "%u" with username and "%c" with clientid in pattern, in one pass.
// A replaced value is not scanned again. If a value that pattern uses is empty or has "+", "#",
// "/" or NUL, the result is ("", false): an allow rule does not apply and a deny rule denies.
// With deny_special_chars false, the values are not checked.
func Substitute(pattern, username, clientid string) (string, bool) {
	if !strings.Contains(pattern, "%") {
		return pattern, true
	}
	check := !uncheckedPlaceholders.Load()
	var b strings.Builder
	for {
		i := strings.IndexByte(pattern, '%')
		if i < 0 || i+1 >= len(pattern) {
			b.WriteString(pattern)
			return b.String(), true
		}
		var v string
		switch pattern[i+1] {
		case 'u':
			v = username
		case 'c':
			v = clientid
		default:
			b.WriteString(pattern[:i+1])
			pattern = pattern[i+1:]
			continue
		}
		if check && (v == "" || strings.ContainsAny(v, "+#/\x00")) {
			return "", false
		}
		b.WriteString(pattern[:i])
		b.WriteString(v)
		pattern = pattern[i+2:]
	}
}
