package topics

import (
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestTopicsMatch(t *testing.T) {
	Convey("Match should match mqtt topics correctly", t, func() {
		tests := []struct {
			pattern  string
			topic    string
			expected bool
		}{
			// Exact matches
			{"a/b/c", "a/b/c", true},
			{"a/b", "a/b", true},
			{"a", "a", true},

			{"a/b", "a/x", false},
			{"a/b", "x/b", false},

			// Single-level wildcard +
			{"a/+/c", "a/b/c", true},
			{"a/+/c", "a/x/c", true},
			{"+/+/+", "a/b/c", true},
			{"+/b/+", "a/b/c", true},
			{"a/b/+", "a/b/c", true},
			{"+", "a", true},

			{"a/+/c", "a/x/x", false},

			// Wrong segment count with +
			{"a/+/c", "a/c", false},
			{"a/+/c", "a/b/c/d", false},
			{"+/+", "a", false},
			{"+/+", "a/b/c", false},

			// Multi-level wildcard #
			{"a/b/#", "a/b", true},
			{"a/b/#", "a/b/c", true},
			{"a/b/#", "a/b/c/d/e", true},
			{"#", "a", true},
			{"#", "a/b/c", true},
			{"#", "/", true},
			{"#", "//", true},

			{"a/b/#", "a", false},
			{"a/b/#", "a/x/c", false},

			// # cannot match middle segments
			{"a/#/c", "a/b/c", false},

			// Pattern longer than topic
			{"a/b/c/d", "a/b/c", false},
			{"a/b/+", "a/b", false},

			// Topic longer than pattern
			{"a/b", "a/b/c", false},
			{"a/b/c", "a/b/c/d", false},
			{"a/b/+", "a/b/c/d", false},

			// Empty topic and pattern
			{"", "", true},
			{"#", "", true},
			{"+", "", true},

			{"", "a", false},

			// Trailing slashes
			{"a/b/", "a/b/", true},

			{"a/b", "a/b/", false},
			{"a/b/", "a/b", false},

			// Topic with empty segments
			{"a//c", "a//c", true},
			{"a/+/c", "a//c", true},

			// A topic that starts with $ is not matched by + or # at the first level
			{"#", "$SYS/broker/uptime", false},
			{"#", "$SYS", false},
			{"+/x", "$private/x", false},
			{"+", "$", false},
			{"#", "$SYS/#", false},
			{"+/#", "$SYS/#", false},
			{"$SYS/#", "$SYS/broker/uptime", true},
			{"$SYS/+/uptime", "$SYS/broker/uptime", true},
			{"$SYS/#", "$SYS/#", true},
			{"a/#", "a/$x", true},
			{"+/+", "a/$x", true},

			// A shared subscription filter keeps the plain matching
			{"#", "$share/g/a/b", true},
			{"+/g/#", "$share/g/a", true},
		}

		for i, test := range tests {
			Convey(fmt.Sprintf("#%d: Match(%s, %s)", i, test.pattern, test.topic), func() {
				result := Match(test.pattern, test.topic)

				if result != test.expected {
					fmt.Printf("\nFAILED test #%d: pattern=%q topic=%q → got=%v, expected=%v\n", i, test.topic, test.pattern, result, test.expected)
				}

				So(result, ShouldEqual, test.expected)
			})
		}
	})
}

func TestSubstitute(t *testing.T) {
	Convey("Substitute should replace %u and %c in one pass and check the values", t, func() {
		tests := []struct {
			pattern  string
			username string
			clientid string
			want     string
			ok       Outcome
		}{
			{"a/b", "", "", "a/b", Replaced},
			{"users/%u/%c", "alice", "dev1", "users/alice/dev1", Replaced},
			{"%u/%u", "alice", "", "alice/alice", Replaced},
			{"%c%u", "x", "y", "yx", Replaced},
			{"a/%x/%", "u", "c", "a/%x/%", Replaced},
			{"a/%%u", "alice", "c", "a/%alice", Replaced},

			// A value is not scanned again.
			{"a/%u", "%c", "dev1", "a/%c", Replaced},
			{"a/%c", "alice", "%u", "a/%u", Replaced},

			// A used value with + or # is rejected. An empty value or one with / or NUL is skipped.
			{"clients/%c/#", "alice", "+", "", Reject},
			{"clients/%c/#", "alice", "#", "", Reject},
			{"clients/%c/#", "alice", "a/b", "", Skip},
			{"clients/%c/#", "alice", "a\x00", "", Skip},
			{"clients/%c/#", "alice", "", "", Skip},
			{"users/%u", "", "dev1", "", Skip},
			{"users/%u", "a+", "dev1", "", Reject},
			{"users/%u", "a/+", "dev1", "", Reject},

			// A skipped value does not hide a wildcard in another value.
			{"%c/%u/x", "+", "", "", Reject},
			{"%u/%c/x", "", "+", "", Reject},
			{"%c/%u/x", "", "", "", Skip},

			// A value that the pattern does not use is not checked.
			{"users/%u", "alice", "+", "users/alice", Replaced},
		}

		for i, test := range tests {
			got, ok := Substitute(test.pattern, test.username, test.clientid)
			So(fmt.Sprintf("#%d %q %v", i, got, ok), ShouldEqual, fmt.Sprintf("#%d %q %v", i, test.want, test.ok))
		}
	})
}
