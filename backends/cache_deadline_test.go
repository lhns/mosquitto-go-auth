package backends

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	jwtGo "github.com/golang-jwt/jwt/v5"
	. "github.com/smartystreets/goconvey/convey"
)

func TestCacheDeadline(t *testing.T) {
	sign := func(claims jwtGo.MapClaims) string {
		token, err := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, claims).SignedString([]byte("secret"))
		So(err, ShouldBeNil)
		return token
	}

	Convey("CacheDeadline should give the exp of a JWT", t, func() {
		exp := time.Now().Add(time.Hour).Truncate(time.Second)
		token := sign(jwtGo.MapClaims{"username": "test", "exp": exp.Unix()})
		b := &Backends{backends: map[string]Backend{jwtBackend: &JWT{}}, jwtMode: localMode}

		for _, acl := range []bool{false, true} {
			deadline, capped := b.CacheDeadline(token, acl)
			So(capped, ShouldBeTrue)
			So(deadline.Equal(exp), ShouldBeTrue)
		}

		Convey("An expired token should give a deadline in the past", func() {
			deadline, capped := b.CacheDeadline(sign(jwtGo.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()}), true)
			So(capped, ShouldBeTrue)
			So(deadline.Before(time.Now()), ShouldBeTrue)
		})

		Convey("A JWT prefix should be removed", func() {
			b.checkPrefix = true
			b.prefixes = map[string]string{"jwt": jwtBackend}

			deadline, capped := b.CacheDeadline("jwt_"+token, false)
			So(capped, ShouldBeTrue)
			So(deadline.Equal(exp), ShouldBeTrue)
		})

		Convey("The algorithm of the token should not matter", func() {
			// ES256K is not registered in the JWT library. The payload has padding.
			header := base64.URLEncoding.EncodeToString([]byte(`{"alg":"ES256K","typ":"JWT"}`))
			payload := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"test","exp":%d}`, exp.Unix())))
			deadline, capped := b.CacheDeadline(header+"."+payload+".c2ln", true)
			So(capped, ShouldBeTrue)
			So(deadline.Equal(exp), ShouldBeTrue)

		})

		Convey("A token with an undecodable header should still be capped", func() {
			payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix())))
			deadline, capped := b.CacheDeadline("!!!."+payload+".c2ln", true)
			So(capped, ShouldBeTrue)
			So(deadline.Equal(exp), ShouldBeTrue)
		})

		Convey("A payload with exp and EXP should be capped at the real exp", func() {
			// A case-insensitive JSON decoder would take the last key, the JWT library takes "exp".
			raw := func(payload string) string {
				return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".x"
			}
			for _, payload := range []string{
				fmt.Sprintf(`{"exp":%d,"EXP":4102444800}`, exp.Unix()),
				fmt.Sprintf(`{"EXP":4102444800,"exp":%d}`, exp.Unix()),
			} {
				deadline, capped := b.CacheDeadline(raw(payload), true)
				So(capped, ShouldBeTrue)
				So(deadline.Equal(exp), ShouldBeTrue)
			}
		})

		Convey("There should be no cap for a username that is not a JWT or a JWT without an exp", func() {
			raw := func(payload string) string {
				return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".x"
			}
			for _, username := range []string{"alice", "", "a.b.c", "a.b", sign(jwtGo.MapClaims{"username": "test"}),
				raw(`not json`), raw(`[1]`), raw(`{"EXP":1}`), raw(`{"exp":253402300800}`)} {
				_, capped := b.CacheDeadline(username, true)
				So(capped, ShouldBeFalse)
			}
		})

		Convey("An exp that cannot be read should expire the token at once", func() {
			raw := func(payload string) string {
				return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".x"
			}
			future := time.Now().Add(time.Hour).Unix()
			for _, payload := range []string{
				`{"exp":"1730000000"}`, `{"exp":null}`, `{"exp":true}`, `{"exp":{}}`, `{"exp":[]}`, `{"exp":-1}`,
				// the unrelated claim breaks a decode of all claims, exp must still count
				`{"exp":"x","x":1e400}`,
			} {
				deadline, capped := b.CacheDeadline(raw(payload), true)
				So(capped, ShouldBeTrue)
				So(deadline.After(time.Now()), ShouldBeFalse)
			}

			// An unrelated claim that does not decode must not lift the cap of a valid exp.
			deadline, capped := b.CacheDeadline(raw(fmt.Sprintf(`{"exp":%d,"x":1e400}`, future)), true)
			So(capped, ShouldBeTrue)
			So(deadline.Equal(time.Unix(future, 0)), ShouldBeTrue)

			// Both keys: only "exp" counts, here it is unreadable.
			deadline, capped = b.CacheDeadline(raw(`{"exp":"x","EXP":4102444800}`), true)
			So(capped, ShouldBeTrue)
			So(deadline.After(time.Now()), ShouldBeFalse)

			Convey("with a JWT prefix", func() {
				b.checkPrefix = true
				b.prefixes = map[string]string{"jwt": jwtBackend}
				_, capped := b.CacheDeadline("jwt_"+raw(`{"exp":null}`), true)
				So(capped, ShouldBeTrue)
			})
		})

		Convey("An exp too large to expire should not cap, a fractional exp should keep its fraction", func() {
			raw := func(payload string) string {
				return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".x"
			}
			for _, payload := range []string{`{"exp":1e300}`, `{"exp":99999999999999999999}`, `{"exp":253402300800}`} {
				_, capped := b.CacheDeadline(raw(payload), true)
				So(capped, ShouldBeFalse)
			}
			deadline, capped := b.CacheDeadline(raw(`{"exp":253402300799}`), true)
			So(capped, ShouldBeTrue)
			So(deadline.Equal(time.Unix(253402300799, 0)), ShouldBeTrue)

			deadline, capped = b.CacheDeadline(raw(`{"exp":1700000000.5}`), true)
			So(capped, ShouldBeTrue)
			So(deadline.Equal(time.Unix(1700000000, 500000000)), ShouldBeTrue)
		})

		Convey("There should be no cap without the JWT backend", func() {
			_, capped := (&Backends{}).CacheDeadline(token, true)
			So(capped, ShouldBeFalse)
		})

		Convey("The skip options should remove the cap only in local and files mode", func() {
			tests := []struct {
				mode                  string
				skipUser, skipACL     bool
				userCapped, aclCapped bool
			}{
				{localMode, false, false, true, true},
				{localMode, true, false, false, true},
				{localMode, false, true, true, true},
				{localMode, true, true, false, false},
				{filesMode, true, true, false, false},
				{remoteMode, true, true, true, true},
				{jsMode, true, true, true, true},
			}
			for _, test := range tests {
				b := &Backends{backends: map[string]Backend{jwtBackend: &JWT{}}, jwtMode: test.mode, jwtSkipUserExp: test.skipUser, jwtSkipACLExp: test.skipACL}
				_, capped := b.CacheDeadline(token, false)
				So(capped, ShouldEqual, test.userCapped)
				_, capped = b.CacheDeadline(token, true)
				So(capped, ShouldEqual, test.aclCapped)
			}
		})
	})
}
