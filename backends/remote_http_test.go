package backends

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

// closeTracker counts the response bodies that the client closes.
type closeTracker struct {
	rt     http.RoundTripper
	opened atomic.Int32
	closed atomic.Int32
}

type trackedBody struct {
	io.ReadCloser
	t *closeTracker
}

func (b trackedBody) Close() error { b.t.closed.Add(1); return b.ReadCloser.Close() }

func (c *closeTracker) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.rt.RoundTrip(r)
	if err == nil {
		c.opened.Add(1)
		resp.Body = trackedBody{resp.Body, c}
	}
	return resp, err
}

// remoteSUT is one remote backend (http or jwt) under test.
type remoteSUT struct {
	name    string
	call    func() (bool, error)
	client  *http.Client
	tracker *closeTracker
}

func splitHostPort(t *testing.T, rawURL string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://"))
	require.NoError(t, err)
	return host, port
}

// newRemoteSUTs returns the http backend and the jwt remote checker for srv, with extra options.
func newRemoteSUTs(t *testing.T, srv *httptest.Server, mode string, extra map[string]string) []remoteSUT {
	t.Helper()
	host, port := splitHostPort(t, srv.URL)
	tls := "false"
	if strings.HasPrefix(srv.URL, "https") {
		tls = "true"
	}
	opts := map[string]string{
		"http_host": host, "http_port": port, "http_getuser_uri": "/user", "http_aclcheck_uri": "/acl",
		"http_response_mode": mode, "http_with_tls": tls,
		"jwt_host": host, "jwt_port": port, "jwt_getuser_uri": "/user", "jwt_aclcheck_uri": "/acl",
		"jwt_response_mode": mode, "jwt_with_tls": tls,
	}
	for k, v := range extra {
		opts[k] = v
	}
	hb, err := NewHTTP(opts, log.GetLevel(), "test")
	require.NoError(t, err)
	hb.Client.Transport = &closeTracker{rt: hb.Client.Transport}
	jc, err := NewRemoteJWTChecker(opts, tkOptions, "test")
	require.NoError(t, err)
	jr := jc.(*remoteJWTChecker)
	jr.client.Transport = &closeTracker{rt: jr.client.Transport}
	return []remoteSUT{
		{"http", func() (bool, error) { return hb.GetUser("u", "p", "c") }, hb.Client, hb.Client.Transport.(*closeTracker)},
		{"jwt", func() (bool, error) { return jr.GetUser("a.b.c") }, jr.client, jr.client.Transport.(*closeTracker)},
	}
}

func TestRemoteBodyLimit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   string
		status int
		body   string
		ok     bool
		err    bool
	}{
		{"json at the limit", "json", 200, `{"ok":true}` + strings.Repeat(" ", maxRemoteBody-11), true, false},
		{"json over the limit", "json", 200, `{"ok":true}` + strings.Repeat(" ", maxRemoteBody-10), false, true},
		{"text over the limit", "text", 200, "ok" + strings.Repeat(" ", maxRemoteBody), false, true},
		{"status over the limit", "status", 200, strings.Repeat("x", maxRemoteBody+1), false, true},
		{"large body of a 403", "status", 403, strings.Repeat("x", 4*maxRemoteBody), false, false},
		{"large body of a 500", "status", 500, strings.Repeat("x", 4*maxRemoteBody), false, true},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, tc.body)
		}))
		for _, s := range newRemoteSUTs(t, srv, tc.mode, nil) {
			ok, err := s.call()
			require.Equal(t, tc.ok, ok, "%s %s", s.name, tc.name)
			require.Equal(t, tc.err, err != nil, "%s %s: %v", s.name, tc.name, err)
			require.EqualValues(t, 1, s.tracker.opened.Load(), "%s %s", s.name, tc.name)
			require.EqualValues(t, 1, s.tracker.closed.Load(), "%s %s: body not closed", s.name, tc.name)
		}
		srv.Close()
	}
}

// redirectServer counts its requests and redirects when to returns a location.
func redirectServer(t *testing.T, tls bool, hits *atomic.Int32, auth *atomic.Value, to func(r *http.Request) string) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if auth != nil {
			auth.Store(r.Header.Get("Authorization"))
		}
		if loc := to(r); loc != "" {
			http.Redirect(w, r, loc, http.StatusTemporaryRedirect)
		}
	})
	srv := httptest.NewUnstartedServer(handler)
	if tls {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return srv
}

func noRedirect(*http.Request) string { return "" }

var followOpts = map[string]string{"http_follow_redirects": "true", "jwt_follow_redirects": "true"}

func TestRemoteRedirectNotFollowedByDefault(t *testing.T) {
	var targetHits, srcHits atomic.Int32
	target := redirectServer(t, false, &targetHits, nil, noRedirect)
	src := redirectServer(t, false, &srcHits, nil, func(*http.Request) string { return target.URL + "/user" })
	for _, s := range newRemoteSUTs(t, src, "status", nil) {
		ok, err := s.call()
		require.False(t, ok, s.name)
		require.NoError(t, err, s.name) // a 3xx is a status below 500
		require.EqualValues(t, 1, s.tracker.closed.Load(), s.name)
	}
	require.EqualValues(t, 2, srcHits.Load())
	require.Zero(t, targetHits.Load())

	// A bad Location is also a plain 3xx.
	bad := redirectServer(t, false, &srcHits, nil, func(*http.Request) string { return "http://[::1" })
	for _, s := range newRemoteSUTs(t, bad, "status", nil) {
		ok, err := s.call()
		require.False(t, ok, s.name)
		require.NoError(t, err, s.name)
	}
}

func TestRemoteRedirectFollowed(t *testing.T) {
	// Same host: followed, at most maxRemoteRedirects hops.
	for _, hops := range []int{maxRemoteRedirects, maxRemoteRedirects + 1} {
		var hits atomic.Int32
		srv := redirectServer(t, false, &hits, nil, func(r *http.Request) string {
			if r.URL.Path == "/user" && r.URL.Query().Get("n") == "" {
				return "/user?n=1"
			}
			if n := r.URL.Query().Get("n"); n != "" && int(n[0]-'0') < hops {
				return "/user?n=" + string(n[0]+1)
			}
			return ""
		})
		for _, s := range newRemoteSUTs(t, srv, "status", followOpts) {
			ok, err := s.call()
			require.Equal(t, hops <= maxRemoteRedirects, ok, "%s %d", s.name, hops)
			require.Equal(t, hops > maxRemoteRedirects, err != nil, "%s %d", s.name, hops)
		}
	}

	// Another host, or https to http: refused, with an error.
	var otherHits, hits atomic.Int32
	other := redirectServer(t, false, &otherHits, nil, noRedirect)
	cross := redirectServer(t, false, &hits, nil, func(*http.Request) string { return "http://localhost:" + portOf(t, other) + "/user" })
	down := redirectServer(t, true, &hits, nil, func(*http.Request) string { return other.URL + "/user" })
	for _, srv := range []*httptest.Server{cross, down} {
		for _, s := range newRemoteSUTs(t, srv, "status", followOpts) {
			ok, err := s.call()
			require.False(t, ok, s.name)
			require.Error(t, err, s.name)
		}
	}
	require.Zero(t, otherHits.Load())
}

func portOf(t *testing.T, srv *httptest.Server) string {
	_, port := splitHostPort(t, srv.URL)
	return port
}

// With the issuer as host, a redirect may go to a host in jwt_host_whitelist, and only such a host
// gets the token.
func TestRemoteJWTRedirectAllowlist(t *testing.T) {
	var allowedHits, otherHits, srcHits atomic.Int32
	var allowedAuth, otherAuth atomic.Value
	allowed := redirectServer(t, false, &allowedHits, &allowedAuth, noRedirect)
	other := redirectServer(t, false, &otherHits, &otherAuth, noRedirect)
	allowedHost := "localhost:" + portOf(t, allowed)
	src := redirectServer(t, false, &srcHits, nil, func(r *http.Request) string {
		if r.URL.Query().Get("to") == "other" {
			return other.URL + "/user"
		}
		return "http://" + allowedHost + "/user"
	})
	srcHost := "127.0.0.1:" + portOf(t, src)

	options := keyOpts(jwtSecret)
	options.parseToken = true
	c, err := NewRemoteJWTChecker(map[string]string{
		"jwt_port": "1", "jwt_getuser_uri": "/user", "jwt_aclcheck_uri": "/acl",
		"jwt_host_whitelist": srcHost + "," + allowedHost, "jwt_follow_redirects": "true",
	}, options, "test")
	require.NoError(t, err)
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": srcHost, "sub": "user", "username": "user", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(jwtSecret)
	require.NoError(t, err)

	ok, err := c.GetUser(tok)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 1, allowedHits.Load())
	require.Equal(t, "Bearer "+tok, allowedAuth.Load())

	jr := c.(*remoteJWTChecker)
	jr.userUri = "/user?to=other"
	ok, err = c.GetUser(tok)
	require.Error(t, err)
	require.False(t, ok)
	require.Zero(t, otherHits.Load())
}

// checkRedirectChain runs the redirect policy of c for the last URL of chain, after the others.
func checkRedirectChain(t *testing.T, c *http.Client, chain ...string) error {
	t.Helper()
	var via []*http.Request
	for _, u := range chain[:len(chain)-1] {
		r, err := http.NewRequest(http.MethodGet, u, nil)
		require.NoError(t, err)
		via = append(via, r)
	}
	req, err := http.NewRequest(http.MethodGet, chain[len(chain)-1], nil)
	require.NoError(t, err)
	return c.CheckRedirect(req, via)
}

// The redirect policy compares effective origins and refuses every https to http hop. The same
// rules apply with an allowlist (JWT issuer mode), which only adds destinations with the same
// scheme.
func TestRemoteRedirectPolicy(t *testing.T) {
	type chain struct {
		urls []string
		ok   bool
	}
	common := []chain{
		{[]string{"https://auth.example:443/user", "https://auth.example/check"}, true},
		{[]string{"https://auth.example/user", "https://AUTH.example:443/check"}, true},
		{[]string{"http://auth.example/user", "http://auth.example:80/check"}, true},
		{[]string{"http://auth.example/user", "https://auth.example/check"}, true},
		{[]string{"http://auth.example:8080/user", "https://auth.example/check"}, true},
		{[]string{"http://auth.example:8080/user", "https://auth.example:8080/check"}, true},
		{[]string{"http://auth.example:8080/user", "https://auth.example:9443/check"}, false},
		{[]string{"http://auth.example/user", "https://auth.example/secure", "http://auth.example/final"}, false},
		{[]string{"https://auth.example/user", "http://auth.example/check"}, false},
		{[]string{"http://auth.example/user", "http://third.example/check"}, false},
		{[]string{"http://auth.example/user", "http://auth.example:8080/check"}, false},
	}
	allowlist := []chain{
		{[]string{"http://auth.example/user", "http://other.example/check"}, true},
		{[]string{"http://auth.example/user", "https://other.example/check"}, false},
		{[]string{"https://auth.example/user", "http://other.example/check"}, false},
	}
	plain := newRemoteClient(5, false, nil, true, nil)
	allowed := newRemoteClient(5, false, nil, true, func(u *url.URL) bool { return u.Hostname() == "other.example" })
	for _, tc := range common {
		require.Equal(t, tc.ok, checkRedirectChain(t, plain, tc.urls...) == nil, "%v", tc.urls)
		require.Equal(t, tc.ok, checkRedirectChain(t, allowed, tc.urls...) == nil, "allowlist %v", tc.urls)
	}
	for _, tc := range allowlist {
		require.Equal(t, tc.ok, checkRedirectChain(t, allowed, tc.urls...) == nil, "allowlist %v", tc.urls)
	}
	require.Error(t, checkRedirectChain(t, plain, "http://auth.example/user", "http://other.example/check"))
}

// With redirects off, a 3xx status logs one warning for each check type and backend. The check
// is still denied without an error, and the warning holds no URL, Location, username or token.
func TestRemoteRedirectWarning(t *testing.T) {
	prev := log.GetLevel()
	log.SetLevel(log.WarnLevel)
	t.Cleanup(func() { log.SetLevel(prev) })

	var hits atomic.Int32
	srv := redirectServer(t, false, &hits, nil, func(*http.Request) string { return "http://secret-location.example/next" })
	warnings := func(hook *logtest.Hook, prefix string) []string {
		var out []string
		for _, e := range hook.AllEntries() {
			if e.Level == log.WarnLevel && strings.HasPrefix(e.Message, prefix+": HTTP status") {
				out = append(out, e.Message)
			}
		}
		return out
	}
	for _, s := range newRemoteSUTs(t, srv, "status", nil) {
		hook := logtest.NewGlobal()
		for i := 0; i < 3; i++ {
			ok, err := s.call()
			require.False(t, ok, s.name)
			require.NoError(t, err, s.name)
		}
		got := warnings(hook, s.name)
		require.Equal(t, []string{s.name + ": HTTP status 307. Redirects are off. Configure the final endpoint, or set " +
			s.name + "_follow_redirects true."}, got, s.name)
		for _, e := range hook.AllEntries() {
			require.NotContains(t, e.Message, "secret-location", s.name)
			require.NotContains(t, e.Message, "a.b.c", s.name)
		}
		hook.Reset()
	}

	// Each check type warns once, also with concurrent calls (run with -race).
	host, port := splitHostPort(t, srv.URL)
	hb, err := NewHTTP(map[string]string{
		"http_host": host, "http_port": port, "http_getuser_uri": "/user", "http_aclcheck_uri": "/acl",
		"http_superuser_uri": "/super",
	}, log.WarnLevel, "test")
	require.NoError(t, err)
	hook := logtest.NewGlobal()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = hb.GetUser("u", "p", "c")
			_, _ = hb.GetSuperuser("u")
			_, _ = hb.CheckAcl("u", "t", "c", 1)
		}()
	}
	wg.Wait()
	require.Len(t, warnings(hook, "http"), 3)

	// With redirects on, a 3xx that is not a redirect gives no warning.
	srv304 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotModified) }))
	t.Cleanup(srv304.Close)
	hook.Reset()
	for _, s := range newRemoteSUTs(t, srv304, "status", followOpts) {
		ok, err := s.call()
		require.False(t, ok, s.name)
		require.NoError(t, err, s.name)
	}
	require.Empty(t, warnings(hook, "http"))
	require.Empty(t, warnings(hook, "jwt"))
}
