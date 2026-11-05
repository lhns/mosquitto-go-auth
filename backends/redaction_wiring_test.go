package backends

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	gs "github.com/iegomez/mosquitto-go-auth/grpc"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The http backend logs only the status of a denial with a JWT backend, not the text that can echo
// the username (cut off) and the password. Without one the text is logged.
func TestRedaction_HTTPDenialText(t *testing.T) {
	for _, mode := range []string{"text", "json"} {
		text := "bad token " + longToken[:40] + " password " + sentinelPW
		reply := text
		if mode == "json" {
			reply = `{"ok":false,"error":"` + text + `"}`
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(reply))
		}))
		t.Cleanup(srv.Close)

		for _, hide := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/hide=%t", mode, hide), func(t *testing.T) {
				o := httpForRedaction(t, srv.URL, hide)
				o.ResponseMode = mode
				hook := captureDebugLogs(t)
				ok, err := o.GetUser(longToken, sentinelPW, "cid")
				require.NoError(t, err)
				require.False(t, ok)
				if hide {
					requireNoTokenLeak(t, hook, longToken)
					require.False(t, logsContain(hook, sentinelPW))
					require.True(t, logsContain(hook, "api error: status 200"))
				} else {
					require.True(t, logsContain(hook, text))
				}
			})
		}
	}
}

// roundTripFunc is an http.RoundTripper made of a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// failingBody fails its read with an error that echoes the token.
type failingBody struct{ token string }

func (b failingBody) Read([]byte) (int, error) { return 0, fmt.Errorf("read failed for %s", b.token) }
func (failingBody) Close() error               { return nil }

// A read error of the reply, which holds the token, is hidden in the http and remote jwt backends.
func TestRedaction_ReadError(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: failingBody{longToken}, Header: http.Header{}, Request: r}, nil
	})}

	t.Run("http", func(t *testing.T) {
		o := httpForRedaction(t, "http://localhost:1", true)
		o.Client = client
		hook := captureDebugLogs(t)
		_, err := o.GetUser(longToken, "pw", "cid")
		requireNoTokenLeak(t, hook, longToken, err)
		require.Contains(t, err.Error(), "read failed")
	})

	t.Run("remote jwt", func(t *testing.T) {
		b := remoteJWTForRedaction(t, map[string]string{"jwt_host": "localhost:1"})
		b.checker.(*remoteJWTChecker).client = client
		hook := captureDebugLogs(t)
		_, err := b.GetUser(longToken, "", "cid")
		requireNoTokenLeak(t, hook, longToken, err)
		require.Contains(t, err.Error(), "read failed")
	})
}

// A request error that quotes a redirect URL holds the percent-encoded token: it is hidden too.
func TestRedaction_EncodedToken(t *testing.T) {
	opaque := "ab+cd/ef=gh" + strings.Repeat("x+y/z=", 8)
	require.NotEqual(t, opaque, url.QueryEscape(opaque))
	require.NotEqual(t, opaque, url.PathEscape(opaque))

	for _, encoded := range []string{url.QueryEscape(opaque), url.PathEscape(opaque)} {
		err := hideToken(true, errors.New(`Get "https://host/x?t=`+encoded+`": redirect`), opaque)
		require.NotContains(t, err.Error(), encoded)
		require.Contains(t, err.Error(), hiddenUsername)
	}
	// Not hidden without a jwt backend.
	err := hideToken(false, errors.New("t="+url.QueryEscape(opaque)), opaque)
	require.Contains(t, err.Error(), url.QueryEscape(opaque))

	// Through a real redirect to a URL with the token in the query.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/x?t="+url.QueryEscape(opaque), http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	o := httpForRedaction(t, srv.URL, true)
	hook := captureDebugLogs(t)
	_, err = o.GetUser(opaque, "pw", "cid")
	require.Error(t, err)
	require.NotContains(t, err.Error(), url.QueryEscape(opaque))
	require.False(t, logsContain(hook, url.QueryEscape(opaque)))
}

// failingLDAP is an LDAP client whose search error quotes the filter, which holds the username.
type failingLDAP struct{}

func (failingLDAP) Close() error           { return nil }
func (failingLDAP) Bind(_, _ string) error { return nil }
func (failingLDAP) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return nil, fmt.Errorf("bad filter %s", r.Filter)
}

// With a JWT backend the LDAP search errors do not hold the username (runs without a server).
func TestRedaction_LDAPErrorEcho(t *testing.T) {
	for _, hide := range []bool{true, false} {
		t.Run(fmt.Sprintf("hide=%t", hide), func(t *testing.T) {
			l := &LDAP{
				client: failingLDAP{}, UserFilter: "(cn=%s)", SuperuserFilter: "(cn=%s)", GroupFilter: "(member=%s)",
				GroupDN: "ou=g", AclTopicPatternAttribute: "p", AclAccAttribute: "a", hideToken: hide,
			}
			hook := captureDebugLogs(t)

			_, userErr := l.GetUser(longToken, "pw", "cid")
			_, superErr := l.GetSuperuser(longToken)
			_, aclErr := l.CheckAcl(longToken, "t", "cid", 1)

			for _, err := range []error{userErr, superErr, aclErr} {
				require.Error(t, err)
				require.Equal(t, !hide, strings.Contains(err.Error(), longToken))
			}
			if hide {
				requireNoTokenLeak(t, hook, longToken, userErr, superErr, aclErr)
			} else {
				require.True(t, logsContain(hook, longToken))
			}
		})
	}
}

// withHideToken sets hideToken on every backend type that echoes external error text.
func TestWithHideToken(t *testing.T) {
	for _, hide := range []bool{true, false} {
		got := map[string]bool{
			"postgres": withHideToken(Postgres{}, hide).(Postgres).hideToken,
			"mysql":    withHideToken(Mysql{}, hide).(Mysql).hideToken,
			"sqlite":   withHideToken(Sqlite{}, hide).(Sqlite).hideToken,
			"http":     withHideToken(HTTP{}, hide).(HTTP).hideToken,
			"ldap":     withHideToken(&LDAP{}, hide).(*LDAP).hideToken,
			"grpc":     withHideToken(&GRPC{}, hide).(*GRPC).hideToken,
			"js":       withHideToken(&Javascript{}, hide).(*Javascript).hideToken,
		}
		for name, value := range got {
			require.Equal(t, hide, value, name)
		}
	}
}

// Initialize sets hideToken only with a jwt backend. The backends that need no server are used;
// the sql and ldap backends need one and are covered by TestWithHideToken.
func TestInitializeSetsHideToken(t *testing.T) {
	script := writeScript(t, t.TempDir(), "script.js", "true;")
	for _, withJWT := range []bool{true, false} {
		opts := map[string]string{
			"backends":  "http,js",
			"http_host": "localhost", "http_port": "1", "http_getuser_uri": "/u", "http_superuser_uri": "/s", "http_aclcheck_uri": "/a",
			"js_user_script_path": script, "js_superuser_script_path": script, "js_acl_script_path": script,
		}
		if withJWT {
			opts["backends"] = "http,js,jwt"
			opts["jwt_mode"] = "remote"
			opts["jwt_host"] = "localhost"
			opts["jwt_getuser_uri"] = "/u"
			opts["jwt_aclcheck_uri"] = "/a"
			opts["jwt_port"] = ""
			opts["jwt_secret"] = "secret"
			opts["jwt_userfield"] = "Username"
			opts["jwt_response_mode"] = "text"
			opts["jwt_params_mode"] = "form"
		}
		b, err := Initialize(opts, log.DebugLevel, "test")
		require.NoError(t, err)
		t.Cleanup(b.Halt)
		require.Equal(t, withJWT, b.backends[httpBackend].(HTTP).hideToken)
		require.Equal(t, withJWT, b.backends[jsBackend].(*Javascript).hideToken)
	}
}

// sliceAuthServer is a gRPC auth server whose errors echo a middle slice of the username.
type sliceAuthServer struct{ echoAuthServer }

func slice(username string) string { return username[20:60] }

func (sliceAuthServer) GetUser(_ context.Context, req *gs.GetUserRequest) (*gs.AuthResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "unknown user "+slice(req.Username))
}

func (sliceAuthServer) GetSuperuser(_ context.Context, req *gs.GetSuperuserRequest) (*gs.AuthResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "unknown user "+slice(req.Username))
}

func (sliceAuthServer) CheckAcl(_ context.Context, req *gs.CheckAclRequest) (*gs.AuthResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "unknown user "+slice(req.Username))
}

// A gRPC error that echoes a slice from the middle of the token is hidden as a whole.
func TestRedaction_GRPCMiddleSliceEcho(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	gs.RegisterAuthServiceServer(srv, &sliceAuthServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	host, port, err := net.SplitHostPort(lis.Addr().String())
	require.NoError(t, err)

	for _, hide := range []bool{true, false} {
		t.Run(fmt.Sprintf("hide=%t", hide), func(t *testing.T) {
			hook := captureDebugLogs(t)
			g, err := NewGRPC(map[string]string{"grpc_host": host, "grpc_port": port, "grpc_dial_timeout_ms": "1000"}, log.DebugLevel)
			require.NoError(t, err)
			g.hideToken = hide

			_, userErr := g.GetUser(longToken, "pw", "cid")
			_, superErr := g.GetSuperuser(longToken)
			_, aclErr := g.CheckAcl(longToken, "t", "cid", 1)

			if hide {
				requireNoTokenLeak(t, hook, longToken, userErr, superErr, aclErr)
			} else {
				require.Contains(t, userErr.Error(), slice(longToken))
				require.True(t, logsContain(hook, slice(longToken)))
			}
		})
	}
}

// A script that puts a part of the token (the signature, a middle slice) into its error does not
// leak it.
func TestRedaction_JSPartOfTokenEcho(t *testing.T) {
	dir := t.TempDir()
	scripts := map[string]struct{ body, part string }{
		"signature": {"var p = username.split('.'); null[p[2]];", strings.Split(longToken, ".")[2]},
		"slice":     {"null[username.substring(20, 60)];", slice(longToken)},
	}
	for name, tc := range scripts {
		script := writeScript(t, dir, name+".js", tc.body)
		for _, hide := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/hide=%t", name, hide), func(t *testing.T) {
				hook := captureDebugLogs(t)
				j, err := NewJavascript(map[string]string{
					"js_user_script_path": script, "js_superuser_script_path": script, "js_acl_script_path": script,
					"js_ms_max_duration": "5000",
				}, log.DebugLevel)
				require.NoError(t, err)
				j.hideToken = hide

				_, userErr := j.GetUser(longToken, "pw", "cid")
				_, superErr := j.GetSuperuser(longToken)
				_, aclErr := j.CheckAcl(longToken, "t", "cid", 1)

				if hide {
					requireNoTokenLeak(t, hook, longToken, userErr, superErr, aclErr)
				} else {
					// The control: the script really puts the part into the error.
					require.Contains(t, userErr.Error(), tc.part)
					require.True(t, logsContain(hook, tc.part))
				}
			})
		}
	}
}

// echoBackend fails every call with an error that echoes the username, as mongo, redis or a
// custom plugin can.
type echoBackend struct{}

func (echoBackend) GetUser(username, _, _ string) (bool, error) {
	return false, errors.New("unknown user " + username)
}
func (echoBackend) GetSuperuser(username string) (bool, error) {
	return false, errors.New("unknown user " + username)
}
func (echoBackend) CheckAcl(username, _, _ string, _ int32) (bool, error) {
	return false, errors.New("unknown user " + username)
}
func (echoBackend) GetName() string { return "echo" }
func (echoBackend) Halt()           {}

// The dispatcher hides the username in the errors of every backend with a JWT backend, also for
// backends without their own hiding. Without one the error is returned unchanged.
func TestRedaction_DispatcherErrors(t *testing.T) {
	for _, exhaust := range []bool{false, true} {
		for _, hide := range []bool{true, false} {
			t.Run(fmt.Sprintf("exhaust=%t/hide=%t", exhaust, hide), func(t *testing.T) {
				b := &Backends{
					backends:       map[string]Backend{"echo": echoBackend{}},
					userCheckers:   []string{"echo"},
					aclCheckers:    []string{"echo"},
					sortedBackends: []string{"echo"},
					prefixes:       map[string]string{}, jwtConfigured: hide, exhaustBackendFirst: exhaust,
					superuserCheckers: []string{"echo"},
				}
				hook := captureDebugLogs(t)

				_, userErr := b.AuthUnpwdCheck(context.Background(), longToken, "pw", "cid")
				_, aclErr := b.AuthAclCheck(context.Background(), "cid", longToken, "t", 1)

				if hide {
					requireNoTokenLeak(t, hook, longToken, userErr, aclErr)
				} else {
					require.Contains(t, userErr.Error(), longToken)
					require.Contains(t, aclErr.Error(), longToken)
				}
			})
		}
	}
}
