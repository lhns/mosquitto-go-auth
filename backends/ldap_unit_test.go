package backends

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// These tests use a fake LDAP client and need no LDAP server.

const (
	testServiceDN = "cn=mosquitto,ou=people,dc=example,dc=org"
	testUserDN    = "cn=user,ou=people,dc=example,dc=org"
)

var errLDAPNet = ldap.NewError(ldap.ErrorNetwork, errors.New("network down"))

// recConn is one fake connection. It records the binds and the searches made on it.
type recConn struct {
	srv      *recServer
	mu       sync.Mutex
	binds    []string
	searches int
	closed   bool
}

func (c *recConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *recConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *recConn) Bind(user, _ string) error {
	c.mu.Lock()
	c.binds = append(c.binds, user)
	c.mu.Unlock()
	return c.srv.bindErr(user)
}

func (c *recConn) Search(*ldap.SearchRequest) (*ldap.SearchResult, error) {
	c.mu.Lock()
	c.searches++
	n, closed := c.searches, c.closed
	c.mu.Unlock()
	if closed {
		c.srv.closedSearches.Add(1)
		return nil, errors.New("search on a closed connection")
	}
	time.Sleep(50 * time.Microsecond) // give an overlapping request time to run
	if err := c.srv.searchErr(n); err != nil {
		return nil, err
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(testUserDN, nil)}}, nil
}

// recServer hands out fake connections and lets a test inject errors.
type recServer struct {
	mu             sync.Mutex
	conns          []*recConn
	closedSearches atomic.Int32
	dialErr        error
	bindErr        func(user string) error
	searchErr      func(n int) error // n counts the searches on one connection
}

func (s *recServer) factory(LDAP) (LDAPClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dialErr != nil {
		return nil, s.dialErr
	}
	c := &recConn{srv: s}
	s.conns = append(s.conns, c)
	return c, nil
}

func newRecLDAP(t *testing.T, srv *recServer) *LDAP {
	t.Helper()
	if srv.bindErr == nil {
		srv.bindErr = func(string) error { return nil }
	}
	if srv.searchErr == nil {
		srv.searchErr = func(int) error { return nil }
	}
	l, err := NewLDAPWithFactory(map[string]string{
		"ldap_user_dn":           "ou=people,dc=example,dc=org",
		"ldap_group_dn":          "ou=groups,dc=example,dc=org",
		"ldap_bind_dn":           testServiceDN,
		"ldap_bind_password":     "pw",
		"ldap_user_filter":       "(cn=%s)",
		"ldap_superuser_filter":  "(cn=%s)",
		"ldap_acl_acc_attribute": "mqttTopicAcc",
	}, log.ErrorLevel, srv.factory)
	require.NoError(t, err)
	return l
}

// Concurrent requests with network errors: no search runs on a closed connection, each
// network error is hidden by one reconnect and retry, and a service connection never binds a user.
func TestLDAPConcurrentRequestsWithReconnects(t *testing.T) {
	srv := &recServer{searchErr: func(n int) error {
		if n%5 == 0 {
			return errLDAPNet
		}
		return nil
	}}
	l := newRecLDAP(t, srv)

	var errs atomic.Int32
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				for _, f := range []func() (bool, error){
					func() (bool, error) { return l.GetUser("user", "secret", "c") },
					func() (bool, error) { return l.GetSuperuser("user") },
					func() (bool, error) { return l.CheckAcl("user", "a/b", "c", 1) },
				} {
					if _, err := f(); err != nil {
						errs.Add(1)
					}
				}
			}
		}()
	}
	wg.Wait()
	l.Halt()

	require.Zero(t, srv.closedSearches.Load(), "a search ran on a closed connection")
	require.Zero(t, errs.Load())
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, c := range srv.conns {
		if c.searches > 0 {
			require.Equal(t, []string{testServiceDN}, c.binds, "a service connection binds only the service account")
		} else {
			require.Equal(t, []string{testUserDN}, c.binds)
			require.True(t, c.closed, "a user connection is closed after the bind")
		}
	}
}

func TestLDAPUserBindErrors(t *testing.T) {
	var userErr error
	srv := &recServer{bindErr: func(u string) error {
		if u == testUserDN {
			return userErr
		}
		return nil
	}}
	l := newRecLDAP(t, srv)

	// A wrong password is a denial.
	userErr = ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	ok, err := l.GetUser("user", "bad", "c")
	require.NoError(t, err)
	require.False(t, ok)

	// A network error, also a plain one, is an error and not a denial.
	for _, e := range []error{errLDAPNet, &net.OpError{Op: "read", Err: errors.New("reset")}} {
		userErr = e
		ok, err = l.GetUser("user", "secret", "c")
		require.Error(t, err)
		require.False(t, ok)
	}
}

func TestLDAPFailedReconnectConnectsAgain(t *testing.T) {
	failed := false
	srv := &recServer{searchErr: func(int) error {
		if !failed {
			failed = true
			return errLDAPNet
		}
		return nil
	}}
	l := newRecLDAP(t, srv)

	// The reconnect fails: an error, and no service connection is left.
	srv.dialErr = errLDAPNet
	_, err := l.GetSuperuser("user")
	require.Error(t, err)

	// The next request connects again.
	srv.dialErr = nil
	ok, err := l.GetSuperuser("user")
	require.NoError(t, err)
	require.True(t, ok)
}

func TestLDAPHalt(t *testing.T) {
	srv := &recServer{}
	l := newRecLDAP(t, srv)
	l.Halt()
	l.Halt()
	require.True(t, srv.conns[0].isClosed())

	_, err := l.GetUser("user", "secret", "c")
	require.ErrorIs(t, err, errLDAPHalted)
	_, err = l.GetSuperuser("user")
	require.ErrorIs(t, err, errLDAPHalted)
	_, err = l.CheckAcl("user", "a/b", "c", 1)
	require.ErrorIs(t, err, errLDAPHalted)
}

func TestLDAPTimeoutOption(t *testing.T) {
	for v, want := range map[string][2]time.Duration{
		// Not set and invalid values: 10 seconds for the responses and for the connect.
		"":   {10 * time.Second, 10 * time.Second},
		"3":  {3 * time.Second, 3 * time.Second},
		"0":  {0, 0}, // no plugin limit for both
		"-1": {10 * time.Second, 10 * time.Second},
		"x":  {10 * time.Second, 10 * time.Second},
		// The largest number of seconds that a duration holds, and the first one above it.
		"9223372036": {9223372036 * time.Second, 9223372036 * time.Second},
		"9223372037": {10 * time.Second, 10 * time.Second},
	} {
		opts := map[string]string{
			"ldap_user_dn": "ou=people", "ldap_bind_dn": testServiceDN, "ldap_bind_password": "pw", "ldap_user_filter": "(cn=%s)",
		}
		if v != "" {
			opts["ldap_timeout"] = v
		}
		srv := &recServer{bindErr: func(string) error { return nil }}
		l, err := NewLDAPWithFactory(opts, log.ErrorLevel, srv.factory)
		require.NoError(t, err)
		require.Equal(t, want[0], l.Timeout, v)
		require.Equal(t, want[1], l.DialTimeout, v)
	}
}

// A server that accepts the connection but never answers: the service bind ends at ldap_timeout.
func TestLDAPTimeoutStalledServer(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	var conns []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})

	start := time.Now()
	_, err = NewLDAP(map[string]string{
		"ldap_url": "ldap://" + lis.Addr().String(), "ldap_timeout": "1",
		"ldap_user_dn": "ou=people", "ldap_bind_dn": testServiceDN, "ldap_bind_password": "pw", "ldap_user_filter": "(cn=%s)",
	}, log.ErrorLevel)
	require.Error(t, err)
	require.Less(t, time.Since(start), 5*time.Second)
}

// netEchoLDAP fails every search with a network error that quotes the filter, which holds the
// username.
type netEchoLDAP struct{}

func (netEchoLDAP) Close() error           { return nil }
func (netEchoLDAP) Bind(_, _ string) error { return nil }
func (netEchoLDAP) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return nil, ldap.NewError(ldap.ErrorNetwork, fmt.Errorf("bad filter %s", r.Filter))
}

// The reconnect path does not log the username: with a jwt backend it can be a token.
func TestLDAPNetworkErrorRedaction(t *testing.T) {
	l, err := NewLDAPWithFactory(map[string]string{
		"ldap_user_dn": "ou=people", "ldap_bind_dn": testServiceDN, "ldap_bind_password": "pw",
		"ldap_user_filter": "(cn=%s)", "ldap_superuser_filter": "(cn=%s)",
		"ldap_group_dn": "ou=g", "ldap_acl_topic_pattern_attribute": "p",
	}, log.ErrorLevel, func(LDAP) (LDAPClient, error) { return netEchoLDAP{}, nil })
	require.NoError(t, err)
	l.hideToken = true
	hook := captureDebugLogs(t)

	_, userErr := l.GetUser(longToken, "pw", "cid")
	_, superErr := l.GetSuperuser(longToken)
	_, aclErr := l.CheckAcl(longToken, "t", "cid", 1)
	for _, err := range []error{userErr, superErr, aclErr} {
		require.Error(t, err)
	}
	requireNoTokenLeak(t, hook, longToken, userErr, superErr, aclErr)
}

// fakeLDAPServer answers a bind with success. On the first connection it resets the socket when
// a search comes. On a later connection it answers a search with one entry.
func fakeLDAPServer(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	var conns atomic.Int32
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			n := conns.Add(1)
			go func(c net.Conn, first bool) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					m, err := c.Read(buf)
					if err != nil || m < 2 {
						return
					}
					// LDAPMessage: SEQUENCE, length, messageID (INTEGER, 1 byte), protocolOp tag.
					off := 2
					if buf[1]&0x80 != 0 {
						off += int(buf[1] & 0x7f)
					}
					id, op := buf[off+2], buf[off+3]
					switch op {
					case 0x60: // bind request: success
						_, _ = c.Write([]byte{0x30, 0x0c, 0x02, 0x01, id, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
					case 0x63: // search request
						if first {
							_ = c.(*net.TCPConn).SetLinger(0) // reset, not a clean close
							return
						}
						_, _ = c.Write([]byte{0x30, 0x0a, 0x02, 0x01, id, 0x64, 0x05, 0x04, 0x01, 'a', 0x30, 0x00})
						_, _ = c.Write([]byte{0x30, 0x0c, 0x02, 0x01, id, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
					default: // unbind and others
						return
					}
				}
			}(c, n == 1)
		}
	}()
	return lis.Addr().String(), &conns
}

// A real socket reset during a search: go-ldap returns a plain error, and the plugin still
// reconnects and runs the search again.
func TestLDAPSocketResetReconnects(t *testing.T) {
	addr, conns := fakeLDAPServer(t)
	l, err := NewLDAP(map[string]string{
		"ldap_url": "ldap://" + addr, "ldap_timeout": "5",
		"ldap_user_dn": "ou=people", "ldap_bind_dn": testServiceDN, "ldap_bind_password": "pw",
		"ldap_user_filter": "(cn=%s)", "ldap_superuser_filter": "(cn=%s)",
	}, log.ErrorLevel)
	require.NoError(t, err)
	defer l.Halt()

	ok, err := l.GetSuperuser("user")
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 2, conns.Load())
}

// sendFailLDAP fails the first search the way go-ldap reports a failed write: a plain error, and
// the connection is not closing yet (the reader is still blocked).
type sendFailLDAP struct {
	recConn
	failed *atomic.Bool
}

func (c *sendFailLDAP) IsClosing() bool { return false }

func (c *sendFailLDAP) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if c.failed.CompareAndSwap(false, true) {
		return nil, errors.New("unable to send request: write tcp 127.0.0.1:1->127.0.0.1:2: write: broken pipe")
	}
	return c.recConn.Search(r)
}

func TestLDAPSendFailureReconnects(t *testing.T) {
	srv := &recServer{bindErr: func(string) error { return nil }, searchErr: func(int) error { return nil }}
	var failed atomic.Bool
	var conns atomic.Int32
	l, err := NewLDAPWithFactory(map[string]string{
		"ldap_user_dn": "ou=people", "ldap_bind_dn": testServiceDN, "ldap_bind_password": "pw",
		"ldap_user_filter": "(cn=%s)", "ldap_superuser_filter": "(cn=%s)",
	}, log.ErrorLevel, func(LDAP) (LDAPClient, error) {
		conns.Add(1)
		return &sendFailLDAP{recConn: recConn{srv: srv}, failed: &failed}, nil
	})
	require.NoError(t, err)

	ok, err := l.GetSuperuser("user")
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 2, conns.Load(), "one reconnect")
}

// The result codes of the user bind: a refusal is a denial, any other result is an error.
func TestLDAPUserBindResultCodes(t *testing.T) {
	var code uint16
	srv := &recServer{bindErr: func(u string) error {
		if u == testUserDN {
			return ldap.NewError(code, errors.New("bind result"))
		}
		return nil
	}}
	l := newRecLDAP(t, srv)
	for c, denial := range map[uint16]bool{
		ldap.LDAPResultInvalidCredentials:          true,
		ldap.LDAPResultNoSuchObject:                true,
		ldap.LDAPResultInvalidDNSyntax:             true,
		ldap.ErrorEmptyPassword:                    true,
		ldap.LDAPResultConstraintViolation:         true,
		ldap.LDAPResultInappropriateAuthentication: true,
		ldap.LDAPResultInsufficientAccessRights:    true,
		ldap.LDAPResultBusy:                        false,
		ldap.LDAPResultUnavailable:                 false,
		ldap.LDAPResultUnwillingToPerform:          false,
		ldap.LDAPResultOther:                       false,
	} {
		code = c
		ok, err := l.GetUser("user", "secret", "c")
		require.False(t, ok, c)
		require.Equal(t, !denial, err != nil, "code %d: %v", c, err)
	}

	// The service bind is not a user bind: a refusal there is an error.
	srv.bindErr = func(string) error {
		return ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("refused"))
	}
	_, err := NewLDAPWithFactory(map[string]string{
		"ldap_user_dn": "ou=people", "ldap_bind_dn": testServiceDN, "ldap_bind_password": "pw", "ldap_user_filter": "(cn=%s)",
	}, log.ErrorLevel, srv.factory)
	require.Error(t, err)
}

// A refused user bind is logged at debug level only, with a fixed message.
func TestLDAPUserBindRefusalLog(t *testing.T) {
	srv := &recServer{bindErr: func(u string) error {
		if u == testUserDN {
			return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials for cn=user"))
		}
		return nil
	}}
	l := newRecLDAP(t, srv)
	hook := captureDebugLogs(t)
	ok, err := l.GetUser("user", "bad", "c")
	require.NoError(t, err)
	require.False(t, ok)
	for _, e := range hook.AllEntries() {
		require.Less(t, log.ErrorLevel, e.Level, "a refusal must not log at error level: %s", e.Message)
		require.NotContains(t, e.Message, "cn=user")
	}
	require.True(t, logsContain(hook, "LDAP user bind refused"))
}

// With a jwt backend, the error of a user bind that is not a refusal does not hold the username.
func TestLDAPUserBindErrorRedaction(t *testing.T) {
	srv := &recServer{bindErr: func(u string) error {
		if u == testUserDN {
			return ldap.NewError(ldap.LDAPResultUnwillingToPerform, fmt.Errorf("unwilling for %s", longToken))
		}
		return nil
	}}
	l := newRecLDAP(t, srv)
	l.hideToken = true
	hook := captureDebugLogs(t)
	ok, err := l.GetUser(longToken, "pw", "c")
	require.Error(t, err)
	require.False(t, ok)
	requireNoTokenLeak(t, hook, longToken, err)
}
