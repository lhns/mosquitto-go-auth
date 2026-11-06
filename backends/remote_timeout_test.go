package backends

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	gs "github.com/iegomez/mosquitto-go-auth/grpc"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A request of the http backend and of the jwt remote mode always has a timeout.
func TestHTTPAndJWTTimeoutOptions(t *testing.T) {
	cases := map[string]time.Duration{"3": 3 * time.Second, "0": 5 * time.Second, "-1": 5 * time.Second, "abc": 5 * time.Second,
		"2147483647": 2147483647 * time.Second}
	if strconv.IntSize == 64 {
		// The timeout is an int. With 64 bits, the duration sets the limit: the largest number of
		// seconds that a duration holds, and the first one above it. With 32 bits, a larger
		// value is not a number for the int parser, so it gives the default.
		cases["9223372036"] = 9223372036 * time.Second
		cases["9223372037"] = 5 * time.Second
	} else {
		cases["2147483648"] = 5 * time.Second
	}
	for v, want := range cases {
		be, err := NewHTTP(map[string]string{
			"http_host": "h", "http_port": "1", "http_getuser_uri": "/u", "http_aclcheck_uri": "/a", "http_timeout": v,
		}, log.ErrorLevel, "test")
		require.NoError(t, err)
		require.Equal(t, want, be.Client.Timeout, v)

		c, err := NewRemoteJWTChecker(map[string]string{
			"jwt_host": "h", "jwt_port": "1", "jwt_getuser_uri": "/u", "jwt_aclcheck_uri": "/a", "jwt_http_timeout": v,
		}, tokenOptions{}, "test")
		require.NoError(t, err)
		require.Equal(t, want, c.(*remoteJWTChecker).client.Timeout, v)
	}
}

// slowGRPC never answers a check before the context of the call ends. It counts the requests.
type slowGRPC struct {
	gs.UnimplementedAuthServiceServer
	calls atomic.Int32
}

func (s *slowGRPC) wait(ctx context.Context) error {
	s.calls.Add(1)
	<-ctx.Done()
	return ctx.Err()
}

func (s *slowGRPC) GetUser(ctx context.Context, _ *gs.GetUserRequest) (*gs.AuthResponse, error) {
	return nil, s.wait(ctx)
}

func (s *slowGRPC) GetSuperuser(ctx context.Context, _ *gs.GetSuperuserRequest) (*gs.AuthResponse, error) {
	return nil, s.wait(ctx)
}

func (s *slowGRPC) CheckAcl(ctx context.Context, _ *gs.CheckAclRequest) (*gs.AuthResponse, error) {
	return nil, s.wait(ctx)
}

func (s *slowGRPC) GetName(ctx context.Context, _ *empty.Empty) (*gs.NameResponse, error) {
	return nil, s.wait(ctx)
}

func (*slowGRPC) Halt(context.Context, *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, nil
}

func startGRPC(t *testing.T, impl gs.AuthServiceServer) (string, string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	gs.RegisterAuthServiceServer(srv, impl)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	host, port, _ := net.SplitHostPort(lis.Addr().String())
	return host, port
}

// A gRPC check ends at grpc_timeout_ms.
func TestGRPCCallTimeout(t *testing.T) {
	srv := &slowGRPC{}
	host, port := startGRPC(t, srv)
	be, err := NewGRPC(map[string]string{"grpc_host": host, "grpc_port": port, "grpc_timeout_ms": "200"}, log.ErrorLevel)
	require.NoError(t, err)
	defer be.Halt()

	for name, check := range map[string]func() (bool, error){
		"user":      func() (bool, error) { return be.GetUser("u", "p", "c") },
		"superuser": func() (bool, error) { return be.GetSuperuser("u") },
		"acl":       func() (bool, error) { return be.CheckAcl("u", "t", "c", 1) },
	} {
		before := srv.calls.Load()
		start := time.Now()
		ok, err := check()
		elapsed := time.Since(start)
		require.False(t, ok, name)
		require.Equal(t, codes.DeadlineExceeded, status.Code(err), name)
		require.Equal(t, before+1, srv.calls.Load(), "%s: the server did not get the request", name)
		require.GreaterOrEqual(t, elapsed, 150*time.Millisecond, name)
		require.Less(t, elapsed, 2*time.Second, "%s: the check waited for the stalled server", name)
	}

	// The checks log the backend name, so GetName has the same limit.
	start := time.Now()
	require.Equal(t, "gRPC", be.GetName())
	elapsed := time.Since(start)
	require.GreaterOrEqual(t, elapsed, 150*time.Millisecond)
	require.Less(t, elapsed, 2*time.Second, "GetName waited for the stalled server")
}

func TestGRPCTimeoutOption(t *testing.T) {
	host, port := startGRPC(t, NewAuthServiceAPI())
	prev := log.GetLevel()
	log.SetLevel(log.WarnLevel) // NewGRPC does not set the level
	t.Cleanup(func() { log.SetLevel(prev) })
	for v, want := range map[string]time.Duration{"": 5 * time.Second, "1500": 1500 * time.Millisecond, "0": 5 * time.Second, "-5": 5 * time.Second, "x": 5 * time.Second,
		"9223372036854": 9223372036854 * time.Millisecond, "9223372036855": 5 * time.Second} {
		hook := logtest.NewGlobal()
		opts := map[string]string{"grpc_host": host, "grpc_port": port}
		if v != "" {
			opts["grpc_timeout_ms"] = v
		}
		be, err := NewGRPC(opts, log.WarnLevel)
		require.NoError(t, err)
		require.Equal(t, want, be.callTimeout, v)
		be.Halt()
		warned := false
		for _, e := range hook.AllEntries() {
			warned = warned || e.Level == log.WarnLevel && e.Message == "option grpc_timeout_ms must be a number of milliseconds above 0 and in the range of a duration, the default (5000) is used"
		}
		require.Equal(t, v != "" && want == 5*time.Second, warned, v)
	}
}
