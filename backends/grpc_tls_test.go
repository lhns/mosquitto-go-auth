//go:build integration

package backends

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"testing"

	gs "github.com/iegomez/mosquitto-go-auth/grpc"
	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestGRPCTls(t *testing.T) {
	Convey("Given a mock grpc server with TLS", t, func(c C) {
		serverCert, err := tls.LoadX509KeyPair("/test-files/certificates/grpc/fullchain-server.pem",
			"/test-files/certificates/grpc/server-key.pem")
		c.So(err, ShouldBeNil)

		config := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.NoClientCert,
		}
		grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(config)))
		gs.RegisterAuthServiceServer(grpcServer, NewAuthServiceAPI())

		listen, err := net.Listen("tcp", ":3123")
		c.So(err, ShouldBeNil)

		go grpcServer.Serve(listen)
		defer grpcServer.Stop()

		authOpts := make(map[string]string)
		authOpts["grpc_host"] = "localhost"
		authOpts["grpc_port"] = "3123"
		authOpts["grpc_dial_timeout_ms"] = "100"
		authOpts["grpc_fail_on_dial_error"] = "true"

		Convey("Given client connects without TLS, it should fail", func() {
			g, err := NewGRPC(authOpts, log.DebugLevel)
			c.So(err, ShouldBeError)
			c.So(err.Error(), ShouldEqual, "context deadline exceeded")
			c.So(g, ShouldBeNil)
		})

		authOpts["grpc_ca_cert"] = "/test-files/certificates/db/ca.pem"

		Convey("Given client connects with TLS but with wrong CA, it should fail", func() {
			g, err := NewGRPC(authOpts, log.DebugLevel)
			c.So(err, ShouldBeError)
			c.So(err.Error(), ShouldEqual, "context deadline exceeded")
			c.So(g, ShouldBeNil)
		})

		authOpts["grpc_ca_cert"] = "/test-files/certificates/ca.pem"

		Convey("Given client connects with TLS, it should work", func() {
			g, err := NewGRPC(authOpts, log.DebugLevel)
			c.So(err, ShouldBeNil)
			c.So(g, ShouldNotBeNil)
		})
	})
}

func TestGRPCMutualTls(t *testing.T) {
	Convey("Given a mock grpc server with TLS", t, func(c C) {
		serverCert, err := tls.LoadX509KeyPair("/test-files/certificates/grpc/fullchain-server.pem",
			"/test-files/certificates/grpc/server-key.pem")
		c.So(err, ShouldBeNil)

		clientCaBytes, err := ioutil.ReadFile("/test-files/certificates/grpc/ca.pem")
		c.So(err, ShouldBeNil)
		clientCaCertPool := x509.NewCertPool()
		c.So(clientCaCertPool.AppendCertsFromPEM(clientCaBytes), ShouldBeTrue)

		config := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCaCertPool,
		}
		grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(config)))
		gs.RegisterAuthServiceServer(grpcServer, NewAuthServiceAPI())

		listen, err := net.Listen("tcp", ":3123")
		c.So(err, ShouldBeNil)

		go grpcServer.Serve(listen)
		defer grpcServer.Stop()

		authOpts := make(map[string]string)
		authOpts["grpc_host"] = "localhost"
		authOpts["grpc_port"] = "3123"
		authOpts["grpc_dial_timeout_ms"] = "100"
		authOpts["grpc_fail_on_dial_error"] = "true"

		Convey("Given client connects without TLS, it should fail", func() {
			g, err := NewGRPC(authOpts, log.DebugLevel)
			c.So(err, ShouldBeError)
			c.So(err.Error(), ShouldEqual, "context deadline exceeded")
			c.So(g, ShouldBeNil)
		})

		authOpts["grpc_ca_cert"] = "/test-files/certificates/ca.pem"

		Convey("Given client connects with TLS but without a client certificate, it should fail", func() {
			g, err := NewGRPC(authOpts, log.DebugLevel)
			c.So(err, ShouldBeError)
			c.So(err.Error(), ShouldEqual, "context deadline exceeded")
			c.So(g, ShouldBeNil)
		})

		authOpts["grpc_tls_cert"] = "/test-files/certificates/db/client.pem"
		authOpts["grpc_tls_key"] = "/test-files/certificates/db/client-key.pem"

		Convey("Given client connects with mTLS but with client cert from wrong CA, it should fail", func() {
			g, err := NewGRPC(authOpts, log.DebugLevel)
			c.So(err, ShouldBeError)
			c.So(err.Error(), ShouldEqual, "context deadline exceeded")
			c.So(g, ShouldBeNil)
		})

		authOpts["grpc_tls_cert"] = "/test-files/certificates/grpc/client.pem"
		authOpts["grpc_tls_key"] = "/test-files/certificates/grpc/client-key.pem"

		Convey("Given client connects with mTLS, it should work", func() {
			g, err := NewGRPC(authOpts, log.DebugLevel)
			c.So(err, ShouldBeNil)
			c.So(g, ShouldNotBeNil)
		})
	})
}
