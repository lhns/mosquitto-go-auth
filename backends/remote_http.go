package backends

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	h "net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	// maxRemoteBody is the largest response body that a remote check reads.
	maxRemoteBody = 1 << 20
	// maxRemoteRedirects is the largest number of redirects that are followed
	// when a follow_redirects option is true.
	maxRemoteRedirects = 3
	// maxRemoteDrain is the largest number of unread bytes that are discarded
	// before a body is closed, so the connection can be used again.
	maxRemoteDrain = 4096
)

var (
	errRemoteBodyTooLarge = errors.New("remote check: response body too large")
	errRemoteRedirect     = errors.New("remote check: redirect refused")
)

// parseBoolOption reads a "true" or "false" option. A missing option gives def.
// An invalid value gives def and a warning.
func parseBoolOption(authOpts map[string]string, name string, def bool) bool {
	switch v, ok := authOpts[name]; {
	case !ok:
		return def
	case v == "true":
		return true
	case v == "false":
		return false
	}
	log.Warnf("%s must be true or false; using %v", name, def)
	return def
}

// effectivePort is the port of u, or the default port of its scheme.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return defaultPort(u.Scheme)
}

// sameOrigin compares the scheme, the host name (case-insensitive) and the effective port.
func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

// newRemoteClient builds the client of a remote backend. With verifyPeer false the server
// certificate is not checked. With roots set, the server certificate is checked against roots.
// Redirects are not
// followed unless follow is true. A followed redirect stays within
// maxRemoteRedirects and no hop goes from https to http. It goes to the same
// origin as the first request, or from http to https on the same host name with
// port 443 or the port of the first request, or (same scheme) to a destination
// that hostOK accepts: the allowlist only adds destinations. The Authorization header of the first request goes only
// to an accepted host.
func newRemoteClient(timeout int, verifyPeer bool, roots *x509.CertPool, follow bool, hostOK func(*url.URL) bool) *h.Client {
	c := &h.Client{Timeout: time.Duration(timeout) * time.Second}
	if !verifyPeer {
		c.Transport = &h.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    100,
			IdleConnTimeout: 90 * time.Second,
		}
	} else if roots != nil {
		tr := h.DefaultTransport.(*h.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: roots}
		c.Transport = tr
	}
	if !follow {
		// The client parses the Location header before CheckRedirect runs, so a
		// bad Location would be a request error. Without the header the client
		// returns the 3xx response as it is.
		rt := c.Transport
		if rt == nil {
			rt = h.DefaultTransport
		}
		c.Transport = noRedirectTransport{rt}
	}
	c.CheckRedirect = func(req *h.Request, via []*h.Request) error {
		if !follow {
			return h.ErrUseLastResponse
		}
		first, prev := via[0], via[len(via)-1]
		upgrade := first.URL.Scheme == "http" && req.URL.Scheme == "https" &&
			strings.EqualFold(req.URL.Hostname(), first.URL.Hostname()) &&
			(effectivePort(req.URL) == "443" || effectivePort(req.URL) == effectivePort(first.URL))
		ok := sameOrigin(req.URL, first.URL) || upgrade ||
			hostOK != nil && req.URL.Scheme == first.URL.Scheme && hostOK(req.URL)
		downgrade := prev.URL.Scheme == "https" && req.URL.Scheme != "https"
		if len(via) > maxRemoteRedirects || !ok || downgrade {
			return errRemoteRedirect
		}
		if a := first.Header.Get("Authorization"); a != "" {
			// The host passed the checks above: it is the first host or an allowed host.
			req.Header.Set("Authorization", a)
		}
		return nil
	}
	return c
}

// noRedirectTransport removes the Location header of a 3xx response, so the
// client never processes a redirect.
type noRedirectTransport struct{ h.RoundTripper }

func (t noRedirectTransport) RoundTrip(r *h.Request) (*h.Response, error) {
	resp, err := t.RoundTripper.RoundTrip(r)
	if err == nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Header.Del("Location")
	}
	return resp, err
}

// doRemote sends req and returns the status code and the body. The body is read
// only for a 2xx status, and at most maxRemoteBody bytes are accepted: a longer
// body gives errRemoteBodyTooLarge. The response body is always closed.
func doRemote(c *h.Client, req *h.Request) (int, []byte, error) {
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() {
		_, _ = io.CopyN(io.Discard, resp.Body, maxRemoteDrain)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteBody+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if len(body) > maxRemoteBody {
		return resp.StatusCode, nil, errRemoteBodyTooLarge
	}
	return resp.StatusCode, body, nil
}
