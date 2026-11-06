package backends

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	h "net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type HTTP struct {
	UserUri       string
	SuperuserUri  string
	AclUri        string
	UserAgent     string
	Host          string
	Port          string
	WithTLS       bool
	VerifyPeer    bool
	ParamsMode    string
	httpMethod    string
	ResponseMode  string
	Timeout       int
	Client        *h.Client
	CustomHeaders map[string]string
	hideToken     bool // a jwt backend is configured: the username can be a token
}

type HTTPResponse struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

func NewHTTP(authOpts map[string]string, logLevel log.Level, version string) (HTTP, error) {

	log.SetLevel(logLevel)

	//Initialize with defaults
	var http = HTTP{
		WithTLS:       false,
		VerifyPeer:    false,
		ResponseMode:  "status",
		ParamsMode:    "json",
		httpMethod:    h.MethodPost,
		CustomHeaders: map[string]string{},
	}

	missingOpts := ""
	httpOk := true

	if responseMode, ok := authOpts["http_response_mode"]; ok {
		if responseMode == "text" || responseMode == "json" {
			http.ResponseMode = responseMode
		}
	}

	if paramsMode, ok := authOpts["http_params_mode"]; ok {
		if paramsMode == "form" {
			http.ParamsMode = paramsMode
		}
	}

	if httpMethod, ok := authOpts["http_method"]; ok {
		switch httpMethod {
		case h.MethodGet, h.MethodPut:
			http.httpMethod = httpMethod
		}
	}

	if userUri, ok := authOpts["http_getuser_uri"]; ok {
		http.UserUri = userUri
	} else {
		httpOk = false
		missingOpts += " http_getuser_uri"
	}

	if superuserUri, ok := authOpts["http_superuser_uri"]; ok {
		http.SuperuserUri = superuserUri
	}

	if aclUri, ok := authOpts["http_aclcheck_uri"]; ok {
		http.AclUri = aclUri
	} else {
		httpOk = false
		missingOpts += " http_aclcheck_uri"
	}

	http.UserAgent = fmt.Sprintf("%s-%s", defaultUserAgent, version)
	if userAgent, ok := authOpts["http_user_agent"]; ok {
		http.UserAgent = userAgent
	}

	if host, ok := authOpts["http_host"]; ok {
		http.Host = host
	} else {
		httpOk = false
		missingOpts += " http_host"
	}

	if port, ok := authOpts["http_port"]; ok {
		http.Port = port
	} else {
		httpOk = false
		missingOpts += " http_port"
	}

	if withTLS, ok := authOpts["http_with_tls"]; ok && withTLS == "true" {
		http.WithTLS = true
	}

	if verifyPeer, ok := authOpts["http_verify_peer"]; ok && verifyPeer == "true" {
		http.VerifyPeer = true
	}

	http.Timeout = remoteTimeoutSeconds(authOpts, "http_timeout")

	for key, value := range authOpts {
		if strings.HasPrefix(key, "http_header_") && value != "" {
			headerName := strings.TrimPrefix(key, "http_header_")
			if headerName == "" {
				continue
			}
			http.CustomHeaders[headerName] = value
		}
	}

	if len(http.CustomHeaders) == 0 {
		http.CustomHeaders = nil
	}

	if !httpOk {
		return http, errors.Errorf("HTTP backend error: missing remote options: %s", missingOpts)
	}

	roots, err := remoteCAPool("http", http.WithTLS, http.VerifyPeer, authOpts["http_ca_cert"])
	if err != nil {
		return http, errors.Errorf("HTTP backend error: %s", err)
	}
	follow := parseBoolOption(authOpts, "http_follow_redirects", false)
	if follow {
		log.Warn("http_follow_redirects is true: the plugin follows redirects to the same host")
	}
	http.Client = newRemoteClient(http.Timeout, http.VerifyPeer, roots, follow, nil)

	return http, nil
}

// remoteCAPool handles the TLS options of a remote backend (opt is the option prefix, "http" or
// "jwt"). When TLS is on and verifyPeer is false, it logs a warning, and one more when a CA file is
// set, because the file has no effect. When TLS is on and a CA file is set, the file must hold at
// least one valid PEM certificate. With verifyPeer true the result is the system pool plus the
// certificates of the file. It is nil when no CA file is used.
func remoteCAPool(opt string, withTLS, verifyPeer bool, caPath string) (*x509.CertPool, error) {
	if !withTLS {
		return nil, nil
	}
	var pool *x509.CertPool
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, errors.Errorf("%s_ca_cert: the file cannot be read", opt)
		}
		if pool, err = x509.SystemCertPool(); err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.Errorf("%s_ca_cert: the file has no valid PEM certificate", opt)
		}
	}
	if !verifyPeer {
		log.Warnf("%s_with_tls is true and %s_verify_peer is false: the plugin does not check the server certificate. "+
			"Set %s_verify_peer to true (and %s_ca_cert for a private CA).", opt, opt, opt, opt)
		if caPath != "" {
			log.Warnf("%s_ca_cert has no effect until %s_verify_peer is true", opt, opt)
		}
		return nil, nil
	}
	return pool, nil
}

// defaultRemoteTimeout is the timeout of a remote HTTP request in seconds (http_timeout,
// jwt_http_timeout).
const defaultRemoteTimeout = 5

// remoteTimeoutSeconds reads a request timeout in seconds. A value that is not a number gives an
// error log and the default, as before. A value of 0 or less gives a warning and the default: a
// request must not wait without a limit.
func remoteTimeoutSeconds(authOpts map[string]string, name string) int {
	v, ok := authOpts[name]
	if !ok {
		return defaultRemoteTimeout
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Errorf("unable to parse timeout: %s", err)
		return defaultRemoteTimeout
	}
	if n <= 0 || time.Duration(n) > time.Duration(1<<63-1)/time.Second {
		log.Warnf("option %s must be a number of seconds above 0 and in the range of a duration, the default (%d) is used", name, defaultRemoteTimeout)
		return defaultRemoteTimeout
	}
	return n
}

func (o HTTP) GetUser(username, password, clientid string) (bool, error) {

	var dataMap = map[string]interface{}{
		"username": username,
		"password": password,
		"clientid": clientid,
	}

	var urlValues = url.Values{
		"username": []string{username},
		"password": []string{password},
		"clientid": []string{clientid},
	}

	return o.httpRequest(o.UserUri, username, dataMap, urlValues)

}

func (o HTTP) GetSuperuser(username string) (bool, error) {

	if o.SuperuserUri == "" {
		return false, nil
	}

	var dataMap = map[string]interface{}{
		"username": username,
	}

	var urlValues = url.Values{
		"username": []string{username},
	}

	return o.httpRequest(o.SuperuserUri, username, dataMap, urlValues)

}

func (o HTTP) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {

	dataMap := map[string]interface{}{
		"username": username,
		"clientid": clientid,
		"topic":    topic,
		"acc":      acc,
	}

	var urlValues = url.Values{
		"username": []string{username},
		"clientid": []string{clientid},
		"topic":    []string{topic},
		"acc":      []string{strconv.Itoa(int(acc))},
	}

	return o.httpRequest(o.AclUri, username, dataMap, urlValues)

}

func (o HTTP) httpRequest(uri, username string, dataMap map[string]interface{}, urlValues url.Values) (bool, error) {

	// Don't do the request if the client is nil.
	if o.Client == nil {
		return false, errors.New("http client not initialized")
	}

	tlsStr := "http://"

	if o.WithTLS {
		tlsStr = "https://"
	}

	fullUri := fmt.Sprintf("%s%s%s", tlsStr, o.Host, uri)
	if o.Port != "" {
		fullUri = fmt.Sprintf("%s%s:%s%s", tlsStr, o.Host, o.Port, uri)
	}

	var err error
	var req *h.Request

	if o.ParamsMode == "form" {
		if o.httpMethod != h.MethodPost && o.httpMethod != h.MethodPut {
			log.Errorf("error form param only supported for POST/PUT.")
			err = fmt.Errorf("form only supported for POST/PUT, error code: %d", 500)
			return false, err
		}

		formEncoded := urlValues.Encode()
		req, err = h.NewRequest(o.httpMethod, fullUri, strings.NewReader(formEncoded))

		if err != nil {
			log.Errorf("req error: %s", err)
			return false, err
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		var dataJson []byte
		dataJson, err = json.Marshal(dataMap)

		if err != nil {
			log.Errorf("marshal error: %s", err)
			return false, err
		}

		req, err = h.NewRequest(o.httpMethod, fullUri, bytes.NewReader(dataJson))

		if err != nil {
			log.Errorf("req error: %s", err)
			return false, err
		}

		req.Header.Set("Content-Type", "application/json")
	}

	req.Header.Set("User-Agent", o.UserAgent)

	for header, value := range o.CustomHeaders {
		req.Header.Set(header, value)
	}

	status, body, err := doRemote(o.Client, req)

	if err != nil {
		err = hideToken(o.hideToken, err, username)
		log.Errorf("http request error: %s", err)
		return false, err
	}

	if status < 200 || status >= 300 {
		log.Infof("error code: %d", status)
		if status >= 500 {
			err = fmt.Errorf("error code: %d", status)
		}
		return false, err
	}

	if o.ResponseMode == "text" {

		//For test response, we expect "ok" or an error message.
		if string(body) != "ok" {
			o.logAPIError(string(body), status)
			return false, nil
		}

	} else if o.ResponseMode == "json" {

		//For json response, we expect Ok and Error fields.
		response := HTTPResponse{Ok: false, Error: ""}
		err := json.Unmarshal(body, &response)

		if err != nil {
			log.Errorf("unmarshal error: %s", err)
			return false, err
		}

		if !response.Ok {
			o.logAPIError(response.Error, status)
			return false, nil
		}

	}

	log.Debugf("http request approved for %s", logUsername(o.hideToken, username))
	return true, nil

}

// logAPIError logs the denial text of the server. With a jwt backend it can echo the username or
// the password in any form, so only the status is logged.
func (o HTTP) logAPIError(text string, status int) {
	if o.hideToken {
		log.Infof("api error: status %d", status)
		return
	}
	log.Infof("api error: %s", text)
}

// GetName returns the backend's name
func (o HTTP) GetName() string {
	return "HTTP"
}

// Halt does nothing for http as there's no cleanup needed.
func (o HTTP) Halt() {
	//Do nothing
}
