package backends

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/iegomez/mosquitto-go-auth/backends/topics"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ldapDefaultTimeout bounds the connect and the wait for the response of each bind and each search
// (ldap_timeout, in seconds).
const ldapDefaultTimeout = 10 * time.Second

var errLDAPHalted = errors.New("LDAP backend is halted")

// ldapState is owned by pointer: a copy of LDAP (the factory gets one) never copies the lock.
// mu serializes the use of the shared service connection, its reconnect and Halt.
type ldapState struct {
	mu     sync.Mutex
	client LDAPClient
	halted bool
}

type LDAPClientFactory func(LDAP) (LDAPClient, error)

type LDAPClient interface {
	Close() error
	Bind(username, password string) error
	Search(request *ldap.SearchRequest) (*ldap.SearchResult, error)
}

type LDAP struct {
	factory                  LDAPClientFactory
	state                    *ldapState
	Timeout                  time.Duration // each bind and each search, 0: no limit
	DialTimeout              time.Duration // the connect, 0: no limit
	Url                      string
	UserDN                   string
	GroupDN                  string
	BindDN                   string
	BindPass                 string
	UserFilter               string
	GroupFilter              string
	SuperuserFilter          string
	AclTopicPatternAttribute string
	AclAccAttribute          string
	hideToken                bool // a jwt backend is configured: the username can be a token
	rootCAs                  *x509.CertPool
}

func NewLDAP(authOpts map[string]string, logLevel log.Level) (*LDAP, error) {

	l, err := NewLDAPWithFactory(authOpts, logLevel, func(l LDAP) (LDAPClient, error) {
		// The TLS options (ldap_ca_cert) and the dial timeout (ldap_timeout). The dialer is always
		// set: without it, go-ldap uses its own limit of 60 seconds, also for ldap_timeout 0.
		opts := append(ldapDialOpts(l), ldap.DialWithDialer(&net.Dialer{Timeout: l.DialTimeout}))
		conn, err := ldap.DialURL(l.Url, opts...)
		if err != nil {
			// Return a nil interface, not a nil *ldap.Conn.
			return nil, err
		}
		conn.SetTimeout(l.Timeout)
		return conn, nil
	})

	return l, err
}

// ldapDialOpts returns the dial options for the connection to the server.
// With ldap_ca_cert, an ldaps:// connection trusts the system CAs and the CAs in that file.
func ldapDialOpts(l LDAP) []ldap.DialOpt {
	if l.rootCAs == nil {
		return nil
	}
	u, err := url.Parse(l.Url)
	if err != nil {
		return nil
	}
	return []ldap.DialOpt{ldap.DialWithTLSConfig(&tls.Config{ServerName: u.Hostname(), RootCAs: l.rootCAs})}
}

// loadLDAPRootCAs reads ldap_ca_cert: a PEM file with CA certificates. It returns the system pool
// with these certificates added.
func loadLDAPRootCAs(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("LDAP backend error: ldap_ca_cert: the file cannot be read")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("LDAP backend error: ldap_ca_cert: the file has no PEM certificate")
	}
	return pool, nil
}

func NewLDAPWithFactory(authOpts map[string]string, logLevel log.Level, ldapClientFactory LDAPClientFactory) (*LDAP, error) {

	log.SetLevel(logLevel)

	ldapOk := true
	missingOptions := ""

	var l = LDAP{
		factory:                  ldapClientFactory,
		state:                    &ldapState{},
		Timeout:                  ldapDefaultTimeout,
		DialTimeout:              ldapDefaultTimeout,
		Url:                      "ldap://localhost:389",
		GroupDN:                  "",
		GroupFilter:              "(member=%s)",
		SuperuserFilter:          "",
		AclTopicPatternAttribute: "",
		AclAccAttribute:          "",
	}

	if host, ok := authOpts["ldap_url"]; ok {
		l.Url = host
	}

	if caPath := authOpts["ldap_ca_cert"]; caPath != "" {
		if !strings.HasPrefix(strings.ToLower(l.Url), "ldaps://") {
			// There is no StartTLS: with another URL the passwords would go in plaintext.
			return &l, errors.New("LDAP backend error: ldap_ca_cert is set, but ldap_url is not an ldaps:// URL")
		}
		pool, err := loadLDAPRootCAs(caPath)
		if err != nil {
			return &l, err
		}
		l.rootCAs = pool
	}

	if baseDN, ok := authOpts["ldap_user_dn"]; ok {
		l.UserDN = baseDN
	} else {
		ldapOk = false
		missingOptions += " ldap_user_dn"
	}

	if groupBaseDN, ok := authOpts["ldap_group_dn"]; ok {
		l.GroupDN = groupBaseDN
	}

	if bindDN, ok := authOpts["ldap_bind_dn"]; ok {
		l.BindDN = bindDN
	} else {
		ldapOk = false
		missingOptions += " ldap_bind_dn"
	}

	if bindPass, ok := authOpts["ldap_bind_password"]; ok {
		l.BindPass = bindPass
	} else {
		ldapOk = false
		missingOptions += " ldap_bind_password"
	}

	if userFilter, ok := authOpts["ldap_user_filter"]; ok {
		l.UserFilter = userFilter
	} else {
		ldapOk = false
		missingOptions += " ldap_user_filter"
	}

	if groupFilter, ok := authOpts["ldap_group_filter"]; ok {
		l.GroupFilter = groupFilter
	}

	if superuserFilter, ok := authOpts["ldap_superuser_filter"]; ok {
		l.SuperuserFilter = superuserFilter
	}

	if aclTopicPatternAttribute, ok := authOpts["ldap_acl_topic_pattern_attribute"]; ok {
		l.AclTopicPatternAttribute = aclTopicPatternAttribute
	}

	if aclAccAttribute, ok := authOpts["ldap_acl_acc_attribute"]; ok {
		l.AclAccAttribute = aclAccAttribute
	}

	// ldap_timeout: seconds for the connect and for the wait for the response of each bind and each
	// search (0: no limit for both). A write that blocks is not bounded.
	if v, ok := authOpts["ldap_timeout"]; ok {
		if secs, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && secs >= 0 && secs <= math.MaxInt64/int64(time.Second) {
			l.Timeout = time.Duration(secs) * time.Second
			l.DialTimeout = l.Timeout
		} else {
			log.Warnf("option ldap_timeout must be a number of seconds (0 or more) in the range of a duration, the default (%d) is used", int(ldapDefaultTimeout/time.Second))
		}
	}

	//Exit if any mandatory option is missing.
	if !ldapOk {
		return &l, errors.Errorf("LDAP backend error: missing options:%s", missingOptions)
	}

	// Connect to the LDAP server and bind with the provided credentials.
	l.state.mu.Lock()
	err := l.connectLocked()
	l.state.mu.Unlock()

	return &l, err
}

// factoryConfig is the copy of the backend that the factory gets. It has no live state.
func (l *LDAP) factoryConfig() LDAP {
	c := *l
	c.state = nil

	return c
}

// closeLocked closes the service connection. The caller holds state.mu.
func (l *LDAP) closeLocked() {
	if l.state.client != nil {
		if err := l.state.client.Close(); err != nil {
			log.Errorf("LDAP cleanup error: %s", err)
		}

		l.state.client = nil
	}
}

// connectLocked replaces the service connection with a new one bound as the service account.
// The caller holds state.mu. After an error there is no service connection.
func (l *LDAP) connectLocked() error {

	if l.state.client != nil {
		log.Debugf("Reconnecting to LDAP server")

		l.closeLocked()
	}

	log.Debugf("Connecting to LDAP server at %s", l.Url)

	ldapClient, err := l.factory(l.factoryConfig())

	if err != nil {
		log.Errorf("LDAP connection error: %s", err)

		return err
	}

	err = ldapClient.Bind(l.BindDN, l.BindPass)

	if err != nil {
		log.Errorf("LDAP bind error: %s", err)

		if closeErr := ldapClient.Close(); closeErr != nil {
			log.Errorf("LDAP cleanup error: %s", closeErr)
		}

		return err
	}

	l.state.client = ldapClient

	return nil
}

// isLDAPNetworkError tells a failed or closed connection (also a plain socket error that
// go-ldap does not wrap) from an answer of the server.
func isLDAPNetworkError(err error) bool {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return ldapErr.ResultCode == ldap.ErrorNetwork
	}

	var netErr net.Error

	// go-ldap v3 builds a failed write as a plain error with fmt.Errorf("unable to send request: %s"),
	// so the cause is lost and the connection is not always closing yet. Only the prefix is left.
	return errors.As(err, &netErr) ||
		strings.HasPrefix(err.Error(), "unable to send request: ") ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed)
}

// isClosing tells if the client is a connection that the library closed. go-ldap returns some
// transport failures (for example "unable to read LDAP response packet") as plain errors.
func isClosing(c LDAPClient) bool {
	cc, ok := c.(interface{ IsClosing() bool })
	return ok && cc.IsClosing()
}

// isLDAPCredentialError is true for a result of the user bind that refuses the login: a wrong
// user or password, but also a refusal such as a locked account or a password policy
// (constraintViolation, inappropriateAuthentication, insufficientAccessRights). busy,
// unavailable and unwillingToPerform stay errors: a short directory problem must not cache a
// denial. Any other error is not a decision: GetUser returns it, so that nothing caches a denial.
func isLDAPCredentialError(err error) bool {
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		return false
	}

	switch ldapErr.ResultCode {
	case ldap.LDAPResultInvalidCredentials, ldap.LDAPResultNoSuchObject, ldap.LDAPResultInvalidDNSyntax, ldap.ErrorEmptyPassword,
		ldap.LDAPResultConstraintViolation, ldap.LDAPResultInappropriateAuthentication, ldap.LDAPResultInsufficientAccessRights:
		return true
	}

	return false
}

// checkNotHalted fails closed after Halt. Each request calls it first, before any shortcut.
func (l *LDAP) checkNotHalted() error {
	l.state.mu.Lock()
	defer l.state.mu.Unlock()

	if l.state.halted {
		return errLDAPHalted
	}

	return nil
}

// search runs one search on the service connection. Searches, reconnects and Halt run one at a
// time. After a network error the connection is replaced once and the search runs again.
func (l *LDAP) search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {

	l.state.mu.Lock()
	defer l.state.mu.Unlock()

	if l.state.halted {
		return nil, errLDAPHalted
	}

	// A failed reconnect leaves no connection: connect again with the next request.
	if l.state.client == nil {
		if err := l.connectLocked(); err != nil {
			return nil, err
		}
	}

	result, err := l.state.client.Search(request)

	if err != nil && (isLDAPNetworkError(err) || isClosing(l.state.client)) {
		// The error text can hold the username, so the callers log it (redacted).
		log.Warn("LDAP search failed on the network: reconnecting and trying again")

		if rerr := l.connectLocked(); rerr != nil {
			return nil, err
		}

		return l.state.client.Search(request)
	}

	return result, err
}

func (l *LDAP) GetUser(username, password, clientid string) (bool, error) {

	if err := l.checkNotHalted(); err != nil {
		return false, err
	}

	searchRequest := ldap.NewSearchRequest(
		l.UserDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(l.UserFilter, ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	searchResult, err := l.search(searchRequest)

	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			log.Debugf("LDAP user search returned no such object (code 32)")

			return false, nil
		}

		err = hideToken(l.hideToken, err, username)
		log.Errorf("LDAP user search error: %s", err)
		return false, err
	}

	if len(searchResult.Entries) != 1 {
		log.Debugf("LDAP user search returned %d entries", len(searchResult.Entries))

		return false, nil
	}

	userDN := searchResult.Entries[0].DN

	userLdapClient, err := l.factory(l.factoryConfig())

	if err != nil {
		log.Errorf("LDAP user connection error: %s", err)

		return false, err
	}

	defer func(ldapClient LDAPClient) {
		err := ldapClient.Close()

		if err != nil {
			log.Errorf("LDAP user cleanup error: %s", err)
		}
	}(userLdapClient)

	err = userLdapClient.Bind(userDN, password)

	if err != nil {
		// Classify first: hideToken can replace the *ldap.Error and lose its result code.
		// Only a refusal is a denial. Any other error (a network error, also a plain one) is
		// returned, so that nothing caches a denial for it.
		if isLDAPCredentialError(err) {
			log.Debugf("LDAP user bind refused")

			return false, nil
		}

		err = hideToken(l.hideToken, err, username)
		log.Errorf("LDAP user bind error: %s", err)

		return false, err
	}

	return true, nil
}

func (l *LDAP) GetSuperuser(username string) (bool, error) {

	if err := l.checkNotHalted(); err != nil {
		return false, err
	}

	//If there's no superuser filter, return false.
	if l.SuperuserFilter == "" {
		return false, nil
	}

	searchRequest := ldap.NewSearchRequest(
		l.UserDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(l.SuperuserFilter, ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	searchResult, err := l.search(searchRequest)

	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			log.Debugf("LDAP superuser search returned no such object (code 32)")

			return false, nil
		}

		err = hideToken(l.hideToken, err, username)
		log.Errorf("LDAP superuser search error: %s", err)
		return false, err
	}

	if len(searchResult.Entries) != 1 {
		log.Debugf("LDAP superuser search returned %d entries", len(searchResult.Entries))

		return false, err
	}

	return true, nil
}

func (l *LDAP) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {

	if err := l.checkNotHalted(); err != nil {
		return false, err
	}

	attributes := []string{}

	if l.AclTopicPatternAttribute != "" {
		attributes = append(attributes, l.AclTopicPatternAttribute)
	}

	if l.AclAccAttribute != "" {
		attributes = append(attributes, l.AclAccAttribute)
	}

	//If there are no acl attributes defined, assume all privileges for all users.
	if len(attributes) == 0 {
		return true, nil
	}

	//If there is no groupBaseDN, return false.
	if l.GroupDN == "" {
		log.Errorf("ldap_group_base_dn not set, cannot check ACL")
		return false, nil
	}

	searchRequest := ldap.NewSearchRequest(
		l.GroupDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(l.GroupFilter, ldap.EscapeFilter(username)),
		attributes,
		nil,
	)

	searchResult, err := l.search(searchRequest)

	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			log.Debugf("LDAP acl search returned no such object (code 32)")

			return false, nil
		}

		err = hideToken(l.hideToken, err, username)
		log.Errorf("LDAP acl search error: %s", err)
		return false, err
	}

	if len(searchResult.Entries) == 0 {
		log.Debugf("LDAP acl search returned no entries")
	}

	// Iterate through the results and check for topic access
	for _, entry := range searchResult.Entries {
		// If there is an acc attribute, check if the access level matches.
		if l.AclAccAttribute != "" {
			accessStr := entry.GetAttributeValue(l.AclAccAttribute)

			if accessStr != "" {
				access, err := strconv.ParseInt(accessStr, 10, 32)

				if err != nil {
					log.Errorf("LDAP acl failed to parse %s as int32: %s", accessStr, err)

					continue
				}

				// Check if all bits in acc are present in access
				if int32(access)&acc != acc {
					continue
				}
			}
		}

		var topicPatterns []string

		if l.AclTopicPatternAttribute != "" {
			topicPatterns = entry.GetAttributeValues(l.AclTopicPatternAttribute)
		}

		// Check the access levels and topic patterns for a match
		for _, pattern := range topicPatterns {
			if topics.Match(pattern, topic) {
				return true, nil
			}
		}
	}

	// No matching topic pattern found
	return false, nil
}

// GetName returns the backend's name
func (l *LDAP) GetName() string {
	return "LDAP"
}

// Halt waits for the request that uses the service connection, closes it and stops the backend.
// Later requests fail with an error. It is safe to call more than once.
func (l *LDAP) Halt() {

	l.state.mu.Lock()
	defer l.state.mu.Unlock()

	l.state.halted = true
	l.closeLocked()
}
