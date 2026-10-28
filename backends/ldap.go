package backends

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/iegomez/mosquitto-go-auth/backends/topics"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type LDAPClientFactory func(LDAP) (LDAPClient, error)

type LDAPClient interface {
	Close() error
	Bind(username, password string) error
	Search(request *ldap.SearchRequest) (*ldap.SearchResult, error)
}

type LDAP struct {
	factory                  LDAPClientFactory
	client                   LDAPClient
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
		ldapClient, err := ldap.DialURL(l.Url, ldapDialOpts(l)...)
		return ldapClient, err
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

	//Exit if any mandatory option is missing.
	if !ldapOk {
		return &l, errors.Errorf("LDAP backend error: missing options:%s", missingOptions)
	}

	// Connect to the LDAP server and bind with the provided credentials.
	err := l.reconnectLDAP()

	return &l, err
}

func (l *LDAP) reconnectLDAP() error {

	if l.client != nil {
		log.Debugf("Reconnecting to LDAP server")

		l.Halt()
	}

	log.Debugf("Connecting to LDAP server at %s", l.Url)

	ldapClient, err := l.factory(*l)

	if err != nil {
		log.Errorf("LDAP connection error: %s", err)

		return err
	}

	l.client = ldapClient

	err = l.client.Bind(l.BindDN, l.BindPass)

	if err != nil {
		log.Errorf("LDAP bind error: %s", err)

		closeErr := l.client.Close()

		if closeErr != nil {
			log.Errorf("LDAP cleanup error: %s", closeErr)
		}

		return err
	}

	return nil
}

func (l *LDAP) GetUser(username, password, clientid string) (bool, error) {

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

	searchResult, err := l.client.Search(searchRequest)

	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			log.Debugf("LDAP user search returned no such object (code 32)")

			return false, nil
		}

		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.ErrorNetwork {
			_ = l.reconnectLDAP()
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

	userLdapClient, err := l.factory(*l)

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
		log.Errorf("LDAP user bind error: %s", err)

		return false, nil
	}

	return true, nil
}

func (l *LDAP) GetSuperuser(username string) (bool, error) {

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

	searchResult, err := l.client.Search(searchRequest)

	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			log.Debugf("LDAP superuser search returned no such object (code 32)")

			return false, nil
		}

		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.ErrorNetwork {
			_ = l.reconnectLDAP()
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

	searchResult, err := l.client.Search(searchRequest)

	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			log.Debugf("LDAP acl search returned no such object (code 32)")

			return false, nil
		}

		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.ErrorNetwork {
			_ = l.reconnectLDAP()
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

// Halt closes the ldap connection.
func (l *LDAP) Halt() {

	if l.client != nil {
		err := l.client.Close()

		if err != nil {
			log.Errorf("LDAP cleanup error: %s", err)
		}

		l.client = nil
	}
}
