package backends

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type LDAP struct {
	Conn            *ldap.Conn
	Url             string
	BaseDN          string
	BindDN          string
	BindPass        string
	UserFilter      string
	SuperuserFilter string
	AclFilter       string
}

func NewLDAP(authOpts map[string]string, logLevel log.Level) (LDAP, error) {

	log.SetLevel(logLevel)

	ldapOk := true
	missingOptions := ""

	var o = LDAP{
		Url:             "ldap://localhost:389",
		SuperuserFilter: "",
		AclFilter:       "",
	}

	if host, ok := authOpts["ldap_url"]; ok {
		o.Url = host
	}

	if baseDN, ok := authOpts["ldap_base_dn"]; ok {
		o.BaseDN = baseDN
	} else {
		ldapOk = false
		missingOptions += " ldap_base_dn"
	}

	if bindDN, ok := authOpts["ldap_bind_dn"]; ok {
		o.BindDN = bindDN
	} else {
		ldapOk = false
		missingOptions += " ldap_bind_dn"
	}

	if bindPass, ok := authOpts["ldap_bind_password"]; ok {
		o.BindPass = bindPass
	} else {
		ldapOk = false
		missingOptions += " ldap_bind_password"
	}

	if userFilter, ok := authOpts["ldap_user_filter"]; ok {
		o.UserFilter = userFilter
	} else {
		ldapOk = false
		missingOptions += " ldap_user_filter"
	}

	if superuserFilter, ok := authOpts["ldap_superuser_filter"]; ok {
		o.SuperuserFilter = superuserFilter
	}

	if aclFilter, ok := authOpts["ldap_acl_filter"]; ok {
		o.AclFilter = aclFilter
	}

	//Exit if any mandatory option is missing.
	if !ldapOk {
		return o, errors.Errorf("LDAP backend error: missing options:%s", missingOptions)
	}

	//Check if the LDAP server is reachable
	conn, err := ldap.DialURL(o.Url)
	if err != nil {
		log.Debugf("LDAP connection error: %s", err)
		return o, err
	}
	o.Conn = conn

	err = conn.Bind(o.BindDN, o.BindPass)
	if err != nil {
		log.Debugf("LDAP bind error: %s", err)
		return o, err
	}

	return o, nil
}

func (o LDAP) GetUser(username, password, clientid string) (bool, error) {

	searchRequest := ldap.NewSearchRequest(
		o.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(o.UserFilter, username),
		[]string{"dn"},
		nil,
	)

	searchResult, err := o.Conn.Search(searchRequest)
	if err != nil || len(searchResult.Entries) != 1 {
		log.Debugf("LDAP user search error: %s", err)
		return false, err
	}

	userDN := searchResult.Entries[0].DN

	userConn, err := ldap.DialURL(o.Url)
	if err != nil {
		log.Debugf("LDAP user connection error: %s", err)
		return false, err
	}
	defer func(userConn *ldap.Conn) {
		err := userConn.Close()
		if err != nil {
			log.Errorf("LDAP user cleanup error: %s", err)
		}
	}(userConn)

	err = userConn.Bind(userDN, password)
	if err != nil {
		log.Debugf("LDAP user bind error: %s", err)
		return false, err
	}

	return true, nil
}

func (o LDAP) GetSuperuser(username string) (bool, error) {

	//If there's no superuser filter, assume all privileges for all users.
	if o.SuperuserFilter == "" {
		return true, nil
	}

	searchRequest := ldap.NewSearchRequest(
		o.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(o.SuperuserFilter, username),
		[]string{"dn"},
		nil,
	)

	searchResult, err := o.Conn.Search(searchRequest)
	if err != nil || len(searchResult.Entries) != 1 {
		log.Debugf("LDAP superuser search error: %s", err)
		return false, err
	}

	return true, nil
}

func (o LDAP) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {

	//If there's no acl filter, assume all privileges for all users.
	if o.AclFilter == "" {
		return true, nil
	}

	searchRequest := ldap.NewSearchRequest(
		o.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(o.AclFilter, username, topic, acc),
		[]string{"dn"},
		nil,
	)

	searchResult, err := o.Conn.Search(searchRequest)
	if err != nil || len(searchResult.Entries) != 1 {
		log.Debugf("LDAP acl search error: %s", err)
		return false, err
	}

	return true, nil
}

// GetName returns the backend's name
func (b LDAP) GetName() string {
	return "LDAP"
}

// Halt closes the ldap connection.
func (o LDAP) Halt() {
	if o.Conn != nil {
		err := o.Conn.Close()
		if err != nil {
			log.Errorf("LDAP cleanup error: %s", err)
		}
	}
}
