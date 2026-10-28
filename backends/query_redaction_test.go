package backends

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	jwtGo "github.com/golang-jwt/jwt/v5"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/jmoiron/sqlx"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// echoDriver is a database driver whose every query fails with an error that quotes the arguments,
// as a driver does for a value it cannot convert.
type echoDriver struct{}

type echoConn struct{}

type echoStmt struct{}

func (echoDriver) Open(string) (driver.Conn, error) { return echoConn{}, nil }

func (echoConn) Prepare(string) (driver.Stmt, error) { return echoStmt{}, nil }
func (echoConn) Close() error                        { return nil }
func (echoConn) Begin() (driver.Tx, error)           { return nil, errors.New("no transactions") }

func (echoStmt) Close() error  { return nil }
func (echoStmt) NumInput() int { return -1 }
func (echoStmt) Exec(args []driver.Value) (driver.Result, error) {
	return nil, fmt.Errorf("invalid input syntax: %v", args)
}
func (echoStmt) Query(args []driver.Value) (driver.Rows, error) {
	return nil, fmt.Errorf("invalid input syntax: %v", args)
}

func init() { sql.Register("echo-redaction", echoDriver{}) }

func echoDB(t *testing.T) *sqlx.DB {
	t.Helper()
	db, err := sqlx.Open("echo-redaction", "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// sqlChecks runs the three checks of a backend and returns their errors.
func sqlChecks(b interface {
	GetUser(username, password, clientid string) (bool, error)
	GetSuperuser(username string) (bool, error)
	CheckAcl(username, topic, clientid string, acc int32) (bool, error)
}) []error {
	_, e1 := b.GetUser(remoteToken, "pw", "cid")
	_, e2 := b.GetSuperuser(remoteToken)
	_, e3 := b.CheckAcl(remoteToken, "t", "cid", 1)
	return []error{e1, e2, e3}
}

func TestSQLErrorsHideTokenWithJWT(t *testing.T) {
	for _, hidden := range []bool{true, false} {
		db := echoDB(t)
		for name, tc := range map[string]struct {
			b    func() []error
			text string
		}{
			"postgres": {func() []error {
				return sqlChecks(Postgres{DB: db, UserQuery: "q", SuperuserQuery: "q", AclQuery: "q", hideErrors: hidden})
			}, "postgres: query failed"},
			"mysql": {func() []error {
				return sqlChecks(Mysql{DB: db, UserQuery: "q", SuperuserQuery: "q", AclQuery: "q", hideErrors: hidden})
			}, "mysql: query failed"},
			"sqlite": {func() []error {
				return sqlChecks(Sqlite{DB: db, UserQuery: "q", SuperuserQuery: "q", AclQuery: "q", hideErrors: hidden})
			}, "sqlite: query failed"},
		} {
			t.Run(fmt.Sprintf("%s hidden=%t", name, hidden), func(t *testing.T) {
				var errs []error
				entries := logText(t, func() { errs = tc.b() })
				for _, err := range errs {
					requireErrorText(t, hidden, err, entries)
					if hidden {
						require.Equal(t, tc.text, err.Error())
					}
				}
			})
		}
	}
}

// The jwt backend option sets the flag that hides the text.
func TestJWTConfigured(t *testing.T) {
	require.True(t, jwtConfigured(map[string]string{"backends": "postgres, jwt"}))
	require.False(t, jwtConfigured(map[string]string{"backends": "postgres,files"}))
	require.False(t, jwtConfigured(map[string]string{}))
}

// The local JWT mode never shows the driver text of its own query.
func TestJWTLocalQueryErrorHasNoInput(t *testing.T) {
	const user = "SENTINEL-CLAIM-query"
	checker := &localJWTChecker{
		db:        postgresDB,
		postgres:  Postgres{DB: echoDB(t)},
		userQuery: "q",
		options:   tokenOptions{secret: []byte("secret"), userFieldKey: "username"},
	}
	token, err := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, jwtGo.MapClaims{
		"username": user, "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("secret"))
	require.NoError(t, err)

	var checkErr error
	entries := logText(t, func() { _, checkErr = checker.GetUser(token) })
	require.Error(t, checkErr)
	require.Equal(t, "jwt local: query failed", checkErr.Error())
	require.NotContains(t, entries, user)
}

// echoLDAPClient binds, and fails every search with a server message that quotes the filter.
type echoLDAPClient struct{}

func (echoLDAPClient) Close() error              { return nil }
func (echoLDAPClient) Bind(string, string) error { return nil }
func (echoLDAPClient) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return nil, ldap.NewError(ldap.LDAPResultOther, errors.New("bad filter "+r.Filter))
}

func TestLDAPErrorsHideTokenWithJWT(t *testing.T) {
	for list, hidden := range redactionBackendLists {
		t.Run(list, func(t *testing.T) {
			l, err := NewLDAPWithFactory(map[string]string{
				"backends":                         list,
				"ldap_url":                         "ldap://localhost:389",
				"ldap_user_dn":                     "ou=people,dc=example,dc=org",
				"ldap_group_dn":                    "ou=groups,dc=example,dc=org",
				"ldap_bind_dn":                     "cn=mosquitto,ou=people,dc=example,dc=org",
				"ldap_bind_password":               "pw",
				"ldap_user_filter":                 "(cn=%s)",
				"ldap_group_filter":                "(member=cn=%s,ou=people,dc=example,dc=org)",
				"ldap_superuser_filter":            "(cn=%s)",
				"ldap_acl_topic_pattern_attribute": "mqttTopicPattern",
				"ldap_acl_acc_attribute":           "mqttTopicAcc",
			}, log.GetLevel(), func(LDAP) (LDAPClient, error) { return echoLDAPClient{}, nil })
			require.NoError(t, err)
			t.Cleanup(l.Halt)

			var errs []error
			entries := logText(t, func() { errs = sqlChecks(l) })
			for _, err := range errs {
				requireErrorText(t, hidden, err, entries)
				if hidden {
					require.Equal(t, "ldap: search failed", err.Error())
				}
			}
		})
	}
}

// A real driver error quotes the input. This test needs the Postgres database of the test container.
func TestPostgresCastErrorHidesTokenWithJWT(t *testing.T) {
	opts := map[string]string{
		"backends":      "postgres,jwt",
		"pg_host":       "localhost",
		"pg_port":       "5432",
		"pg_sslmode":    "disable",
		"pg_dbname":     "go_auth_test",
		"pg_user":       "go_auth_test",
		"pg_password":   "go_auth_test",
		"pg_userquery":  "select password_hash from test_user where id = $1::integer",
		"pg_superquery": "select count(*) from test_user where id = $1::integer",
		"pg_aclquery":   "select topic from test_acl where test_user_id = $1::integer and rw >= $2",
	}
	pg, err := NewPostgres(opts, log.GetLevel(), hashing.NewHasher(opts, ""))
	require.NoError(t, err)
	t.Cleanup(pg.Halt)

	var errs []error
	entries := logText(t, func() { errs = sqlChecks(pg) })
	for _, err := range errs {
		requireErrorText(t, true, err, entries)
		require.Equal(t, "postgres: query failed", err.Error())
	}
}
