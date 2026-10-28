//go:build integration

package backends

import (
	"testing"

	. "github.com/iegomez/mosquitto-go-auth/backends/constants"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

func TestLocalPostgresJWT(t *testing.T) {

	Convey("Creating a token should return a nil error", t, func() {
		token, err := jwtToken.SignedString(jwtSecret)
		So(err, ShouldBeNil)

		// Initialize JWT in local mode.
		authOpts := make(map[string]string)
		authOpts["jwt_mode"] = "local"
		authOpts["jwt_db"] = "postgres"
		authOpts["jwt_secret"] = string(jwtSecret)
		authOpts["jwt_userfield"] = "Username"
		authOpts["jwt_userquery"] = "select count(*) from test_user where username = $1 limit 1"

		// Give necessary postgres options.
		authOpts["jwt_pg_host"] = "localhost"
		authOpts["jwt_pg_port"] = "5432"
		authOpts["jwt_pg_sslmode"] = "disable"
		authOpts["jwt_pg_dbname"] = "go_auth_test"
		authOpts["jwt_pg_user"] = "go_auth_test"
		authOpts["jwt_pg_password"] = "go_auth_test"
		authOpts["jwt_pg_superquery"] = "select count(*) from test_user where username = $1 and is_admin = true"
		authOpts["jwt_pg_aclquery"] = "SELECT test_acl.topic FROM test_acl, test_user WHERE test_user.username = $1 AND test_acl.test_user_id = test_user.id AND rw >= $2"

		// Set regular PG options just to create a PG instance and create the records.

		pgAuthOpts := make(map[string]string)
		pgAuthOpts["pg_host"] = "localhost"
		pgAuthOpts["pg_port"] = "5432"
		pgAuthOpts["pg_sslmode"] = "disable"
		pgAuthOpts["pg_dbname"] = "go_auth_test"
		pgAuthOpts["pg_user"] = "go_auth_test"
		pgAuthOpts["pg_password"] = "go_auth_test"
		pgAuthOpts["pg_userquery"] = "mock"
		pgAuthOpts["pg_superquery"] = "mock"
		pgAuthOpts["pg_aclquery"] = "mock"

		db, err := NewPostgres(pgAuthOpts, log.DebugLevel, hashing.NewHasher(pgAuthOpts, ""))
		So(err, ShouldBeNil)

		Convey("Given correct option NewJWT returns an instance of jwt backend", func() {
			jwt, err := NewLocalJWTChecker(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""), tkOptions)
			So(err, ShouldBeNil)

			//Empty db
			db.DB.MustExec("delete from test_user where 1 = 1")
			db.DB.MustExec("delete from test_acl where 1 = 1")

			//Now test everything.

			insertQuery := "INSERT INTO test_user(username, password_hash, is_admin) values($1, $2, $3) returning id"

			userID := 0

			err = db.DB.Get(&userID, insertQuery, username, userPassHash, true)

			So(err, ShouldBeNil)
			So(userID, ShouldBeGreaterThan, 0)

			Convey("Given a correct token, it should correctly authenticate it", func() {

				authenticated, err := jwt.GetUser(token)
				So(err, ShouldBeNil)
				So(authenticated, ShouldBeTrue)
			})

			Convey("Given an incorrect token, it should not authenticate it", func() {

				wrongToken, err := wrongJwtToken.SignedString(jwtSecret)
				So(err, ShouldBeNil)

				authenticated, err := jwt.GetUser(wrongToken)
				So(err, ShouldBeNil)
				So(authenticated, ShouldBeFalse)

			})

			Convey("Given a token that is admin, super user should pass", func() {
				superuser, err := jwt.GetSuperuser(token)
				So(err, ShouldBeNil)
				So(superuser, ShouldBeTrue)

				Convey("But disabling superusers by removing superuri should now return false", func() {
					authOpts["jwt_pg_superquery"] = ""
					jwt, err := NewLocalJWTChecker(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""), tkOptions)
					So(err, ShouldBeNil)

					superuser, err := jwt.GetSuperuser(token)
					So(err, ShouldBeNil)
					So(superuser, ShouldBeFalse)
				})
			})

			//Now create some acls and test topics

			strictACL := "test/topic/1"
			singleLevelACL := "test/topic/+"
			hierarchyACL := "test/#"

			clientID := "test_client"

			aclID := 0
			aclQuery := "INSERT INTO test_acl(test_user_id, topic, rw) values($1, $2, $3) returning id"
			err = db.DB.Get(&aclID, aclQuery, userID, strictACL, MOSQ_ACL_READ)
			So(err, ShouldBeNil)

			Convey("Given only strict acl in db, an exact match should work and and inexact one not", func() {

				testTopic1 := `test/topic/1`
				testTopic2 := `test/topic/2`

				tt1, err1 := jwt.CheckAcl(token, testTopic1, clientID, MOSQ_ACL_READ)
				tt2, err2 := jwt.CheckAcl(token, testTopic2, clientID, MOSQ_ACL_READ)

				So(err1, ShouldBeNil)
				So(err2, ShouldBeNil)
				So(tt1, ShouldBeTrue)
				So(tt2, ShouldBeFalse)

			})

			Convey("Given read only privileges, a pub check should fail", func() {

				testTopic1 := "test/topic/1"
				tt1, err1 := jwt.CheckAcl(token, testTopic1, clientID, MOSQ_ACL_WRITE)
				So(err1, ShouldBeNil)
				So(tt1, ShouldBeFalse)

			})

			Convey("Given wildcard subscriptions against strict db acl, acl checks should fail", func() {

				tt1, err1 := jwt.CheckAcl(token, singleLevelACL, clientID, MOSQ_ACL_READ)
				tt2, err2 := jwt.CheckAcl(token, hierarchyACL, clientID, MOSQ_ACL_READ)

				So(err1, ShouldBeNil)
				So(err2, ShouldBeNil)
				So(tt1, ShouldBeFalse)
				So(tt2, ShouldBeFalse)

			})

			//Now insert single level topic to check against.

			err = db.DB.Get(&aclID, aclQuery, userID, singleLevelACL, MOSQ_ACL_READ)
			So(err, ShouldBeNil)

			Convey("Given a topic not strictly present that matches a db single level wildcard, acl check should pass", func() {
				tt1, err1 := jwt.CheckAcl(token, "test/topic/whatever", clientID, MOSQ_ACL_READ)
				So(err1, ShouldBeNil)
				So(tt1, ShouldBeTrue)
			})

			//Now insert hierarchy wildcard to check against.

			err = db.DB.Get(&aclID, aclQuery, userID, hierarchyACL, MOSQ_ACL_READ)
			So(err, ShouldBeNil)

			Convey("Given a topic not strictly present that matches a hierarchy wildcard, acl check should pass", func() {
				tt1, err1 := jwt.CheckAcl(token, "test/what/ever", clientID, MOSQ_ACL_READ)
				So(err1, ShouldBeNil)
				So(tt1, ShouldBeTrue)
			})

			Convey("Deleting superuser and acl queries should work fine", func() {

				authOpts["jwt_pg_superquery"] = ""
				authOpts["jwt_pg_aclquery"] = ""

				jwt, err := NewLocalJWTChecker(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""), tkOptions)
				So(err, ShouldBeNil)

				Convey("So checking against them should give false and true for any user", func() {

					tt1, err1 := jwt.CheckAcl(token, singleLevelACL, clientID, MOSQ_ACL_READ)
					tt2, err2 := jwt.CheckAcl(token, hierarchyACL, clientID, MOSQ_ACL_READ)

					So(err1, ShouldBeNil)
					So(err2, ShouldBeNil)
					So(tt1, ShouldBeTrue)
					So(tt2, ShouldBeTrue)

					superuser, err := jwt.GetSuperuser(token)
					So(err, ShouldBeNil)
					So(superuser, ShouldBeFalse)

				})

			})

			//Empty db
			db.DB.MustExec("delete from test_user where 1 = 1")
			db.DB.MustExec("delete from test_acl where 1 = 1")

			jwt.Halt()
		})

	})

}

func TestLocalMysqlJWT(t *testing.T) {

	Convey("Creating a token should return a nil error", t, func() {
		token, err := jwtToken.SignedString(jwtSecret)
		So(err, ShouldBeNil)

		// Initialize JWT in local mode.
		authOpts := make(map[string]string)
		authOpts["jwt_mode"] = "local"
		authOpts["jwt_db"] = "mysql"
		authOpts["jwt_secret"] = string(jwtSecret)
		authOpts["jwt_userfield"] = "Username"
		authOpts["jwt_userquery"] = "select count(*) from test_user where username = ? limit 1"

		// Give necessary postgres options.
		authOpts["jwt_mysql_host"] = "localhost"
		authOpts["jwt_mysql_port"] = "3306"
		authOpts["jwt_mysql_dbname"] = "go_auth_test"
		authOpts["jwt_mysql_user"] = "go_auth_test"
		authOpts["jwt_mysql_password"] = "go_auth_test"
		authOpts["jwt_mysql_allow_native_passwords"] = "true"
		authOpts["jwt_mysql_superquery"] = "select count(*) from test_user where username = ? and is_admin = true"
		authOpts["jwt_mysql_aclquery"] = "SELECT test_acl.topic FROM test_acl, test_user WHERE test_user.username = ? AND test_acl.test_user_id = test_user.id AND rw >= ?"

		// Set options for our MySQL instance used to create test records.
		mysqlAuthOpts := make(map[string]string)
		mysqlAuthOpts["mysql_host"] = "localhost"
		mysqlAuthOpts["mysql_port"] = "3306"
		mysqlAuthOpts["mysql_dbname"] = "go_auth_test"
		mysqlAuthOpts["mysql_user"] = "go_auth_test"
		mysqlAuthOpts["mysql_password"] = "go_auth_test"
		mysqlAuthOpts["mysql_allow_native_passwords"] = "true"
		mysqlAuthOpts["mysql_userquery"] = "mock"
		mysqlAuthOpts["mysql_superquery"] = "mock"
		mysqlAuthOpts["mysql_aclquery"] = "mock"

		db, err := NewMysql(mysqlAuthOpts, log.DebugLevel, hashing.NewHasher(mysqlAuthOpts, ""))
		So(err, ShouldBeNil)

		Convey("Given correct option NewJWT returns an instance of jwt backend", func() {
			jwt, err := NewLocalJWTChecker(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""), tkOptions)
			So(err, ShouldBeNil)

			//Empty db
			db.DB.MustExec("delete from test_user where 1 = 1")
			db.DB.MustExec("delete from test_acl where 1 = 1")

			//Now test everything.

			insertQuery := "INSERT INTO test_user(username, password_hash, is_admin) values(?, ?, ?)"

			userID := int64(0)

			res, err := db.DB.Exec(insertQuery, username, userPassHash, true)
			So(err, ShouldBeNil)

			userID, err = res.LastInsertId()

			So(err, ShouldBeNil)
			So(userID, ShouldBeGreaterThan, 0)

			Convey("Given a correct token, it should correctly authenticate it", func() {

				authenticated, err := jwt.GetUser(token)
				So(err, ShouldBeNil)
				So(authenticated, ShouldBeTrue)

			})

			Convey("Given an incorrect token, it should not authenticate it", func() {

				wrongToken, err := wrongJwtToken.SignedString(jwtSecret)
				So(err, ShouldBeNil)

				authenticated, err := jwt.GetUser(wrongToken)
				So(err, ShouldBeNil)
				So(authenticated, ShouldBeFalse)

			})

			Convey("Given a token that is admin, super user should pass", func() {
				superuser, err := jwt.GetSuperuser(token)
				So(err, ShouldBeNil)
				So(superuser, ShouldBeTrue)
				Convey("But disabling superusers by removing superuri should now return false", func() {
					authOpts["jwt_mysql_superquery"] = ""
					jwt, err := NewLocalJWTChecker(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""), tkOptions)
					So(err, ShouldBeNil)

					superuser, err := jwt.GetSuperuser(token)
					So(err, ShouldBeNil)
					So(superuser, ShouldBeFalse)
				})
			})

			strictACL := "test/topic/1"
			singleLevelACL := "test/topic/+"
			hierarchyACL := "test/#"

			clientID := "test_client"

			aclID := int64(0)
			aclQuery := "INSERT INTO test_acl(test_user_id, topic, rw) values(?, ?, ?)"
			res, err = db.DB.Exec(aclQuery, userID, strictACL, MOSQ_ACL_READ)
			So(err, ShouldBeNil)
			aclID, err = res.LastInsertId()
			So(err, ShouldBeNil)
			So(aclID, ShouldBeGreaterThan, 0)

			Convey("Given only strict acl in db, an exact match should work and and inexact one not", func() {

				testTopic1 := `test/topic/1`
				testTopic2 := `test/topic/2`

				tt1, err1 := jwt.CheckAcl(token, testTopic1, clientID, MOSQ_ACL_READ)
				tt2, err2 := jwt.CheckAcl(token, testTopic2, clientID, MOSQ_ACL_READ)

				So(err1, ShouldBeNil)
				So(err2, ShouldBeNil)
				So(tt1, ShouldBeTrue)
				So(tt2, ShouldBeFalse)

			})

			Convey("Given read only privileges, a pub check should fail", func() {

				testTopic1 := "test/topic/1"
				tt1, err1 := jwt.CheckAcl(token, testTopic1, clientID, MOSQ_ACL_WRITE)
				So(err1, ShouldBeNil)
				So(tt1, ShouldBeFalse)

			})

			Convey("Given wildcard subscriptions against strict db acl, acl checks should fail", func() {

				tt1, err1 := jwt.CheckAcl(token, singleLevelACL, clientID, MOSQ_ACL_READ)
				tt2, err2 := jwt.CheckAcl(token, hierarchyACL, clientID, MOSQ_ACL_READ)

				So(err1, ShouldBeNil)
				So(err2, ShouldBeNil)
				So(tt1, ShouldBeFalse)
				So(tt2, ShouldBeFalse)

			})

			//Now insert single level topic to check against.

			_, err = db.DB.Exec(aclQuery, userID, singleLevelACL, MOSQ_ACL_READ)
			So(err, ShouldBeNil)

			Convey("Given a topic not strictly present that matches a db single level wildcard, acl check should pass", func() {
				tt1, err1 := jwt.CheckAcl(token, "test/topic/whatever", clientID, MOSQ_ACL_READ)
				So(err1, ShouldBeNil)
				So(tt1, ShouldBeTrue)
			})

			//Now insert hierarchy wildcard to check against.

			_, err = db.DB.Exec(aclQuery, userID, hierarchyACL, MOSQ_ACL_READ)
			So(err, ShouldBeNil)

			Convey("Given a topic not strictly present that matches a hierarchy wildcard, acl check should pass", func() {
				tt1, err1 := jwt.CheckAcl(token, "test/what/ever", clientID, MOSQ_ACL_READ)
				So(err1, ShouldBeNil)
				So(tt1, ShouldBeTrue)
			})

			Convey("Deleting superuser and acl queries should work fine", func() {

				authOpts["jwt_mysql_superquery"] = ""
				authOpts["jwt_mysql_aclquery"] = ""

				jwt, err := NewLocalJWTChecker(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""), tkOptions)
				So(err, ShouldBeNil)

				Convey("So checking against them should give false and true for any user", func() {

					tt1, err1 := jwt.CheckAcl(token, singleLevelACL, clientID, MOSQ_ACL_READ)
					tt2, err2 := jwt.CheckAcl(token, hierarchyACL, clientID, MOSQ_ACL_READ)

					So(err1, ShouldBeNil)
					So(err2, ShouldBeNil)
					So(tt1, ShouldBeTrue)
					So(tt2, ShouldBeTrue)

					superuser, err := jwt.GetSuperuser(token)
					So(err, ShouldBeNil)
					So(superuser, ShouldBeFalse)

				})

			})

			//Empty db
			db.DB.MustExec("delete from test_user where 1 = 1")
			db.DB.MustExec("delete from test_acl where 1 = 1")

			jwt.Halt()

		})

	})

}
