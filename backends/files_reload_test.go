package backends

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/iegomez/mosquitto-go-auth/backends/constants"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

func TestBackendsReload(t *testing.T) {
	Convey("A reload of the backends should reach the files backend and the JWT files mode", t, func() {
		dir := t.TempDir()
		pwPath, aclPath := filepath.Join(dir, "passwords"), filepath.Join(dir, "acls")
		write := func(path, text string) {
			So(os.WriteFile(path, []byte(text), 0600), ShouldBeNil)
		}
		write(pwPath, "alice:x\nbob:x\n")
		write(aclPath, "user alice\ntopic read a/#\n\nuser bob\ntopic read b/#\n")

		opts := map[string]string{
			"backends": "files, jwt", "files_register": "user, acl",
			"files_password_path": pwPath, "files_acl_path": aclPath,
			"jwt_mode": "files", "jwt_acl_path": aclPath, "jwt_secret": "s",
		}
		hasher := hashing.NewHasher(opts, "files")
		f, err := NewFiles(opts, log.ErrorLevel, hasher)
		So(err, ShouldBeNil)
		j, err := NewJWT(opts, log.ErrorLevel, hasher, "test")
		So(err, ShouldBeNil)
		b := &Backends{backends: map[string]Backend{"files": f, "jwt": j}}
		defer b.Halt()

		bobAllowed := func() (inFiles, inJWT bool) {
			inFiles, err := f.CheckAcl("bob", "b/x", "id", MOSQ_ACL_READ)
			So(err, ShouldBeNil)
			inJWT, err = j.checker.(*filesJWTChecker).checker.CheckAcl("bob", "b/x", "id", MOSQ_ACL_READ)
			So(err, ShouldBeNil)
			return inFiles, inJWT
		}

		inFiles, inJWT := bobAllowed()
		So(inFiles, ShouldBeTrue)
		So(inJWT, ShouldBeTrue)

		write(pwPath, "alice:x\n")
		write(aclPath, "user alice\ntopic read a/#\n")
		b.Reload()

		inFiles, inJWT = bobAllowed()
		So(inFiles, ShouldBeFalse)
		So(inJWT, ShouldBeFalse)
	})
}
