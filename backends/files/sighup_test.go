package files

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	. "github.com/iegomez/mosquitto-go-auth/backends/constants"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

func TestFilesSighupRemovesUserAndRule(t *testing.T) {
	Convey("After SIGHUP, a user and a rule removed from the files should be gone", t, func() {
		dir := t.TempDir()
		pwPath, aclPath := filepath.Join(dir, "passwords"), filepath.Join(dir, "acls")
		hasher := hashing.NewHasher(map[string]string{}, "files")

		alicePw, err := hasher.Hash("alice")
		So(err, ShouldBeNil)
		bobPw, err := hasher.Hash("bob")
		So(err, ShouldBeNil)

		So(os.WriteFile(pwPath, []byte("alice:"+alicePw+"\nbob:"+bobPw+"\n"), 0600), ShouldBeNil)
		So(os.WriteFile(aclPath, []byte("user alice\ntopic read a/#\ntopic read old/#\n\nuser bob\ntopic read b/#\n"), 0600), ShouldBeNil)

		files, err := NewChecker("files", pwPath, aclPath, log.ErrorLevel, hasher)
		So(err, ShouldBeNil)
		defer files.Halt()

		So(os.WriteFile(pwPath, []byte("alice:"+alicePw+"\n"), 0600), ShouldBeNil)
		So(os.WriteFile(aclPath, []byte("user alice\ntopic read a/#\n"), 0600), ShouldBeNil)
		files.signals <- syscall.SIGHUP

		bobLogin := func() bool {
			ok, err := files.GetUser("bob", "bob", "id")
			So(err, ShouldBeNil)
			return ok
		}
		deadline := time.Now().Add(5 * time.Second)
		for bobLogin() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		So(bobLogin(), ShouldBeFalse)

		granted, err := files.CheckAcl("alice", "old/x", "id", MOSQ_ACL_READ)
		So(err, ShouldBeNil)
		So(granted, ShouldBeFalse)

		granted, err = files.CheckAcl("alice", "a/x", "id", MOSQ_ACL_READ)
		So(err, ShouldBeNil)
		So(granted, ShouldBeTrue)
	})
}
