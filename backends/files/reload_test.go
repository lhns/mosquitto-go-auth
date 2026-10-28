package files

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	. "github.com/iegomez/mosquitto-go-auth/backends/constants"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

func TestFilesReload(t *testing.T) {
	Convey("Given a password file and an ACL file", t, func() {
		dir := t.TempDir()
		pwPath, aclPath := filepath.Join(dir, "passwords"), filepath.Join(dir, "acls")
		hasher := hashing.NewHasher(map[string]string{}, "files")

		alicePw, err := hasher.Hash("alice")
		So(err, ShouldBeNil)
		bobPw, err := hasher.Hash("bob")
		So(err, ShouldBeNil)

		write := func(path, text string) {
			So(os.WriteFile(path, []byte(text), 0600), ShouldBeNil)
		}
		write(pwPath, "alice:"+alicePw+"\nbob:"+bobPw+"\n")
		write(aclPath, "topic read general/#\n\nuser alice\ntopic read a/#\n\nuser bob\ntopic read b/#\ntopic read shared/#\n")

		files, err := NewChecker("files", pwPath, aclPath, log.ErrorLevel, hasher)
		So(err, ShouldBeNil)
		defer files.Halt()

		allowed := func(username, topic string) bool {
			ok, err := files.CheckAcl(username, topic, "id", MOSQ_ACL_READ)
			So(err, ShouldBeNil)
			return ok
		}
		login := func(username, password string) bool {
			ok, err := files.GetUser(username, password, "id")
			So(err, ShouldBeNil)
			return ok
		}

		So(login("bob", "bob"), ShouldBeTrue)
		So(allowed("bob", "shared/x"), ShouldBeTrue)
		So(allowed("bob", "general/x"), ShouldBeTrue)

		Convey("A reload should remove a deleted user and deleted rules", func() {
			write(pwPath, "alice:"+alicePw+"\n")
			write(aclPath, "user alice\ntopic read a/#\n")
			So(files.Reload(), ShouldBeNil)

			So(login("bob", "bob"), ShouldBeFalse)
			So(allowed("bob", "b/x"), ShouldBeFalse)
			So(allowed("alice", "general/x"), ShouldBeFalse)
			So(login("alice", "alice"), ShouldBeTrue)
			So(allowed("alice", "a/x"), ShouldBeTrue)
		})

		Convey("A reload should remove a deleted rule of a user that stays", func() {
			write(aclPath, "user bob\ntopic read b/#\n")
			So(files.Reload(), ShouldBeNil)

			So(allowed("bob", "b/x"), ShouldBeTrue)
			So(allowed("bob", "shared/x"), ShouldBeFalse)
		})

		Convey("A reload should not add the rules again", func() {
			So(files.Reload(), ShouldBeNil)
			So(files.Reload(), ShouldBeNil)

			So(len(files.Users()["bob"].aclRecords), ShouldEqual, 2)
			So(len(files.snap.Load().aclRecords), ShouldEqual, 1)
		})

		Convey("A failed reload should keep the last good data", func() {
			write(pwPath, "alice:"+alicePw+"\n")
			write(aclPath, "user alice\nbad line\n")
			So(files.Reload(), ShouldNotBeNil)

			So(login("bob", "bob"), ShouldBeTrue)
			So(allowed("bob", "shared/x"), ShouldBeTrue)

			So(os.Remove(pwPath), ShouldBeNil)
			So(files.Reload(), ShouldNotBeNil)
			So(login("bob", "bob"), ShouldBeTrue)
		})

		Convey("A reload should skip malformed password lines like startup", func() {
			write(pwPath, "alice:"+alicePw+"\nsecret-line-content\n")
			write(aclPath, "user alice\ntopic read a/#\n")
			So(files.Reload(), ShouldBeNil)

			So(login("alice", "alice"), ShouldBeTrue)
			So(login("bob", "bob"), ShouldBeFalse)
			So(allowed("alice", "a/x"), ShouldBeTrue)
		})

		Convey("A change of the result of Users should not change the checker", func() {
			delete(files.Users(), "bob")
			files.Users()["alice"].aclRecords[0].topic = "#"

			So(login("bob", "bob"), ShouldBeTrue)
			So(allowed("alice", "z"), ShouldBeFalse)
		})

		Convey("Checks should run while a reload runs", func() {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				for i := 0; i < 20; i++ {
					_ = files.Reload()
				}
			}()
			go func() {
				defer wg.Done()
				for i := 0; i < 20; i++ {
					_, _ = files.CheckAcl("bob", "b/x", "id", MOSQ_ACL_READ)
					_, _ = files.GetUser("alice", "alice", "id")
					_ = files.Users()
				}
			}()
			wg.Wait()
			So(allowed("bob", "b/x"), ShouldBeTrue)
		})
	})
}
