package backends

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/iegomez/mosquitto-go-auth/telemetry"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// hiddenUsername stands for a username that must not appear in logs and errors.
const hiddenUsername = "<hidden>"

const (
	// hiddenErrorText replaces an error text that holds a cut-off username.
	hiddenErrorText = "error (text hidden: it may contain the username)"
	// An error with any truncatedTokenWindowLen characters long part of a username of at least
	// truncatedTokenMinLen characters, but not the whole username, is taken for a cut-off or sliced one.
	truncatedTokenMinLen    = 32
	truncatedTokenWindowLen = 16
	// A text is percent-decoded at most this many times when it is searched for the username.
	maxPercentDecodings = 5
)

type Backend interface {
	GetUser(username, password, clientid string) (bool, error)
	GetSuperuser(username string) (bool, error)
	CheckAcl(username, topic, clientId string, acc int32) (bool, error)
	GetName() string
	Halt()
}

type Backends struct {
	backends map[string]Backend

	aclCheckers       []string
	userCheckers      []string
	superuserCheckers []string

	checkPrefix bool
	stripPrefix bool
	prefixes    map[string]string

	// jwt_mode, jwt_skip_user_expiration and jwt_skip_acl_expiration, for CacheDeadline.
	jwtMode        string
	jwtSkipUserExp bool
	jwtSkipACLExp  bool

	disableSuperuser    bool
	exhaustBackendFirst bool
	jwtConfigured       bool
	sortedBackends      []string
}

const (
	// backends
	postgresBackend = "postgres"
	jwtBackend      = "jwt"
	redisBackend    = "redis"
	httpBackend     = "http"
	filesBackend    = "files"
	mysqlBackend    = "mysql"
	sqliteBackend   = "sqlite"
	mongoBackend    = "mongo"
	pluginBackend   = "plugin"
	grpcBackend     = "grpc"
	jsBackend       = "js"
	ldapBackend     = "ldap"

	// checks
	aclCheck       = "acl"
	userCheck      = "user"
	superuserCheck = "superuser"

	// other constants
	defaultUserAgent = "mosquitto"
)

// AllowedBackendsOptsPrefix serves as a check for allowed backends and a map from backend to expected opts prefix.
var allowedBackendsOptsPrefix = map[string]string{
	postgresBackend: "pg",
	jwtBackend:      "jwt",
	redisBackend:    "redis",
	httpBackend:     "http",
	filesBackend:    "files",
	mysqlBackend:    "mysql",
	sqliteBackend:   "sqlite",
	mongoBackend:    "mongo",
	pluginBackend:   "plugin",
	grpcBackend:     "grpc",
	jsBackend:       "js",
	ldapBackend:     "ldap",
}

// Initialize sets general options, tries to build the backends and register their checkers.
func Initialize(authOpts map[string]string, logLevel log.Level, version string) (*Backends, error) {
	b := &Backends{
		backends:          make(map[string]Backend),
		aclCheckers:       make([]string, 0),
		userCheckers:      make([]string, 0),
		superuserCheckers: make([]string, 0),
		prefixes:          make(map[string]string),
	}

	// Disable superusers for all backends if option is set.
	if authOpts["disable_superuser"] == "true" {
		b.disableSuperuser = true

	}

	// When set, a backend will be checked for superuser (if enabled) and ACL before checking another backend.
	if authOpts["exhaust_backend_first"] == "true" {
		b.exhaustBackendFirst = true

	}

	backendsOpt, ok := authOpts["backends"]
	if !ok || backendsOpt == "" {
		return nil, fmt.Errorf("missing or blank option backends")
	}

	backends := strings.Split(strings.Replace(backendsOpt, " ", "", -1), ",")
	if len(backends) < 1 {
		return nil, fmt.Errorf("missing or blank option backends")
	}

	for _, backend := range backends {
		if _, ok := allowedBackendsOptsPrefix[backend]; !ok {
			return nil, fmt.Errorf("unknown backend %s", backend)
		}
	}

	for _, backend := range backends {
		if backend == jwtBackend {
			b.jwtConfigured = true
		}
	}

	quietRedisLibraryLogs(authOpts)

	err := b.addBackends(authOpts, logLevel, backends, version)
	if err != nil {
		return nil, err
	}

	err = b.setCheckers(authOpts)
	if err != nil {
		return nil, err
	}

	b.setPrefixes(authOpts, backends)

	return b, nil
}

func (b *Backends) addBackends(authOpts map[string]string, logLevel log.Level, backends []string, version string) error {
	// Store given backends as given to order them when checking.
	//
	// This allows to sort user checking, and first exhaust superuser/acl checks of a given backend before checking the next one,
	// instead of the default superuser of all backends before checking them again for ACLs.
	//
	// Neither option is a silver bullet, but at least give some more grained control when paired with
	// checkers registering.
	b.sortedBackends = make([]string, len(backends))
	copy(b.sortedBackends, backends)

	for _, bename := range backends {
		var beIface Backend
		var err error

		hasher := hashing.NewHasher(authOpts, allowedBackendsOptsPrefix[bename])
		switch bename {
		case postgresBackend:
			beIface, err = NewPostgres(authOpts, logLevel, hasher)
			if err != nil {
				log.Fatalf("backend register error: couldn't initialize %s backend with error %s.", bename, err)
			} else {
				log.Infof("backend registered: %s", beIface.GetName())
				b.backends[postgresBackend] = withHideToken(beIface, b.jwtConfigured)
			}
		case jwtBackend:
			b.jwtMode = authOpts["jwt_mode"]
			b.jwtSkipUserExp = authOpts["jwt_skip_user_expiration"] == "true"
			b.jwtSkipACLExp = authOpts["jwt_skip_acl_expiration"] == "true"
			beIface, err = NewJWT(authOpts, logLevel, hasher, version)
			if err != nil {
				log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
			} else {
				log.Infof("Backend registered: %s", beIface.GetName())
				b.backends[jwtBackend] = beIface.(*JWT)
			}
		case filesBackend:
			beIface, err = NewFiles(authOpts, logLevel, hasher)
			if err != nil {
				log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
			} else {
				log.Infof("Backend registered: %s", beIface.GetName())
				b.backends[filesBackend] = beIface.(*Files)
			}
		case redisBackend:
			beIface, err = NewRedis(authOpts, logLevel, hasher)
			if err != nil {
				log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
			} else {
				log.Infof("Backend registered: %s", beIface.GetName())
				b.backends[redisBackend] = beIface.(Redis)
			}
		case mysqlBackend:
			beIface, err = NewMysql(authOpts, logLevel, hasher)
			if err != nil {
				log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
			} else {
				log.Infof("Backend registered: %s", beIface.GetName())
				b.backends[mysqlBackend] = withHideToken(beIface, b.jwtConfigured)
			}
		case httpBackend:
			beIface, err = NewHTTP(authOpts, logLevel, version)
			if err != nil {
				log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
			} else {
				log.Infof("Backend registered: %s", beIface.GetName())
				b.backends[httpBackend] = withHideToken(beIface, b.jwtConfigured)
			}
		case sqliteBackend:
			beIface, err = NewSqlite(authOpts, logLevel, hasher)
			if err != nil {
				log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
			} else {
				log.Infof("Backend registered: %s", beIface.GetName())
				b.backends[sqliteBackend] = withHideToken(beIface, b.jwtConfigured)
			}
		case mongoBackend:
			beIface, err = NewMongo(authOpts, logLevel, hasher)
			if err != nil {
				log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
			} else {
				log.Infof("Backend registered: %s", beIface.GetName())
				b.backends[mongoBackend] = beIface.(Mongo)
			}
		case grpcBackend:
			beIface, err = NewGRPC(authOpts, logLevel)
			if err != nil {
				log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
			} else {
				log.Infof("Backend registered: %s", beIface.GetName())
				b.backends[grpcBackend] = withHideToken(beIface, b.jwtConfigured)
			}
		case jsBackend:
			beIface, err = NewJavascript(authOpts, logLevel)
			if err != nil {
				log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
			} else {
				log.Infof("Backend registered: %s", beIface.GetName())
				b.backends[jsBackend] = withHideToken(beIface, b.jwtConfigured)
			}
		case ldapBackend:
			beIface, err = NewLDAP(authOpts, logLevel)
			if err != nil {
				log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
			} else {
				log.Infof("Backend registered: %s", beIface.GetName())
				b.backends[ldapBackend] = withHideToken(beIface, b.jwtConfigured)
			}
		case pluginBackend:
			beIface, err = NewCustomPlugin(authOpts, logLevel)
			if err != nil {
				log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
			} else {
				log.Infof("Backend registered: %s", beIface.GetName())
				b.backends[pluginBackend] = beIface.(*CustomPlugin)
			}
		default:
			return fmt.Errorf("unkown backend %s", bename)
		}
	}

	return nil
}

func (b *Backends) setCheckers(authOpts map[string]string) error {
	// We'll register which plugins will perform checks for user, superuser and acls.
	// At least one backend must be registered for user and acl checks.
	// When option auth_opt_backend_register is missing for the backend, we register all checks.
	for _, name := range b.sortedBackends {

		opt := fmt.Sprintf("%s_register", allowedBackendsOptsPrefix[name])
		options, ok := authOpts[opt]

		if ok {
			checkers := strings.Split(strings.Replace(options, " ", "", -1), ",")
			for _, check := range checkers {
				switch check {
				case aclCheck:
					b.aclCheckers = append(b.aclCheckers, name)
					log.Infof("registered acl checker: %s", name)
				case userCheck:
					b.userCheckers = append(b.userCheckers, name)
					log.Infof("registered user checker: %s", name)
				case superuserCheck:
					if !b.disableSuperuser {
						b.superuserCheckers = append(b.superuserCheckers, name)
						log.Infof("registered superuser checker: %s", name)
					}
				default:
					return fmt.Errorf("unsupported check %s found for backend %s", check, name)
				}
			}
		} else {
			b.aclCheckers = append(b.aclCheckers, name)
			log.Infof("registered acl checker: %s", name)
			b.userCheckers = append(b.userCheckers, name)
			log.Infof("registered user checker: %s", name)

			if !b.disableSuperuser {
				b.superuserCheckers = append(b.superuserCheckers, name)
				log.Infof("registered superuser checker: %s", name)
			}
		}
	}

	if len(b.userCheckers) == 0 && len(b.aclCheckers) == 0 {
		return errors.New("no backends registered")
	}

	return nil
}

// withHideToken sets hideToken on the backends that echo external error text, and gives the
// backend back (the sql, http backends are values, so they are copied).
func withHideToken(be Backend, hide bool) Backend {
	switch be := be.(type) {
	case Postgres:
		be.hideToken = hide
		return be
	case Mysql:
		be.hideToken = hide
		return be
	case Sqlite:
		be.hideToken = hide
		return be
	case HTTP:
		be.hideToken = hide
		return be
	case *LDAP:
		be.hideToken = hide
	case *GRPC:
		be.hideToken = hide
	case *Javascript:
		be.hideToken = hide
	}
	return be
}

// hideToken replaces the username in the text of an error. With a jwt backend the username can be
// a token, and a database or directory error can quote it (for example the cast error of a uuid column).
// Without a jwt backend the error is returned unchanged.
//
// A driver may cut the text of an error (MySQL limits messages to 512 bytes), which leaves a part of
// a long username that the exact match misses. Then the text is replaced as a whole.
func hideToken(hide bool, err error, username string) error {
	if !hide || err == nil || username == "" {
		return err
	}
	if text := hideText(err.Error(), username); text != err.Error() {
		return errors.New(text)
	}
	return err
}

// hideText is hideToken for a text, such as the reply of an auth server. The whole username is
// replaced first, also in its URL-encoded forms (a url.Error quotes a redirect URL). A part of the
// username that is left (a cut-off copy, a signature or a slice a script quotes) hides the whole text.
func hideText(text, username string) string {
	if username == "" {
		return text
	}
	text = strings.ReplaceAll(text, username, hiddenUsername)
	for _, encoded := range []string{url.QueryEscape(username), url.PathEscape(username)} {
		if encoded != username {
			text = strings.ReplaceAll(text, encoded, hiddenUsername)
		}
	}
	if holdsUsernamePart(text, username) {
		return hiddenErrorText
	}
	// A client library can quote the username percent-encoded in every byte, which leaves no run of
	// plain characters to match. Decode the text (more than once: it can be encoded twice) and look again.
	for decoded, i := text, 0; i < maxPercentDecodings; i++ {
		next := percentDecode(decoded)
		if next == decoded {
			break
		}
		decoded = next
		if strings.Contains(decoded, username) || holdsUsernamePart(decoded, username) {
			return hiddenErrorText
		}
	}
	return text
}

// holdsUsernamePart tells if text holds a truncatedTokenWindowLen long part of a long username.
func holdsUsernamePart(text, username string) bool {
	if len(username) < truncatedTokenMinLen {
		return false
	}
	for i := 0; i+truncatedTokenWindowLen <= len(username); i++ {
		if strings.Contains(text, username[i:i+truncatedTokenWindowLen]) {
			return true
		}
	}
	return false
}

// percentDecode decodes every valid %XX sequence of s and leaves any other text as it is.
func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok := unhex(s[i+1]); ok {
				if lo, ok := unhex(s[i+2]); ok {
					b.WriteByte(hi<<4 | lo)
					i += 2
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// logUsername returns the username for debug logs, or a placeholder when hide is set.
func logUsername(hide bool, username string) string {
	if hide {
		return hiddenUsername
	}
	return username
}

// LogUsername returns the username for debug logs, or a placeholder when it must not be shown.
func (b *Backends) LogUsername(username string) string {
	return logUsername(b.jwtConfigured, username)
}

// setPrefixes sets options for prefixes handling.
func (b *Backends) setPrefixes(authOpts map[string]string, backends []string) {
	checkPrefix, ok := authOpts["check_prefix"]

	if !ok || strings.Replace(checkPrefix, " ", "", -1) != "true" {
		b.checkPrefix = false
		b.stripPrefix = false

		return
	}

	prefixesStr, ok := authOpts["prefixes"]

	if !ok {
		log.Warn("Error: prefixes enabled but no options given, defaulting to prefixes disabled.")
		b.checkPrefix = false
		b.stripPrefix = false

		return
	}

	prefixes := strings.Split(strings.Replace(prefixesStr, " ", "", -1), ",")

	if len(prefixes) != len(backends) {
		log.Errorf("Error: got %d backends and %d prefixes, defaulting to prefixes disabled.", len(backends), len(prefixes))
		b.checkPrefix = false
		b.stripPrefix = false

		return
	}

	if authOpts["strip_prefix"] == "true" {
		b.stripPrefix = true
	}

	for i, backend := range backends {
		b.prefixes[prefixes[i]] = backend
	}

	log.Infof("prefixes enabled for backends %s with prefixes %s.", authOpts["backends"], authOpts["prefixes"])
	b.checkPrefix = true
}

// lookupPrefix checks if a username contains a valid prefix. If so, returns ok and the suitable
// backend name; else, !ok and empty string.
func (b *Backends) lookupPrefix(username string) (bool, string) {
	if _, backend, ok := b.splitPrefix(username); ok {
		log.Debugf("Found prefix for user %s, using backend %s.", b.LogUsername(username), backend)
		return true, backend
	}
	return false, ""
}

// splitPrefix gives the registered prefix of a username and its backend, without logging.
func (b *Backends) splitPrefix(username string) (prefix, backend string, ok bool) {
	if i := strings.Index(username, "_"); i > 0 {
		if backend, ok := b.prefixes[username[:i]]; ok {
			return username[:i], backend, true
		}
	}
	return "", "", false
}

// getPrefixForBackend retrieves the user provided prefix for a given backend.
func (b *Backends) getPrefixForBackend(backend string) string {
	for k, v := range b.prefixes {
		if v == backend {
			return k
		}
	}
	return ""
}

func checkRegistered(bename string, checkers []string) bool {
	for _, b := range checkers {
		if b == bename {
			return true
		}
	}

	return false
}

// traceBackendCall wraps a single backend call with a span and the
// BackendDuration histogram. Does nothing visible when telemetry is off
// (noop tracer, noop histogram). Kept short so call sites stay readable.
func traceBackendCall(ctx context.Context, bename, op string, fn func(context.Context) (bool, error)) (bool, error) {
	ctx, span := telemetry.Tracer().Start(ctx, "backend."+op,
		trace.WithAttributes(
			attribute.String("backend.name", bename),
			attribute.String("backend.op", op),
		),
	)
	start := time.Now()
	ok, err := fn(ctx)
	result := "granted"
	if err != nil {
		result = "error"
	} else if !ok {
		result = "rejected"
	}
	span.SetAttributes(attribute.String("backend.result", result))
	span.End()
	telemetry.BackendDuration.Record(ctx, time.Since(start).Seconds(),
		metric.WithAttributes(
			attribute.String("backend.name", bename),
			attribute.String("backend.op", op),
			attribute.String("backend.result", result),
		),
	)
	return ok, err
}

// traceCall is traceBackendCall for a call with username: with a jwt backend the username can be a
// token, so the error text, which any backend (mongo, redis, a custom plugin) can fill with it, is
// hidden here, where the error leaves the backends.
func (b *Backends) traceCall(ctx context.Context, bename, op, username string, fn func(context.Context) (bool, error)) (bool, error) {
	ok, err := traceBackendCall(ctx, bename, op, fn)
	return ok, hideToken(b.jwtConfigured, err, username)
}

// AuthUnpwdCheck checks user authentication.
func (b *Backends) AuthUnpwdCheck(ctx context.Context, username, password, clientid string) (bool, error) {
	var authenticated bool
	var err error

	// If prefixes are enabled, check if username has a valid prefix and use the correct backend if so.
	if !b.checkPrefix {
		return b.checkAuth(ctx, username, password, clientid)
	}

	validPrefix, bename := b.lookupPrefix(username)

	if !validPrefix {
		return b.checkAuth(ctx, username, password, clientid)
	}

	if !checkRegistered(bename, b.userCheckers) {
		return false, fmt.Errorf("backend %s not registered to check users", bename)
	}

	// If the backend is JWT and the token was prefixed, then strip the token.
	// If the token was passed without a prefix it will be handled in the common case.
	// Also strip the prefix if the strip_prefix option was set.
	if bename == jwtBackend || b.stripPrefix {
		prefix := b.getPrefixForBackend(bename)
		username = strings.TrimPrefix(username, prefix+"_")
	}
	var backend = b.backends[bename]

	authenticated, err = b.traceCall(ctx, bename, "get_user", username, func(context.Context) (bool, error) {
		return backend.GetUser(username, password, clientid)
	})
	if authenticated && err == nil {
		log.Debugf("user %s authenticated with backend %s", b.LogUsername(username), backend.GetName())
	}

	return authenticated, err
}

func (b *Backends) checkAuth(ctx context.Context, username, password, clientid string) (bool, error) {
	var err error

	for _, bename := range b.userCheckers {
		var backend = b.backends[bename]

		log.Debugf("checking user %s with backend %s", b.LogUsername(username), backend.GetName())

		ok, getUserErr := b.traceCall(ctx, bename, "get_user", username, func(context.Context) (bool, error) {
			return backend.GetUser(username, password, clientid)
		})
		if ok && getUserErr == nil {
			log.Debugf("user %s authenticated with backend %s", b.LogUsername(username), backend.GetName())
			return true, nil
		} else if getUserErr != nil && err == nil {
			err = getUserErr
		}
	}

	return false, err
}

// AuthAclCheck checks user/topic/acc authorization.
func (b *Backends) AuthAclCheck(ctx context.Context, clientid, username, topic string, acc int) (bool, error) {
	var aclCheck bool
	var err error

	// If prefixes are enabled, check if username has a valid prefix and use the correct backend if so.
	// Else, check all backends.
	if !b.checkPrefix {
		return b.checkAcl(ctx, username, topic, clientid, acc)
	}

	validPrefix, bename := b.lookupPrefix(username)

	if !validPrefix {
		return b.checkAcl(ctx, username, topic, clientid, acc)
	}

	// If the backend is JWT and the token was prefixed, then strip the token.
	// If the token was passed without a prefix then let it be handled in the common case.
	// Also strip the prefix if the strip_prefix option was set.
	if bename == jwtBackend || b.stripPrefix {
		prefix := b.getPrefixForBackend(bename)
		username = strings.TrimPrefix(username, prefix+"_")
	}
	var backend = b.backends[bename]

	// Short circuit checks when superusers are disabled.
	if !b.disableSuperuser && checkRegistered(bename, b.superuserCheckers) {
		log.Debugf("Superuser check with backend %s", backend.GetName())

		aclCheck, err = b.traceCall(ctx, bename, "get_superuser", username, func(context.Context) (bool, error) {
			return backend.GetSuperuser(username)
		})

		if aclCheck && err == nil {
			log.Debugf("superuser %s acl authenticated with backend %s", b.LogUsername(username), backend.GetName())
		}
	}
	// If not superuser, check acl.
	if !aclCheck {
		if !checkRegistered(bename, b.aclCheckers) {
			return false, fmt.Errorf("backend %s not registered to check acls", bename)
		}

		log.Debugf("Acl check with backend %s", backend.GetName())
		ok, checkACLErr := b.traceCall(ctx, bename, "check_acl", username, func(context.Context) (bool, error) {
			return backend.CheckAcl(username, topic, clientid, int32(acc))
		})
		if ok && checkACLErr == nil {
			aclCheck = true
			log.Debugf("user %s acl authenticated with backend %s", b.LogUsername(username), backend.GetName())
		} else if checkACLErr != nil && err == nil {
			err = checkACLErr
		}
	}

	log.Debugf("Acl is %t for user %s", aclCheck, b.LogUsername(username))
	return aclCheck, err
}

func (b *Backends) checkAcl(ctx context.Context, username, topic, clientid string, acc int) (bool, error) {
	// Historically, the plugin checked all backends for superuser first (without order),
	// and only then it checked for ACLs.
	// If exhaust_backend_first is set, we check backends for both first following order.
	if b.exhaustBackendFirst {
		return b.exhaustBackendsInOrder(ctx, username, topic, clientid, acc)
	}

	return b.checkSuperuserThenACL(ctx, username, topic, clientid, acc)
}

func (b *Backends) exhaustBackendsInOrder(ctx context.Context, username, topic, clientid string, acc int) (bool, error) {
	// Check every backend, in order, for superuser and ACL.
	var err error

	for _, bename := range b.sortedBackends {
		var backend = b.backends[bename]

		if !b.disableSuperuser && checkRegistered(bename, b.superuserCheckers) {
			log.Debugf("superuser check with backend %s", backend.GetName())
			ok, getSuperuserErr := b.traceCall(ctx, bename, "get_superuser", username, func(context.Context) (bool, error) {
				return backend.GetSuperuser(username)
			})
			if ok && getSuperuserErr == nil {
				log.Debugf("superuser %s acl authenticated with backend %s", b.LogUsername(username), backend.GetName())
				return true, nil
			} else if getSuperuserErr != nil && err == nil {
				err = getSuperuserErr
			}
		}

		if checkRegistered(bename, b.aclCheckers) {
			log.Debugf("acl check with backend %s", backend.GetName())
			ok, checkACLErr := b.traceCall(ctx, bename, "check_acl", username, func(context.Context) (bool, error) {
				return backend.CheckAcl(username, topic, clientid, int32(acc))
			})
			if ok && checkACLErr == nil {
				log.Debugf("user %s acl authenticated with backend %s", b.LogUsername(username), backend.GetName())
				return true, nil
			} else if checkACLErr != nil && err == nil {
				err = checkACLErr
			}
		}
	}

	// No backend authorized access.
	return false, err
}

func (b *Backends) checkSuperuserThenACL(ctx context.Context, username, topic, clientid string, acc int) (bool, error) {
	// Check superusers first
	var err error

	if !b.disableSuperuser {
		for _, bename := range b.superuserCheckers {
			var backend = b.backends[bename]

			log.Debugf("superuser check with backend %s", backend.GetName())
			ok, getSuperuserErr := b.traceCall(ctx, bename, "get_superuser", username, func(context.Context) (bool, error) {
				return backend.GetSuperuser(username)
			})
			if ok && getSuperuserErr == nil {
				log.Debugf("superuser %s acl authenticated with backend %s", b.LogUsername(username), backend.GetName())
				return true, nil
			} else if getSuperuserErr != nil && err == nil {
				err = getSuperuserErr
			}
		}
	}

	for _, bename := range b.aclCheckers {
		var backend = b.backends[bename]

		log.Debugf("Acl check with backend %s", backend.GetName())
		ok, checkACLErr := b.traceCall(ctx, bename, "check_acl", username, func(context.Context) (bool, error) {
			return backend.CheckAcl(username, topic, clientid, int32(acc))
		})
		if ok && checkACLErr == nil {
			log.Debugf("user %s acl authenticated with backend %s", b.LogUsername(username), backend.GetName())
			return true, nil
		} else if checkACLErr != nil && err == nil {
			err = checkACLErr
		}
	}

	// No backend authorized access.
	return false, err
}

// Reloader is implemented by the backends and checkers that can reload their data.
type Reloader interface {
	Reload() error
}

// Reload asks each backend that can reload its data (files, JWT files mode) to do it.
// A failed reload is logged by the backend and does not stop the others.
func (b *Backends) Reload() {
	for _, v := range b.backends {
		if r, ok := v.(Reloader); ok {
			_ = r.Reload()
		}
	}
}

func (b *Backends) Halt() {
	// Halt every registered backend.
	for _, v := range b.backends {
		v.Halt()
	}
}
