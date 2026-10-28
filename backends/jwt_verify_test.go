package backends

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func publicKeyPEM(t *testing.T, pub interface{}) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// newACLBackend builds a files-mode JWT backend with the given secret and skip options.
func newACLBackend(t *testing.T, secret string, skip bool) *JWT {
	aclPath, err := filepath.Abs("../test-files/acls")
	require.NoError(t, err)
	opts := map[string]string{
		"jwt_mode":      "files",
		"backends":      "files",
		"jwt_acl_path":  aclPath,
		"jwt_secret":    secret,
		"jwt_userfield": "Username",
	}
	if skip {
		opts["jwt_skip_acl_expiration"] = "true"
		opts["jwt_skip_user_expiration"] = "true"
	}
	b, err := NewJWT(opts, log.ErrorLevel, hashing.NewHasher(opts, "files"), "test")
	require.NoError(t, err)
	return b
}

// accepts reports whether the backend accepts the token. A panic fails the calling test.
func accepts(t *testing.T, b *JWT, token string) (bool, error) {
	var ok bool
	var err error
	require.NotPanics(t, func() { ok, err = b.CheckAcl(token, "test/general", "id", 1) })
	return ok && err == nil, err
}

func claims(mod func(jwt.MapClaims)) jwt.MapClaims {
	c := jwt.MapClaims{"username": "u", "exp": time.Now().Add(time.Hour).Unix()}
	if mod != nil {
		mod(c)
	}
	return c
}

func sign(t *testing.T, method jwt.SigningMethod, key interface{}, c jwt.MapClaims) string {
	s, err := jwt.NewWithClaims(method, c).SignedString(key)
	require.NoError(t, err)
	return s
}

func TestJWTKeyTypeAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaPEM, ecPEM := publicKeyPEM(t, &rsaKey.PublicKey), publicKeyPEM(t, &ecKey.PublicKey)
	hmacSecret := []byte("some_jwt_secret")

	tests := []struct {
		name   string
		secret []byte
		token  string
		want   bool
	}{
		{"rsa key, RS256 token", rsaPEM, sign(t, jwt.SigningMethodRS256, rsaKey, claims(nil)), true},
		{"rsa key, HS256 token keyed with the PEM bytes", rsaPEM, sign(t, jwt.SigningMethodHS256, rsaPEM, claims(nil)), false},
		{"ec key, ES256 token", ecPEM, sign(t, jwt.SigningMethodES256, ecKey, claims(nil)), true},
		{"ec key, HS256 token keyed with the PEM bytes", ecPEM, sign(t, jwt.SigningMethodHS256, ecPEM, claims(nil)), false},
		{"ec key, RS256 token", ecPEM, sign(t, jwt.SigningMethodRS256, rsaKey, claims(nil)), false},
		{"hmac secret, HS256 token", hmacSecret, sign(t, jwt.SigningMethodHS256, hmacSecret, claims(nil)), true},
		{"hmac secret, RS256 token", hmacSecret, sign(t, jwt.SigningMethodRS256, rsaKey, claims(nil)), false},
		{"hmac secret, ES256 token", hmacSecret, sign(t, jwt.SigningMethodES256, ecKey, claims(nil)), false},
		{"hmac secret, alg none", hmacSecret, sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, claims(nil)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, skip := range []bool{false, true} {
				got, _ := accepts(t, newACLBackend(t, string(tt.secret), skip), tt.token)
				require.Equal(t, tt.want, got, "skip=%v", skip)
			}
		})
	}
}

func TestJWTMalformedPEMIsStartupError(t *testing.T) {
	garbage := "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n"
	opts := map[string]string{"jwt_mode": "files", "backends": "files", "jwt_acl_path": "../test-files/acls", "jwt_secret": garbage}
	_, err := NewJWT(opts, log.ErrorLevel, hashing.NewHasher(opts, "files"), "test")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "bm90IGEga2V5")
}

func TestJWTSecretWithPEMTextIsHMAC(t *testing.T) {
	// A secret that contains PEM marker text but no PEM block is an HMAC secret.
	secret := "abc-----BEGINxyz"
	token := sign(t, jwt.SigningMethodHS256, []byte(secret), claims(nil))
	for _, skip := range []bool{false, true} {
		got, _ := accepts(t, newACLBackend(t, secret, skip), token)
		require.True(t, got, "skip=%v", skip)
	}
}

func TestJWTMissingSecretIsStartupError(t *testing.T) {
	// Modes that always verify tokens need a secret; remote and js only when they parse tokens.
	tests := []struct {
		mode  string
		extra map[string]string
		fails bool
	}{
		{"files", map[string]string{"jwt_acl_path": "../test-files/acls"}, true},
		{"local", map[string]string{"jwt_userquery": "select 1"}, true},
		{"remote", map[string]string{"jwt_host": "localhost", "jwt_port": "80", "jwt_params_mode": "json", "jwt_response_mode": "json", "jwt_getuser_uri": "/u", "jwt_superuser_uri": "/s", "jwt_aclcheck_uri": "/a"}, false},
		{"remote", map[string]string{"jwt_host": "localhost", "jwt_port": "80", "jwt_params_mode": "json", "jwt_response_mode": "json", "jwt_getuser_uri": "/u", "jwt_superuser_uri": "/s", "jwt_aclcheck_uri": "/a", "jwt_parse_token": "true"}, true},
		{"js", map[string]string{"jwt_js_user_script_path": "../test-files/jwt/user_script.js", "jwt_js_superuser_script_path": "../test-files/jwt/superuser_script.js", "jwt_js_acl_script_path": "../test-files/jwt/acl_script.js", "jwt_parse_token": "true"}, true},
	}
	for _, tt := range tests {
		opts := map[string]string{"jwt_mode": tt.mode, "backends": "jwt"}
		for k, v := range tt.extra {
			opts[k] = v
		}
		b, err := NewJWT(opts, log.ErrorLevel, hashing.NewHasher(opts, ""), "test")
		if tt.fails {
			require.Error(t, err, "mode %s", tt.mode)
			require.Contains(t, err.Error(), "jwt_secret", "mode %s", tt.mode)
		} else {
			require.NoError(t, err, "mode %s", tt.mode)
			b.Halt()
		}
	}
}

func TestJWTSkipExpirationSkipsOnlyExpiration(t *testing.T) {
	secret := []byte("some_jwt_secret")
	past := time.Now().Add(-time.Hour).Unix()
	expired := func(c jwt.MapClaims) { c["exp"] = past }
	future := func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }

	tests := []struct {
		name  string
		token string
		skip  bool
		want  bool
	}{
		{"malformed a.b", "a.b", true, false},
		{"malformed text", "not-a-jwt", true, false},
		{"empty", "", true, false},
		{"expired, skip off", sign(t, jwt.SigningMethodHS256, secret, claims(expired)), false, false},
		{"expired, skip on", sign(t, jwt.SigningMethodHS256, secret, claims(expired)), true, true},
		{"expired with wrong signature, skip on", sign(t, jwt.SigningMethodHS256, []byte("other"), claims(expired)), true, false},
		{"nbf in the future, skip on", sign(t, jwt.SigningMethodHS256, secret, claims(future)), true, false},
		{"expired and nbf in the future, skip on", sign(t, jwt.SigningMethodHS256, secret, claims(func(c jwt.MapClaims) { expired(c); future(c) })), true, false},
		{"valid, skip on", sign(t, jwt.SigningMethodHS256, secret, claims(nil)), true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := accepts(t, newACLBackend(t, string(secret), tt.skip), tt.token)
			if !tt.want {
				require.Error(t, err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestJWTJSNonStringUsernameIsDenied(t *testing.T) {
	opts := map[string]string{
		"jwt_mode":                     "js",
		"jwt_parse_token":              "true",
		"jwt_secret":                   "some_jwt_secret",
		"jwt_js_user_script_path":      "../test-files/jwt/parsed_user_script.js",
		"jwt_js_superuser_script_path": "../test-files/jwt/superuser_script.js",
		"jwt_js_acl_script_path":       "../test-files/jwt/acl_script.js",
	}
	b, err := NewJWT(opts, log.ErrorLevel, hashing.NewHasher(opts, "files"), "test")
	require.NoError(t, err)

	for name, sub := range map[string]interface{}{"number": 5, "null": nil, "object": map[string]interface{}{"a": "b"}} {
		t.Run(name, func(t *testing.T) {
			token := sign(t, jwt.SigningMethodHS256, []byte("some_jwt_secret"), claims(func(c jwt.MapClaims) { c["sub"] = sub }))
			require.NotPanics(t, func() {
				got, err := b.GetUser(token, "pass", "id")
				require.Error(t, err)
				require.False(t, got)

				got, err = b.GetSuperuser(token)
				require.Error(t, err)
				require.False(t, got)

				got, err = b.CheckAcl(token, "test/topic", "id", 1)
				require.Error(t, err)
				require.False(t, got)
			})
		})
	}
}
