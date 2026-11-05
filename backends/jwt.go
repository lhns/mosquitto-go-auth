package backends

import (
	"encoding/pem"
	"fmt"
	"os"

	jwtGo "github.com/golang-jwt/jwt/v5"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type JWT struct {
	mode    string
	name    string
	checker jwtChecker
}

type tokenOptions struct {
	parseToken         bool
	skipUserExpiration bool
	skipACLExpiration  bool
	secret             []byte
	key                interface{} // verification key parsed from secret; nil when no secret is set
	methods            []string    // signing algorithms allowed for key
	userFieldKey       string
}

type jwtChecker interface {
	GetUser(username string) (bool, error)
	GetSuperuser(username string) (bool, error)
	CheckAcl(username, topic, clientid string, acc int32) (bool, error)
	Halt()
}

const (
	remoteMode        = "remote"
	localMode         = "local"
	jsMode            = "js"
	filesMode         = "files"
	claimsSubjectKey  = "sub"
	claimsUsernameKey = "username"
	claimsIssKey      = "iss"
)

func NewJWT(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer, version string) (*JWT, error) {
	log.SetLevel(logLevel)

	jwt := &JWT{}

	var err error
	var checker jwtChecker

	var options tokenOptions

	if parseToken, ok := authOpts["jwt_parse_token"]; ok && parseToken == "true" {
		options.parseToken = true
	}

	if skipUserExpiration, ok := authOpts["jwt_skip_user_expiration"]; ok && skipUserExpiration == "true" {
		options.skipUserExpiration = true
	}

	if skipACLExpiration, ok := authOpts["jwt_skip_acl_expiration"]; ok && skipACLExpiration == "true" {
		options.skipACLExpiration = true
	}

	if secret_file, ok := authOpts["jwt_secret_file"]; ok {
		secretBytes, err := os.ReadFile(secret_file)
		if err != nil {
			return nil, fmt.Errorf("error reading JWT secret file: %w", err)
		}
		options.secret = secretBytes
	} else if secret, ok := authOpts["jwt_secret"]; ok {
		options.secret = []byte(secret)
	}

	if err := options.parseKey(); err != nil {
		return nil, err
	}

	// Every mode but remote and js verifies tokens; remote and js only when they parse them.
	mode := authOpts["jwt_mode"]
	if options.key == nil && (mode == localMode || mode == filesMode || options.parseToken) {
		return nil, errors.New("JWT backend error: missing jwt secret, set jwt_secret or jwt_secret_file")
	}

	if userField, ok := authOpts["jwt_userfield"]; ok && userField == "Username" {
		options.userFieldKey = claimsUsernameKey
	} else {
		options.userFieldKey = claimsSubjectKey
	}

	switch mode {
	case jsMode:
		jwt.mode = jsMode
		checker, err = NewJsJWTChecker(authOpts, options)
	case localMode:
		jwt.mode = localMode
		checker, err = NewLocalJWTChecker(authOpts, logLevel, hasher, options)
	case remoteMode:
		jwt.mode = remoteMode
		checker, err = NewRemoteJWTChecker(authOpts, options, version)
	case filesMode:
		jwt.mode = filesMode
		checker, err = NewFilesJWTChecker(authOpts, logLevel, hasher, options)
	default:
		err = errors.New("unknown JWT mode")
	}

	if err != nil {
		return nil, err
	}

	jwt.name = fmt.Sprintf("JWT %s", mode)

	jwt.checker = checker

	return jwt, nil
}

// GetUser authenticates a given user.
func (o *JWT) GetUser(token, password, clientid string) (bool, error) {
	return o.checker.GetUser(token)
}

// GetSuperuser checks if the given user is a superuser.
func (o *JWT) GetSuperuser(token string) (bool, error) {
	return o.checker.GetSuperuser(token)
}

// CheckAcl checks user authorization.
func (o *JWT) CheckAcl(token, topic, clientid string, acc int32) (bool, error) {
	return o.checker.CheckAcl(token, topic, clientid, acc)
}

// GetName returns the backend's name
func (o *JWT) GetName() string {
	return o.name
}

// Reload reloads the checker when it supports it (the files mode).
func (o *JWT) Reload() error {
	if r, ok := o.checker.(Reloader); ok {
		return r.Reload()
	}

	return nil
}

// Halt closes any db connection.
func (o *JWT) Halt() {
	o.checker.Halt()
}

// parseKey derives the verification key and the allowed signing algorithms from the secret.
// A secret that decodes as a PEM block must be an RSA or EC public key; anything else is an HMAC secret.
func (o *tokenOptions) parseKey() error {
	o.key, o.methods = nil, nil
	if len(o.secret) == 0 {
		return nil
	}

	if block, _ := pem.Decode(o.secret); block == nil {
		o.key = o.secret
		o.methods = []string{"HS256", "HS384", "HS512"}
		return nil
	}

	if key, err := jwtGo.ParseRSAPublicKeyFromPEM(o.secret); err == nil {
		o.key = key
		o.methods = []string{"RS256", "RS384", "RS512"}
		return nil
	}

	if key, err := jwtGo.ParseECPublicKeyFromPEM(o.secret); err == nil {
		o.key = key
		o.methods = []string{"ES256", "ES384", "ES512"}
		return nil
	}

	return errors.New("JWT backend error: jwt secret is a PEM block but not a supported RSA or EC public key")
}

// getJWTClaims verifies the token against the configured key and returns its claims.
// When skipExpiration is set, only the expiration check is skipped: the signature,
// algorithm and the library's default claim checks other than exp (such as nbf) still apply.
func getJWTClaims(options tokenOptions, tokenStr string, skipExpiration bool) (*jwtGo.MapClaims, error) {
	if options.key == nil {
		return nil, errors.New("jwt: no verification key configured")
	}

	parserOpts := []jwtGo.ParserOption{jwtGo.WithValidMethods(options.methods)}
	if skipExpiration {
		parserOpts = append(parserOpts, jwtGo.WithoutClaimsValidation())
	}

	jwtToken, err := jwtGo.NewParser(parserOpts...).ParseWithClaims(tokenStr, &jwtGo.MapClaims{}, func(*jwtGo.Token) (interface{}, error) {
		return options.key, nil
	})
	if err != nil {
		log.Debugf("jwt parse error: %s", err)
		return nil, err
	}

	claims, ok := jwtToken.Claims.(*jwtGo.MapClaims)
	if !ok {
		log.Debugf("jwt error: expected *MapClaims, got %T", jwtToken.Claims)
		return nil, errors.New("got strange claims")
	}

	if skipExpiration {
		// Run the library's claim checks on a copy without "exp".
		checked := make(jwtGo.MapClaims, len(*claims))
		for k, v := range *claims {
			if k != "exp" {
				checked[k] = v
			}
		}
		if err := jwtGo.NewValidator().Validate(checked); err != nil {
			log.Debugf("jwt claims error: %s", err)
			return nil, err
		}
	}

	return claims, nil
}

func getUsernameForToken(options tokenOptions, tokenStr string, skipExpiration bool) (string, error) {
	claims, err := getJWTClaims(options, tokenStr, skipExpiration)

	if err != nil {
		return "", err
	}

	username, found := (*claims)[options.userFieldKey]
	if !found {
		return "", nil
	}

	usernameString, ok := username.(string)
	if !ok {
		log.Debugf("jwt error: username expected to be string, got %T", username)
		return "", errors.New("got strange username")
	}

	return usernameString, nil
}

func getClaimsForToken(options tokenOptions, tokenStr string, skipExpiration bool) (map[string]interface{}, error) {
	claims, err := getJWTClaims(options, tokenStr, skipExpiration)
	if err != nil {
		return make(map[string]interface{}), err
	}

	return map[string]interface{}(*claims), nil
}

func getIssForToken(options tokenOptions, tokenStr string, skipExpiration bool) (string, error) {
	claims, err := getJWTClaims(options, tokenStr, skipExpiration)

	if err != nil {
		return "", err
	}

	iss, found := (*claims)[claimsIssKey]
	if !found {
		return "", nil
	}

	issString, ok := iss.(string)
	if !ok {
		log.Debugf("jwt error: iss expected to be string, got %T", iss)
		return "", errors.New("got strange iss")
	}

	return issString, nil
}
