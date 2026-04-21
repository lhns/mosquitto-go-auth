package main

import "C"

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	bes "github.com/iegomez/mosquitto-go-auth/backends"
	"github.com/iegomez/mosquitto-go-auth/cache"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/iegomez/mosquitto-go-auth/telemetry"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// BackendsChecker is the interface used by AuthPlugin to check credentials and ACLs.
type BackendsChecker interface {
	AuthUnpwdCheck(ctx context.Context, username, password, clientid string) (bool, error)
	AuthAclCheck(ctx context.Context, clientid, username, topic string, acc int) (bool, error)
	Halt()
}

type AuthPlugin struct {
	backends              BackendsChecker
	useCache              bool
	logLevel              log.Level
	logDest               string
	logFile               string
	ctx                   context.Context
	cache                 cache.Store
	hasher                hashing.HashComparer
	retryCount            int
	useClientidAsUsername bool
	allowEmptyCredentials bool
	telemetryShutdown     func(context.Context) error
}

// errors to signal mosquitto
const (
	AuthRejected = 0
	AuthGranted  = 1
	AuthError    = 2
)

var authOpts map[string]string //Options passed by mosquitto.
var authPlugin AuthPlugin      //General struct with options and conf.

//export AuthPluginInit
func AuthPluginInit(keys []*C.char, values []*C.char, authOptsNum int, version *C.char) {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	//Initialize auth plugin struct with default and given values.
	authPlugin = AuthPlugin{
		logLevel: log.InfoLevel,
		ctx:      context.Background(),
	}

	shutdown, err := telemetry.Init(authPlugin.ctx)
	authPlugin.telemetryShutdown = shutdown
	if err != nil {
		log.Warnf("telemetry init failed, continuing without: %s", err)
	} else if telemetry.Active() {
		log.Info("telemetry enabled (OTLP)")
	}

	authOpts = make(map[string]string)
	for i := 0; i < authOptsNum; i++ {
		authOpts[C.GoString(keys[i])] = C.GoString(values[i])
	}

	if retryCount, ok := authOpts["retry_count"]; ok {
		retry, err := strconv.Atoi(retryCount)
		if err == nil {
			authPlugin.retryCount = retry
		} else {
			log.Warningf("couldn't parse retryCount (err: %s), defaulting to 0", err)
		}
	}

	if useClientidAsUsername, ok := authOpts["use_clientid_as_username"]; ok && strings.ReplaceAll(useClientidAsUsername, " ", "") == "true" {
		log.Info("clientid will be used as username on checks")
		authPlugin.useClientidAsUsername = true
	} else {
		authPlugin.useClientidAsUsername = false
	}

	if allowEmptyCredentials, ok := authOpts["allow_empty_credentials"]; ok && strings.ReplaceAll(allowEmptyCredentials, " ", "") == "true" {
		log.Info("empty credentials will be allowed")
		authPlugin.allowEmptyCredentials = true
	} else {
		authPlugin.allowEmptyCredentials = false
	}

	//Check if log level is given. Set level if any valid option is given.
	if logLevel, ok := authOpts["log_level"]; ok {
		logLevel = strings.Replace(logLevel, " ", "", -1)
		switch logLevel {
		case "debug":
			authPlugin.logLevel = log.DebugLevel
		case "info":
			authPlugin.logLevel = log.InfoLevel
		case "warn":
			authPlugin.logLevel = log.WarnLevel
		case "error":
			authPlugin.logLevel = log.ErrorLevel
		case "fatal":
			authPlugin.logLevel = log.FatalLevel
		case "panic":
			authPlugin.logLevel = log.PanicLevel
		default:
			log.Info("log_level unkwown, using default info level")
		}
	}

	if logDest, ok := authOpts["log_dest"]; ok {
		switch logDest {
		case "stdout":
			log.SetOutput(os.Stdout)
		case "file":
			if logFile, ok := authOpts["log_file"]; ok {
				file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err == nil {
					log.SetOutput(file)
				} else {
					log.Errorf("failed to log to file, using default stderr: %s", err)
				}
			}
		default:
			log.Info("log_dest unknown, using default stderr")
		}
	}

	authPlugin.backends, err = bes.Initialize(authOpts, authPlugin.logLevel, C.GoString(version))
	if err != nil {
		log.Fatalf("error initializing backends: %s", err)
	}

	if cache, ok := authOpts["cache"]; ok && strings.Replace(cache, " ", "", -1) == "true" {
		log.Info("redisCache activated")
		authPlugin.useCache = true
	} else {
		log.Info("No cache set.")
		authPlugin.useCache = false
	}

	if authPlugin.useCache {
		setCache(authOpts)
	}
}

func setCache(authOpts map[string]string) {

	var aclCacheSeconds int64 = 30
	var authCacheSeconds int64 = 30
	var authJitterSeconds int64 = 0
	var aclJitterSeconds int64 = 0

	if authCacheSec, ok := authOpts["auth_cache_seconds"]; ok {
		authSec, err := strconv.ParseInt(authCacheSec, 10, 64)
		if err == nil {
			authCacheSeconds = authSec
		} else {
			log.Warningf("couldn't parse authCacheSeconds (err: %s), defaulting to %d", err, authCacheSeconds)
		}
	}

	if authJitterSec, ok := authOpts["auth_jitter_seconds"]; ok {
		authSec, err := strconv.ParseInt(authJitterSec, 10, 64)
		if err == nil {
			authJitterSeconds = authSec
		} else {
			log.Warningf("couldn't parse authJitterSeconds (err: %s), defaulting to %d", err, authJitterSeconds)
		}
	}

	if authJitterSeconds > authCacheSeconds {
		authJitterSeconds = authCacheSeconds
		log.Warningf("authJitterSeconds is larger than authCacheSeconds, defaulting to %d", authJitterSeconds)
	}

	if aclCacheSec, ok := authOpts["acl_cache_seconds"]; ok {
		aclSec, err := strconv.ParseInt(aclCacheSec, 10, 64)
		if err == nil {
			aclCacheSeconds = aclSec
		} else {
			log.Warningf("couldn't parse aclCacheSeconds (err: %s), defaulting to %d", err, aclCacheSeconds)
		}
	}

	if aclJitterSec, ok := authOpts["acl_jitter_seconds"]; ok {
		aclSec, err := strconv.ParseInt(aclJitterSec, 10, 64)
		if err == nil {
			aclJitterSeconds = aclSec
		} else {
			log.Warningf("couldn't parse aclJitterSeconds (err: %s), defaulting to %d", err, aclJitterSeconds)
		}
	}

	if aclJitterSeconds > aclCacheSeconds {
		aclJitterSeconds = aclCacheSeconds
		log.Warningf("aclJitterSeconds is larger than aclCacheSeconds, defaulting to %d", aclJitterSeconds)
	}

	reset := false
	if cacheReset, ok := authOpts["cache_reset"]; ok && cacheReset == "true" {
		reset = true
	}

	refreshExpiration := false
	if refresh, ok := authOpts["cache_refresh"]; ok && refresh == "true" {
		refreshExpiration = true
	}

	switch authOpts["cache_type"] {
	case "redis":
		host := "localhost"
		port := "6379"
		db := 3
		password := ""
		cluster := false

		if authOpts["cache_mode"] == "true" {
			cluster = true
		}

		if cachePassword, ok := authOpts["cache_password"]; ok {
			password = cachePassword
		}

		if cluster {

			addressesOpt := authOpts["redis_cluster_addresses"]
			if addressesOpt == "" {
				log.Errorln("cache Redis cluster addresses missing, defaulting to no cache.")
				authPlugin.useCache = false
				return
			}

			// Take the given addresses and trim spaces from them.
			addresses := strings.Split(addressesOpt, ",")
			for i := 0; i < len(addresses); i++ {
				addresses[i] = strings.TrimSpace(addresses[i])
			}

			authPlugin.cache = cache.NewRedisClusterStore(
				password,
				addresses,
				time.Duration(authCacheSeconds)*time.Second,
				time.Duration(aclCacheSeconds)*time.Second,
				time.Duration(authJitterSeconds)*time.Second,
				time.Duration(aclJitterSeconds)*time.Second,
				refreshExpiration,
			)

		} else {
			if cacheHost, ok := authOpts["cache_host"]; ok {
				host = cacheHost
			}

			if cachePort, ok := authOpts["cache_port"]; ok {
				port = cachePort
			}

			if cacheDB, ok := authOpts["cache_db"]; ok {
				parsedDB, err := strconv.ParseInt(cacheDB, 10, 32)
				if err == nil {
					db = int(parsedDB)
				} else {
					log.Warningf("couldn't parse cache db (err: %s), defaulting to %d", err, db)
				}
			}

			authPlugin.cache = cache.NewSingleRedisStore(
				host,
				port,
				password,
				db,
				time.Duration(authCacheSeconds)*time.Second,
				time.Duration(aclCacheSeconds)*time.Second,
				time.Duration(authJitterSeconds)*time.Second,
				time.Duration(aclJitterSeconds)*time.Second,
				refreshExpiration,
			)
		}

	default:
		authPlugin.cache = cache.NewGoStore(
			time.Duration(authCacheSeconds)*time.Second,
			time.Duration(aclCacheSeconds)*time.Second,
			time.Duration(authJitterSeconds)*time.Second,
			time.Duration(aclJitterSeconds)*time.Second,
			refreshExpiration,
		)
	}

	if !authPlugin.cache.Connect(authPlugin.ctx, reset) {
		authPlugin.cache = nil
		authPlugin.useCache = false
		log.Infoln("couldn't start cache, defaulting to no cache")
	}

}

//export AuthUnpwdCheck
func AuthUnpwdCheck(username, password, clientid *C.char) uint8 {
	var ok bool
	var err error

	for try := 0; try <= authPlugin.retryCount; try++ {
		ok, err = authUnpwdCheck(C.GoString(username), C.GoString(password), C.GoString(clientid))
		if err == nil {
			break
		}
	}

	if err != nil {
		log.Error(err)
		return AuthError
	}

	if ok {
		return AuthGranted
	}

	return AuthRejected
}

func authUnpwdCheck(username, password, clientid string) (authenticated bool, err error) {
	var cached bool
	var granted bool

	username = setUsername(username, clientid)

	ctx, span := telemetry.Tracer().Start(authPlugin.ctx, "auth.unpwd_check",
		trace.WithAttributes(
			attribute.String("auth.username", username),
			attribute.String("auth.client_id", clientid),
		),
	)
	start := time.Now()
	defer func() {
		result := authResult(authenticated, err)
		span.SetAttributes(attribute.String("auth.result", result))
		span.End()
		telemetry.AuthDuration.Record(ctx, time.Since(start).Seconds(),
			metric.WithAttributes(attribute.String("auth.result", result)),
		)
	}()

	// Enforce empty-password policy in Go: if password is empty and not allowed, reject.
	if (password == "" || username == "") && !authPlugin.allowEmptyCredentials {
		log.WithContext(ctx).Debugf("empty username or password not allowed")
		return false, fmt.Errorf("empty username or password not allowed")
	}

	if authPlugin.useCache {
		log.WithContext(ctx).Debugf("checking auth cache for %s", username)
		cached, granted = authPlugin.cache.CheckAuthRecord(ctx, username, password)
		if cached {
			log.WithContext(ctx).Debugf("found in cache: %s", username)
			span.AddEvent("cache.hit")
			telemetry.CacheHits.Add(ctx, 1, metric.WithAttributes(attribute.String("auth.kind", "unpwd")))
			return granted, nil
		}
		span.AddEvent("cache.miss")
		telemetry.CacheMisses.Add(ctx, 1, metric.WithAttributes(attribute.String("auth.kind", "unpwd")))
	}

	authenticated, err = authPlugin.backends.AuthUnpwdCheck(ctx, username, password, clientid)

	if authPlugin.useCache && err == nil {
		authGranted := "false"
		if authenticated {
			authGranted = "true"
		}
		log.WithContext(ctx).Debugf("setting auth cache for %s", username)
		if setAuthErr := authPlugin.cache.SetAuthRecord(ctx, username, password, authGranted); setAuthErr != nil {
			log.WithContext(ctx).Errorf("set auth cache: %s", setAuthErr)
			return false, setAuthErr
		}
	}
	return authenticated, err
}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic *C.char, acc C.int) uint8 {
	var ok bool
	var err error

	for try := 0; try <= authPlugin.retryCount; try++ {
		ok, err = authAclCheck(C.GoString(clientid), C.GoString(username), C.GoString(topic), int(acc))
		if err == nil {
			break
		}
	}

	if err != nil {
		log.Error(err)
		return AuthError
	}

	if ok {
		return AuthGranted
	}

	return AuthRejected
}

func authAclCheck(clientid, username, topic string, acc int) (aclCheck bool, err error) {
	var cached bool
	var granted bool

	username = setUsername(username, clientid)

	ctx, span := telemetry.Tracer().Start(authPlugin.ctx, "auth.acl_check",
		trace.WithAttributes(
			attribute.String("auth.username", username),
			attribute.String("auth.client_id", clientid),
			attribute.String("auth.topic", topic),
			attribute.Int("auth.access", acc),
		),
	)
	start := time.Now()
	defer func() {
		result := authResult(aclCheck, err)
		span.SetAttributes(attribute.String("auth.result", result))
		span.End()
		telemetry.ACLDuration.Record(ctx, time.Since(start).Seconds(),
			metric.WithAttributes(attribute.String("auth.result", result)),
		)
	}()

	if authPlugin.useCache {
		log.WithContext(ctx).Debugf("checking acl cache for %s", username)
		cached, granted = authPlugin.cache.CheckACLRecord(ctx, username, topic, clientid, acc)
		if cached {
			log.WithContext(ctx).Debugf("found in cache: %s", username)
			span.AddEvent("cache.hit")
			telemetry.CacheHits.Add(ctx, 1, metric.WithAttributes(attribute.String("auth.kind", "acl")))
			return granted, nil
		}
		span.AddEvent("cache.miss")
		telemetry.CacheMisses.Add(ctx, 1, metric.WithAttributes(attribute.String("auth.kind", "acl")))
	}

	aclCheck, err = authPlugin.backends.AuthAclCheck(ctx, clientid, username, topic, acc)

	if authPlugin.useCache && err == nil {
		authGranted := "false"
		if aclCheck {
			authGranted = "true"
		}
		log.WithContext(ctx).Debugf("setting acl cache (granted = %s) for %s", authGranted, username)
		if setACLErr := authPlugin.cache.SetACLRecord(ctx, username, topic, clientid, acc, authGranted); setACLErr != nil {
			log.WithContext(ctx).Errorf("set acl cache: %s", setACLErr)
			return false, setACLErr
		}
	}

	log.WithContext(ctx).Debugf("Acl is %t for user %s", aclCheck, username)
	return aclCheck, err
}

// authResult maps (ok, err) into a result label used on spans and metrics.
func authResult(ok bool, err error) string {
	if err != nil {
		return "error"
	}
	if ok {
		return "granted"
	}
	return "rejected"
}

//export AuthPskKeyGet
func AuthPskKeyGet() bool {
	return true
}

//export AuthPluginCleanup
func AuthPluginCleanup() {
	log.Info("Cleaning up plugin")
	//If cache is set, close cache connection.
	if authPlugin.cache != nil {
		authPlugin.cache.Close()
	}

	authPlugin.backends.Halt()

	if authPlugin.telemetryShutdown != nil {
		// Per-export is bounded by OTEL_EXPORTER_OTLP_TIMEOUT (default 10s),
		// so an unreachable collector won't hang shutdown indefinitely.
		if err := authPlugin.telemetryShutdown(context.Background()); err != nil {
			log.Warnf("telemetry shutdown: %s", err)
		}
	}
}

func setUsername(username, clientid string) string {
	if authPlugin.useClientidAsUsername {
		return clientid
	}

	return username
}

func main() {}
