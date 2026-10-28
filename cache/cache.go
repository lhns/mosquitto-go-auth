package cache

import (
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"math/rand"
	"strconv"
	"strings"
	"time"

	bes "github.com/iegomez/mosquitto-go-auth/backends"
	"github.com/jellydator/ttlcache/v3"
	goredis "github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

// redisCache stores necessary values for Redis cache
type redisStore struct {
	authExpiration    time.Duration
	aclExpiration     time.Duration
	authJitter        time.Duration
	aclJitter         time.Duration
	refreshExpiration bool
	client            bes.RedisClient
	keys              keyer
}

type goStore struct {
	authExpiration    time.Duration
	aclExpiration     time.Duration
	authJitter        time.Duration
	aclJitter         time.Duration
	refreshExpiration bool
	client            *ttlcache.Cache[string, bool]
	keys              keyer
}

const (
	defaultExpiration = 30
)

type Store interface {
	SetAuthRecord(ctx context.Context, username, password, granted string) error
	CheckAuthRecord(ctx context.Context, username, password string) (bool, bool)
	SetACLRecord(ctx context.Context, username, topic, clientid string, acc int, granted string) error
	CheckACLRecord(ctx context.Context, username, topic, clientid string, acc int) (bool, bool)
	Connect(ctx context.Context, reset bool) bool
	Close()
}

// NewGoStore initializes a cache using go-cache as the store.
func NewGoStore(authExpiration, aclExpiration, authJitter, aclJitter time.Duration, refreshExpiration bool) *goStore {
	// TODO: support hydrating the cache to retain previous values.

	localCache := ttlcache.New[string, bool](
		ttlcache.WithTTL[string, bool](time.Second * (defaultExpiration * 2)),
	)

	go localCache.Start()

	return &goStore{
		authExpiration:    authExpiration,
		aclExpiration:     aclExpiration,
		authJitter:        authJitter,
		aclJitter:         aclJitter,
		refreshExpiration: refreshExpiration,
		client:            localCache,
		keys:              newRandomKeyer(),
	}
}

// NewSingleRedisStore initializes a cache using a single Redis instance as the store.
func NewSingleRedisStore(host, port, password, keySecret string, db int, authExpiration, aclExpiration, authJitter, aclJitter time.Duration, refreshExpiration bool) *redisStore {
	addr := fmt.Sprintf("%s:%s", host, port)
	redisClient := goredis.NewClient(&goredis.Options{
		Addr:     addr,
		Password: password, // no password set
		DB:       db,       // use default db
	})
	//If cache is on, try to start redis.
	return &redisStore{
		authExpiration:    authExpiration,
		aclExpiration:     aclExpiration,
		authJitter:        authJitter,
		aclJitter:         aclJitter,
		refreshExpiration: refreshExpiration,
		client:            &bes.SingleRedisClient{Client: redisClient},
		keys:              keyerFromSecret(keySecret),
	}
}

// NewSingleRedisStore initializes a cache using a Redis Cluster as the store.
func NewRedisClusterStore(password, keySecret string, addresses []string, authExpiration, aclExpiration, authJitter, aclJitter time.Duration, refreshExpiration bool) *redisStore {
	clusterClient := goredis.NewClusterClient(
		&goredis.ClusterOptions{
			Addrs:    addresses,
			Password: password,
		})

	return &redisStore{
		authExpiration:    authExpiration,
		aclExpiration:     aclExpiration,
		authJitter:        authJitter,
		aclJitter:         aclJitter,
		refreshExpiration: refreshExpiration,
		client:            clusterClient,
		keys:              keyerFromSecret(keySecret),
	}
}

// Cache keys have the form "mga:v5:<domain>:<hex digest>", where domain is "auth" or "acl".
// The digest is HMAC-SHA-256 over the domain tag followed by every field as uvarint length + bytes,
// so field boundaries are unambiguous. The HMAC key is secret, so a reader of the key space
// (Redis KEYS, a backup) cannot test password guesses without it. The Go store uses a random key
// of each process. The Redis store uses cache_key_secret; when it is not set, the digest is a plain
// SHA-256 (keyer without a key). Keys are computed per call.
// The "v5" namespace is separate from keys written by earlier versions.
const keyPrefix = "mga:v5:"

// keyer builds cache keys. An empty key gives a plain SHA-256 digest.
type keyer struct {
	key []byte
}

// newRandomKeyer returns a keyer with a random 32-byte key.
func newRandomKeyer() keyer {
	k := make([]byte, sha256.Size)
	_, _ = crand.Read(k) // never fails: a failure of the system source ends the process
	return keyer{key: k}
}

// keyerFromSecret returns a keyer for cache_key_secret; an empty secret gives a plain SHA-256 digest.
func keyerFromSecret(secret string) keyer {
	return keyer{key: []byte(secret)}
}

func (kr keyer) cacheKey(domain string, fields ...string) string {
	var h hash.Hash
	if len(kr.key) == 0 {
		h = sha256.New()
	} else {
		h = hmac.New(sha256.New, kr.key)
	}
	for _, f := range append([]string{domain}, fields...) {
		h.Write(binary.AppendUvarint(nil, uint64(len(f))))
		h.Write([]byte(f))
	}

	return keyPrefix + domain + ":" + hex.EncodeToString(h.Sum(nil))
}

func (kr keyer) toAuthRecord(username, password string) string {
	return kr.cacheKey("auth", username, password)
}

func (kr keyer) toACLRecord(username, topic, clientid string, acc int) string {
	return kr.cacheKey("acl", username, topic, clientid, strconv.Itoa(acc))
}

// Checks if an error was caused by a moved record in a Redis Cluster.
func isMovedError(err error) bool {
	s := err.Error()
	if strings.HasPrefix(s, "MOVED ") || strings.HasPrefix(s, "ASK ") {
		return true
	}

	return false
}

// Return an expiration duration with a jitter added, i.e the actual expiration is in the range [expiration - jitter, expiration + jitter].
// If no expiration was set or jitter > expiration, then any negative value will yield 0 instead.
func expirationWithJitter(expiration, jitter time.Duration) time.Duration {
	if jitter == 0 {
		return expiration
	}

	result := expiration + time.Duration(rand.Int63n(int64(jitter)*2)-int64(jitter))
	if result < 0 {
		return 0
	}

	return result
}

// Connect flushes the cache if reset is set.
func (s *goStore) Connect(ctx context.Context, reset bool) bool {
	log.Infoln("started go-cache")
	if reset {
		s.client.DeleteAll()
		log.Infoln("flushed go-cache")
	}
	return true
}

// Connect pings Redis and flushes the cache if reset is set.
func (s *redisStore) Connect(ctx context.Context, reset bool) bool {
	_, err := s.client.Ping(ctx).Result()
	if err != nil {
		log.Errorf("couldn't start redis. error: %s", err)
		return false
	} else {
		log.Infoln("started redis cache")
		//Check if cache must be reset
		if reset {
			s.client.FlushDB(ctx)
			log.Infoln("flushed redis cache")
		}
	}
	return true
}

func (s *goStore) Close() {
	s.client.Stop()
}

func (s *redisStore) Close() {
	s.client.Close()
}

// CheckAuthRecord checks if the username/password pair is present in the cache. Return if it's present and, if so, if it was granted privileges
func (s *goStore) CheckAuthRecord(ctx context.Context, username, password string) (bool, bool) {
	record := s.keys.toAuthRecord(username, password)
	return s.checkRecord(ctx, record, expirationWithJitter(s.authExpiration, s.authJitter))
}

// CheckAclCache checks if the username/topic/clientid/acc mix is present in the cache. Return if it's present and, if so, if it was granted privileges.
func (s *goStore) CheckACLRecord(ctx context.Context, username, topic, clientid string, acc int) (bool, bool) {
	record := s.keys.toACLRecord(username, topic, clientid, acc)
	return s.checkRecord(ctx, record, expirationWithJitter(s.aclExpiration, s.aclJitter))
}

func (s *goStore) checkRecord(ctx context.Context, record string, expirationTime time.Duration) (bool, bool) {
	var item *ttlcache.Item[string, bool]

	if !s.refreshExpiration {
		item = s.client.Get(record, ttlcache.WithDisableTouchOnHit[string, bool]())
	} else {
		item = s.client.Get(record)
	}

	// Get returns nil when the key is absent or expired
	if item == nil {
		return false, false
	}

	return true, item.Value()
}

// CheckAuthRecord checks if the username/password pair is present in the cache. Return if it's present and, if so, if it was granted privileges
func (s *redisStore) CheckAuthRecord(ctx context.Context, username, password string) (bool, bool) {
	record := s.keys.toAuthRecord(username, password)
	return s.checkRecord(ctx, record, s.authExpiration)
}

// CheckAclCache checks if the username/topic/clientid/acc mix is present in the cache. Return if it's present and, if so, if it was granted privileges.
func (s *redisStore) CheckACLRecord(ctx context.Context, username, topic, clientid string, acc int) (bool, bool) {
	record := s.keys.toACLRecord(username, topic, clientid, acc)
	return s.checkRecord(ctx, record, s.aclExpiration)
}

func (s *redisStore) checkRecord(ctx context.Context, record string, expirationTime time.Duration) (bool, bool) {

	present, granted, err := s.getAndRefresh(ctx, record, expirationTime)
	if err == nil {
		return present, granted
	}

	if isMovedError(err) {
		s.client.ReloadState(ctx)

		//Retry once.
		present, granted, err = s.getAndRefresh(ctx, record, expirationTime)
	}

	if err != nil {
		log.Debugf("set cache error: %s", err)
	}

	return present, granted
}

func (s *redisStore) getAndRefresh(ctx context.Context, record string, expirationTime time.Duration) (bool, bool, error) {
	val, err := s.client.Get(ctx, record).Result()
	if err != nil {
		return false, false, err
	}

	if s.refreshExpiration {
		_, err = s.client.Expire(ctx, record, expirationTime).Result()
		if err != nil {
			return false, false, err
		}
	}

	if val == "true" {
		return true, true, nil
	}

	return true, false, nil
}

// SetAuthRecord sets a pair, granted option and expiration time.
func (s *goStore) SetAuthRecord(ctx context.Context, username, password string, granted string) error {
	record := s.keys.toAuthRecord(username, password)
	recordGranted := false

	if granted == "true" {
		recordGranted = true
	}

	s.client.Set(record, recordGranted, expirationWithJitter(s.authExpiration, s.authJitter))

	return nil
}

// SetAclCache sets a mix, granted option and expiration time.
func (s *goStore) SetACLRecord(ctx context.Context, username, topic, clientid string, acc int, granted string) error {
	record := s.keys.toACLRecord(username, topic, clientid, acc)
	recordGranted := false

	if granted == "true" {
		recordGranted = true
	}

	s.client.Set(record, recordGranted, expirationWithJitter(s.aclExpiration, s.aclJitter))

	return nil
}

// SetAuthRecord sets a pair, granted option and expiration time.
func (s *redisStore) SetAuthRecord(ctx context.Context, username, password string, granted string) error {
	record := s.keys.toAuthRecord(username, password)
	return s.setRecord(ctx, record, granted, expirationWithJitter(s.authExpiration, s.authJitter))
}

// SetAclCache sets a mix, granted option and expiration time.
func (s *redisStore) SetACLRecord(ctx context.Context, username, topic, clientid string, acc int, granted string) error {
	record := s.keys.toACLRecord(username, topic, clientid, acc)
	return s.setRecord(ctx, record, granted, expirationWithJitter(s.aclExpiration, s.aclJitter))
}

func (s *redisStore) setRecord(ctx context.Context, record, granted string, expirationTime time.Duration) error {
	err := s.set(ctx, record, granted, expirationTime)

	if err == nil {
		return nil
	}

	// If record was moved, reload and retry.
	if isMovedError(err) {
		s.client.ReloadState(ctx)

		//Retry once.
		err = s.set(ctx, record, granted, expirationTime)
	}

	return err
}

func (s *redisStore) set(ctx context.Context, record string, granted string, expirationTime time.Duration) error {
	return s.client.Set(ctx, record, granted, expirationTime).Err()
}
