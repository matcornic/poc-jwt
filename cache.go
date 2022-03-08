package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/gobwas/glob"

	"poc-jwt/cache"
)

const (
	cacheAccessKeyPrefix  = "auth:access"
	cacheRefreshKeyPrefix = "auth:refresh"
)

type AuthenticationDB struct {
	cache                  cache.TTLCache
	refreshTokenExpiration time.Duration
	accessTokenExpiration  time.Duration
}

func NewAuthenticationDB(ttlCache cache.TTLCache) *AuthenticationDB {
	return &AuthenticationDB{
		cache:                  ttlCache,
		refreshTokenExpiration: defaultRefreshTokenExpiration,
		accessTokenExpiration:  defaultAccessTokenExpiration,
	}
}

func NewAuthenticationDBWithExpiration(ttlCache cache.TTLCache, refreshTokenExpiration, accessTokenExpiration time.Duration) *AuthenticationDB {
	db := NewAuthenticationDB(ttlCache)
	db.refreshTokenExpiration = refreshTokenExpiration
	db.accessTokenExpiration = accessTokenExpiration
	return db
}

func (db *AuthenticationDB) IsAccessValid(username, uuid string) bool {
	val, err := db.cache.Get(db.accessKeyInCache(username, uuid))
	if err != nil {
		return false
	}
	valInt, ok := val.(int)
	return ok && valInt == 1
}

func (db *AuthenticationDB) IsRefreshValid(username, uuid string) bool {
	val, err := db.cache.Get(db.refreshKeyInCache(username, uuid))
	if err != nil {
		return false
	}
	valInt, ok := val.(int)
	return ok && valInt == 1
}

func (db *AuthenticationDB) DeleteAllUserTokens(username string) (int, error) {
	n1, err1 := db.cache.DelWithPattern(db.accessKeysOfUserPattern(username))
	n2, err2 := db.cache.DelWithPattern(db.refreshKeysOfUserPattern(username))
	if err1 != nil {
		return n1, err1
	}
	return n1 + n2, err2
}

func (db *AuthenticationDB) SaveRefreshToken(username string, td TokenDetail) error {
	now := time.Now()
	if td.Expires == 0 || td.UUID == "" {
		return fmt.Errorf("token detail requires non empty refresh expiration and uuid")
	}
	rt := time.Unix(td.Expires, 0)
	return db.cache.SetWithTTL(db.refreshKeyInCache(username, td.UUID), 1, rt.Sub(now))
}

func (db *AuthenticationDB) SaveAccessToken(username string, td TokenDetail) error {
	now := time.Now()
	if td.Expires == 0 || td.UUID == "" {
		return fmt.Errorf("token detail requires non empty access expiration and uuid")
	}
	rt := time.Unix(td.Expires, 0)
	return db.cache.SetWithTTL(db.accessKeyInCache(username, td.UUID), 1, rt.Sub(now))
}

func (db *AuthenticationDB) DeleteRefreshToken(username string, uuid string) (bool, error) {
	return db.cache.Del(db.refreshKeyInCache(username, uuid))
}

func (db *AuthenticationDB) DeleteAccessToken(username string, uuid string) (bool, error) {
	return db.cache.Del(db.accessKeyInCache(username, uuid))
}

func (db *AuthenticationDB) accessKeyInCache(username string, uuid string) string {
	return strings.Join([]string{cacheAccessKeyPrefix, username, uuid}, ":")
}

func (db *AuthenticationDB) refreshKeyInCache(username string, uuid string) string {
	return strings.Join([]string{cacheRefreshKeyPrefix, username, uuid}, ":")
}

func (db *AuthenticationDB) accessKeysOfUserPattern(username string) glob.Glob {
	return glob.MustCompile(cacheAccessKeyPrefix + ":" + username + ":*")
}

func (db *AuthenticationDB) refreshKeysOfUserPattern(username string) glob.Glob {
	return glob.MustCompile(cacheRefreshKeyPrefix + ":" + username + ":*")
}
