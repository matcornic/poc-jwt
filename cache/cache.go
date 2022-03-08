package cache

import (
	"fmt"
	"time"

	"github.com/ReneKroon/ttlcache/v2"
	"github.com/gobwas/glob"
	"github.com/hashicorp/go-multierror"
)

type TTLCache interface {
	SetWithTTL(key string, value interface{}, ttl time.Duration) error
	Get(key string) (interface{}, error)
	Del(key string) (bool, error)
	DelWithPattern(pattern glob.Glob) (int, error)
	PrintAll()
}

type InMemTTLCache struct {
	cache *ttlcache.Cache
}

func NewInMemCache() TTLCache {
	return InMemTTLCache{
		cache: ttlcache.NewCache(),
	}
}

func (ttlCache InMemTTLCache) SetWithTTL(key string, value interface{}, ttl time.Duration) error {
	return ttlCache.cache.SetWithTTL(key, value, ttl)
}

func (ttlCache InMemTTLCache) Get(key string) (interface{}, error) {
	return ttlCache.cache.Get(key)
}

func (ttlCache InMemTTLCache) Del(key string) (bool, error) {
	err := ttlCache.cache.Remove(key)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (ttlCache InMemTTLCache) DelWithPattern(pattern glob.Glob) (int, error) {
	// /!\ Only for testing, we can authorize ourselves to list all items and search the ones with pattern
	// In real life Redis, we would use del command with glob pattern
	allItems := ttlCache.cache.GetItems()
	var (
		oks int
		err *multierror.Error
	)
	for k := range allItems {
		if pattern.Match(k) {
			ok, errr := ttlCache.Del(k)
			if errr != nil {
				err = multierror.Append(err, errr)
			}
			if ok {
				oks++
			}
		}
	}
	if errRes := err.ErrorOrNil(); errRes != nil {
		return oks, errRes
	}
	return oks, nil
}

func (ttlCache InMemTTLCache) PrintAll() {
	allItems := ttlCache.cache.GetItems()
	for k, v := range allItems {
		fmt.Printf("%v -> %v\n", k, v)
	}
}
