package cache

import (
	"container/list"
	"time"
)

// ExpirableLRU cache. It is not safe for concurrent access.
type ExpirableLRU[K comparable, V any] struct {
	ttl   time.Duration
	ll    *list.List
	cache map[K]*list.Element
}

type expirableEntry[K comparable, V any] struct {
	key        K
	value      V
	lastAccess time.Time
}

// NewExpirableLRU creates a new Cache whose entries older than the provided TTL are removed
// only when the ExpireAll method is explicitly called.
func NewExpirableLRU[K comparable, V any](ttl time.Duration) *ExpirableLRU[K, V] {
	return &ExpirableLRU[K, V]{
		ttl:   ttl,
		ll:    list.New(),
		cache: map[K]*list.Element{},
	}
}

// Put a value into the cache.
func (c *ExpirableLRU[K, V]) Put(key K, value V) {
	timeNow := time.Now()
	if ee, ok := c.cache[key]; ok {
		c.ll.MoveToFront(ee)
		entry := ee.Value.(*expirableEntry[K, V])
		entry.value = value
		entry.lastAccess = timeNow
		return
	}
	ele := c.ll.PushFront(&expirableEntry[K, V]{key: key, value: value, lastAccess: timeNow})
	c.cache[key] = ele
}

// Get looks up a key's value from the cache.
func (c *ExpirableLRU[K, V]) Get(key K) (value V, ok bool) {
	if ele, hit := c.cache[key]; hit {
		c.ll.MoveToFront(ele)
		ele.Value.(*expirableEntry[K, V]).lastAccess = time.Now()
		return ele.Value.(*expirableEntry[K, V]).value, true
	}
	return
}

// Remove the provided key from the cache.
func (c *ExpirableLRU[K, V]) Remove(key K) {
	if ele, hit := c.cache[key]; hit {
		c.removeElement(ele)
	}
}

func (c *ExpirableLRU[K, V]) removeElement(e *list.Element) {
	c.ll.Remove(e)
	kv := e.Value.(*expirableEntry[K, V])
	delete(c.cache, kv.key)
}

// ExpireAll removes all the entries that are older than the cache TTL
func (c *ExpirableLRU[K, V]) ExpireAll() {
	now := time.Now()
	for older := c.ll.Back(); c.expired(older, now); older = c.ll.Back() {
		c.removeElement(older)
	}
}

func (c *ExpirableLRU[K, V]) expired(elem *list.Element, now time.Time) bool {
	return elem != nil &&
		elem.Value.(*expirableEntry[K, V]).lastAccess.Add(c.ttl).Before(now)
}

// Len returns the number of elements in the cache.
func (c *ExpirableLRU[K, V]) Len() int {
	return c.ll.Len()
}
